use std::{
    collections::HashMap,
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::AtomicBool,
};

use anyhow::Context;
use gix::{
    Object, ThreadSafeRepository,
    bstr::BStr,
    features::progress,
    objs::Kind,
    remote::{Direction, ref_map},
};
use hickory_client::proto::rr::{Name, RData, RecordType, rdata::TXT};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

pub(crate) struct Templates {
    repo: ThreadSafeRepository,
}

impl Templates {
    pub(crate) fn new(config: TemplateConfig) -> anyhow::Result<Self> {
        let repo = match gix::open(&config.cache) {
            Ok(repo) => {
                let name = BStr::new(config.remote.as_bytes());
                let master = BStr::new("refs/heads/master");
                let remote = repo
                    .find_fetch_remote(Some(name))?
                    .with_refspecs([master], Direction::Fetch)?;

                info!(cache = %config.cache.display(), remote = %config.remote, "updating templates from remote");
                let conn = remote.connect(Direction::Fetch)?;
                let fetch = conn.prepare_fetch(progress::Discard, ref_map::Options::default())?;
                let interrupt_fetch = AtomicBool::new(false);
                let outcome = fetch.receive(progress::Discard, &interrupt_fetch)?;
                debug!(?outcome, "fetch outcome");

                repo
            }
            Err(gix::open::Error::NotARepository {
                source: gix::discover::is_git::Error::Metadata { source, .. },
                ..
            }) if source.kind() == io::ErrorKind::NotFound => {
                info!(cache = %config.cache.display(), remote = %config.remote, "template cache not found, cloning from remote");
                let interrupt_fetch = AtomicBool::new(false);
                let mut fetch = gix::prepare_clone_bare(&*config.remote, &config.cache)?;
                info!(remote = config.remote, cache = %config.cache.display(), "updating templates");
                let (repo, outcome) = fetch.fetch_only(progress::Discard, &interrupt_fetch)?;
                debug!(?outcome, "fetch outcome");
                repo
            }
            Err(e) => return Err(e).context("failed to open template cache repository"),
        };

        Ok(Self {
            repo: repo.into_sync(),
        })
    }

    pub(crate) fn get(&self, provider: &str, service: &str) -> Result<Option<Template>, ()> {
        let local = self.repo.to_thread_local();
        let tree = match local.head_tree() {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "failed to get head tree");
                return Err(());
            }
        };

        let path = format!("{provider}.{service}.json");
        let Some(entry) = tree.find_entry(&*path) else {
            return Ok(None);
        };

        let object = match entry.object() {
            Ok(
                object @ Object {
                    kind: Kind::Blob, ..
                },
            ) => object,
            Ok(Object { kind, .. }) => {
                warn!(kind = ?kind, path = %path, "object is not a blob");
                return Err(());
            }
            Err(error) => {
                warn!(%error, path = %path, "failed to find object for path");
                return Err(());
            }
        };

        match serde_json::from_slice(&object.data) {
            Ok(template) => Ok(Some(template)),
            Err(error) => {
                warn!(%error, path = %path, "failed to deserialize template");
                Err(())
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Template {
    provider_id: String,
    provider_name: String,
    service_id: String,
    service_name: String,
    logo_url: Option<String>,
    pub(crate) version: Option<usize>,
    description: Option<String>,
    #[serde(default)]
    sync_block: bool,
    #[serde(default)]
    shared_provider_name: bool,
    sync_pub_key_domain: Option<String>,
    sync_redirect_domain: Option<String>,
    #[serde(default)]
    multi_instance: bool,
    #[serde(default)]
    warn_phishing: bool,
    #[serde(default)]
    host_required: bool,
    pub(crate) records: Vec<Record>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    r#type: DcRecordType,
    host: String,
    points_to: Option<String>,
    ttl: u32,
    data: Option<String>,
    #[serde(default)]
    txt_conflict_matching_mode: MatchingMode,
    txt_conflict_matching_prefix: Option<String>,
}

impl Record {
    pub(crate) fn update(
        &self,
        query: &HashMap<String, String>,
    ) -> Result<RecordUpdate, &'static str> {
        match self.r#type {
            DcRecordType::A => self.a(query),
            DcRecordType::Txt => self.txt(query),
            _ => Err("unsupported record type"),
        }
    }

    fn a(&self, query: &HashMap<String, String>) -> Result<RecordUpdate, &'static str> {
        let host_template = ValueTemplate::from_str(&self.host);
        let name = host_template.render(&query)?;
        let fqdn = Name::from_str(&name).map_err(|error| {
            warn!(%error, "failed to parse FQDN from host template");
            "invalid record host"
        })?;

        let Some(points_to) = self.points_to.as_deref() else {
            return Err("A record missing pointsTo field");
        };

        let value_template = ValueTemplate::from_str(&points_to);
        let points_to = value_template.render(&query)?;
        let addr = Ipv4Addr::from_str(&points_to).map_err(|error| {
            warn!(%error, "failed to parse A record address");
            "invalid A record address"
        })?;

        Ok(RecordUpdate {
            r#type: RecordType::A,
            fqdn,
            data: RData::A(addr.into()),
            display: format!("{addr}"),
            ttl: self.ttl,
        })
    }

    fn txt(&self, query: &HashMap<String, String>) -> Result<RecordUpdate, &'static str> {
        let host_template = ValueTemplate::from_str(&self.host);
        let name = host_template.render(query)?;
        let fqdn = Name::from_str(&name).map_err(|error| {
            warn!(%error, "failed to parse FQDN from host template");
            "invalid record host"
        })?;

        let Some(data) = self.data.as_deref() else {
            return Err("TXT record missing data field");
        };

        let value_template = ValueTemplate::from_str(data);
        let data = value_template.render(query)?;
        Ok(RecordUpdate {
            r#type: RecordType::TXT,
            fqdn,
            display: format!("{data:?}"),
            data: RData::TXT(TXT::new(vec![data])),
            ttl: self.ttl,
        })
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RecordUpdate {
    r#type: RecordType,
    fqdn: Name,
    data: RData,
    display: String,
    ttl: u32,
}

struct ValueTemplate<'a>(Vec<Node<'a>>);

impl<'a> ValueTemplate<'a> {
    fn from_str(s: &'a str) -> Self {
        use ParseState::*;
        let mut state = Literal { start: 0 };
        let mut nodes = Vec::new();
        for (i, c) in s.char_indices() {
            state = match (state, c) {
                (Literal { start }, '%') => {
                    if i > start {
                        nodes.push(Node::Literal(&s[start..i]));
                    }
                    Variable { start: i + 1 }
                }
                (Literal { .. }, '@') => {
                    nodes.push(Node::Variable("fqdn"));
                    Literal { start: i + 1 }
                }
                (Variable { start }, '%') => {
                    nodes.push(Node::Variable(&s[start..i]));
                    Literal { start: i + 1 }
                }
                (state, _) => state,
            };
        }

        Self(nodes)
    }

    fn render(&self, query: &HashMap<String, String>) -> Result<String, &'static str> {
        let mut result = String::new();
        for node in &self.0 {
            match node {
                Node::Literal(text) => result.push_str(text),
                Node::Variable(var) => match query.get(*var) {
                    Some(value) => result.push_str(value),
                    None => {
                        warn!(%var, "missing variable in query");
                        return Err("missing variable in query");
                    }
                },
            }
        }

        Ok(result)
    }
}

#[derive(Debug)]
enum Node<'a> {
    Literal(&'a str),
    Variable(&'a str),
}

#[derive(Debug)]
enum ParseState {
    Literal { start: usize },
    Variable { start: usize },
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DcRecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Srv,
    Spfm,
}

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "PascalCase")]
enum MatchingMode {
    #[default]
    None,
    All,
    Prefix,
}

#[derive(Debug, Deserialize)]
pub(crate) struct TemplateConfig {
    cache: PathBuf,
    remote: String,
}

impl TemplateConfig {
    pub(crate) fn update_paths(&mut self, base: &Path) {
        self.cache = base.join(&self.cache);
    }
}
