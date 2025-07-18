use std::{
    fs, io,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::Context;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use clap::Parser;
use gix::{
    Object, ThreadSafeRepository,
    bstr::BStr,
    features::progress,
    objs::Kind,
    remote::{Direction, ref_map},
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let options = Options::parse();
    debug!(?options, "parsed options");
    let config = fs::read_to_string(&options.config).context(format!(
        "failed to read config file {:?}",
        options.config.display()
    ))?;

    let config = toml::from_str::<Config>(&config).context("failed to parse config file")?;
    debug!(?config, "parsed config");

    let state = Arc::new(App {
        templates: Templates::new(config.templates).context("failed to initialize templates")?,
    });

    let app = Router::new()
        .route("/{service}", get(service))
        .with_state(state);

    let listener = TcpListener::bind(config.http.listen).await.unwrap();
    info!(addr = %config.http.listen, "HTTP interface listening");
    Ok(axum::serve(listener, app).await?)
}

async fn service(Path(service): Path<String>, State(app): State<Arc<App>>) -> (StatusCode, String) {
    debug!(service = %service, "received request for service");
    let Some(template) = app.templates.get(&service) else {
        return (
            StatusCode::NOT_FOUND,
            format!("no template found for {service:?}"),
        );
    };

    match serde_json::to_string_pretty(&template) {
        Ok(json) => (StatusCode::OK, json),
        Err(error) => {
            warn!(%error, %service, "failed to serialize template");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to serialize template: {error}"),
            )
        }
    }
}

struct App {
    templates: Templates,
}

struct Templates {
    repo: ThreadSafeRepository,
}

impl Templates {
    fn new(config: TemplateConfig) -> anyhow::Result<Self> {
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

    fn get(&self, path: &str) -> Option<Template> {
        let local = self.repo.to_thread_local();
        let tree = match local.head_tree() {
            Ok(tree) => tree,
            Err(error) => {
                warn!(%error, "failed to get head tree");
                return None;
            }
        };

        let entry = tree.find_entry(path)?;
        let object = match entry.object() {
            Ok(
                object @ Object {
                    kind: Kind::Blob, ..
                },
            ) => object,
            Ok(Object { kind, .. }) => {
                warn!(kind = ?kind, path = %path, "object is not a blob");
                return None;
            }
            Err(error) => {
                warn!(%error, path = %path, "failed to find object for path");
                return None;
            }
        };

        match serde_json::from_slice(&object.data) {
            Ok(template) => Some(template),
            Err(error) => {
                warn!(%error, path = %path, "failed to deserialize template");
                None
            }
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Template {
    provider_id: String,
    provider_name: String,
    service_id: String,
    service_name: String,
    version: usize,
    sync_pub_key_domain: String,
    description: String,
    variable_description: String,
    host_required: bool,
    records: Vec<Record>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    r#type: String,
    host: String,
    points_to: String,
    ttl: u32,
}

#[derive(Debug, Parser)]
struct Options {
    #[clap(long)]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Config {
    http: HttpConfig,
    templates: TemplateConfig,
}

#[derive(Debug, Deserialize)]
struct TemplateConfig {
    cache: PathBuf,
    remote: String,
}

#[derive(Debug, Deserialize)]
struct HttpConfig {
    listen: SocketAddr,
}
