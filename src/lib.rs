use std::{
    collections::HashMap,
    fs, io,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::Context;
use axum::{
    Router,
    extract::{Json, Path, Query, RawQuery, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse},
    routing::get,
};
use gix::{
    Object, ThreadSafeRepository,
    bstr::BStr,
    features::progress,
    objs::Kind,
    remote::{Direction, ref_map},
};
use hickory_client::{
    client::{Client, ClientHandle},
    proto::{
        rr::{DNSClass, Name, RData, RecordType, rdata::TXT},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
    },
};
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;
use tracing::{debug, info, warn};

async fn apply(
    Path(service): Path<ServiceKey>,
    RawQuery(query): RawQuery,
    State(app): State<Arc<App>>,
) -> ApiResponse<Template> {
    debug!(provider = %service.provider, service = %service.service, "received request to apply template");
    let template = match app.templates.get(&service.provider, &service.service) {
        Ok(Some(template)) => template,
        Ok(None) => {
            warn!(provider = %service.provider, service = %service.service, "template not found");
            return ApiResponse::NotFound;
        }
        Err(()) => {
            warn!(provider = %service.provider, service = %service.service, "failed to retrieve template");
            return ApiResponse::Internal;
        }
    };

    let Some(query_str) = query else {
        warn!("missing query parameters");
        return ApiResponse::BadRequest(ApiError {
            message: "missing query parameters".to_owned(),
        });
    };

    // This should never fail, but we handle it gracefully just in case
    let Ok(uri) = Uri::from_str(&format!("/?{query_str}")) else {
        warn!("failed to parse URI from query");
        return ApiResponse::BadRequest(ApiError {
            message: "failed to parse URI from query".to_owned(),
        });
    };

    let Ok(Query(mut query)) = Query::<HashMap<String, String>>::try_from_uri(&uri) else {
        warn!("failed to parse query parameters");
        return ApiResponse::BadRequest(ApiError {
            message: "failed to parse query parameters".to_owned(),
        });
    };

    let properties = match Properties::from_query(&mut query) {
        Ok(props) => props,
        Err(error) => {
            warn!(%error, "failed to parse properties from query");
            return ApiResponse::BadRequest(ApiError {
                message: error.to_owned(),
            });
        }
    };

    let fqdn = match &properties.host {
        Some(host) => format!("{host}.{}", properties.domain),
        None => properties.domain.clone(),
    };

    query.insert("fqdn".to_owned(), fqdn);
    query.insert("domain".to_owned(), properties.domain.clone());
    if let Some(host) = &properties.host {
        query.insert("host".to_owned(), host.clone());
    }

    let mut records = Vec::with_capacity(template.records.len());
    for record in &template.records {
        let result = match record.r#type {
            DcRecordType::A => RecordPreview::a(&record, &query),
            DcRecordType::Txt => RecordPreview::txt(&record, &query),
            _ => continue,
        };

        match result {
            Ok(record) => records.push(record),
            Err(error) => {
                return ApiResponse::BadRequest(ApiError {
                    message: error.to_owned(),
                });
            }
        }
    }

    let preview = Preview {
        properties: &properties,
        template: &template,
        records: &records,
    };

    let html = match app.html.get_template("apply.html") {
        Ok(html) => html,
        Err(error) => {
            warn!(%error, "failed to get HTML template");
            return ApiResponse::Internal;
        }
    };

    match html.render(&preview) {
        Ok(rendered) => ApiResponse::Html(rendered),
        Err(error) => {
            warn!(%error, "failed to render HTML template");
            ApiResponse::Internal
        }
    }
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

#[derive(Serialize)]
struct Preview<'a> {
    properties: &'a Properties,
    template: &'a Template,
    records: &'a [RecordPreview],
}

#[derive(Debug, Serialize)]
struct RecordPreview {
    r#type: RecordType,
    fqdn: Name,
    data: RData,
    display: String,
    ttl: u32,
}

impl RecordPreview {
    fn a(input: &Record, query: &HashMap<String, String>) -> Result<Self, &'static str> {
        let host_template = ValueTemplate::from_str(&input.host);
        let name = host_template.render(&query)?;
        let fqdn = Name::from_str(&name).map_err(|error| {
            warn!(%error, "failed to parse FQDN from host template");
            "invalid record host"
        })?;

        let Some(points_to) = input.points_to.as_deref() else {
            return Err("A record missing pointsTo field");
        };

        let value_template = ValueTemplate::from_str(&points_to);
        let points_to = value_template.render(&query)?;
        let addr = Ipv4Addr::from_str(&points_to).map_err(|error| {
            warn!(%error, "failed to parse A record address");
            "invalid A record address"
        })?;

        Ok(Self {
            r#type: RecordType::A,
            fqdn,
            data: RData::A(addr.into()),
            display: format!("{addr}"),
            ttl: input.ttl,
        })
    }

    fn txt(input: &Record, query: &HashMap<String, String>) -> Result<Self, &'static str> {
        let host_template = ValueTemplate::from_str(&input.host);
        let name = host_template.render(query)?;
        let fqdn = Name::from_str(&name).map_err(|error| {
            warn!(%error, "failed to parse FQDN from host template");
            "invalid record host"
        })?;

        let Some(data) = input.data.as_deref() else {
            return Err("TXT record missing data field");
        };

        let value_template = ValueTemplate::from_str(data);
        let data = value_template.render(query)?;
        Ok(Self {
            r#type: RecordType::TXT,
            fqdn,
            display: format!("{data:?}"),
            data: RData::TXT(TXT::new(vec![data])),
            ttl: input.ttl,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Properties {
    domain: String,
    host: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    provider_name: Option<String>,
    service_name: Option<String>,
    group_id: Option<String>,
    // Signature and key
    sig: Option<(String, String)>,
}

impl Properties {
    fn from_query(query: &mut HashMap<String, String>) -> Result<Self, &'static str> {
        Ok(Self {
            domain: query.remove("domain").ok_or("missing domain field")?,
            host: query.remove("host"),
            redirect_uri: query.remove("redirect_uri"),
            state: query.remove("state"),
            provider_name: query.remove("providerName"),
            service_name: query.remove("serviceName"),
            group_id: query.remove("groupId"),
            sig: match (query.remove("sig"), query.remove("key")) {
                (Some(sig), Some(key)) => Some((sig, key)),
                (Some(_), None) => return Err("missing key for provided sig"),
                (None, Some(_)) => return Err("missing sig for provided key"),
                (None, None) => None,
            },
        })
    }
}

async fn supported(
    Path(service): Path<ServiceKey>,
    State(app): State<Arc<App>>,
) -> ApiResponse<TemplateVersion> {
    debug!(provider = %service.provider, service = %service.service, "received request for service");
    match app.templates.get(&service.provider, &service.service) {
        Ok(Some(template)) => ApiResponse::Json(TemplateVersion {
            version: template.version,
        }),
        Ok(None) => ApiResponse::NotFound,
        Err(()) => ApiResponse::Internal,
    }
}

#[derive(Debug, Deserialize)]
struct ServiceKey {
    provider: String,
    service: String,
}

async fn settings(
    Path(domain): Path<String>,
    State(app): State<Arc<App>>,
) -> ApiResponse<Settings> {
    debug!(%domain, "received request for settings");
    let name = match Name::from_str(&domain) {
        Ok(name) => name,
        Err(error) => {
            warn!(%error, "failed to parse domain name");
            return ApiResponse::BadRequest(ApiError {
                message: format!("invalid domain name: {error}"),
            });
        }
    };

    let mut client = match app.dns.connect().await {
        Ok(client) => client,
        Err(error) => {
            warn!(%error, "failed to connect to DNS server");
            return ApiResponse::Internal;
        }
    };

    let message = match client.query(name, DNSClass::IN, RecordType::SOA).await {
        Ok(message) => message,
        Err(error) => {
            warn!(%domain, ?error, "failed to query DNS for domain settings");
            return ApiResponse::Internal;
        }
    };

    if message.answers().is_empty() {
        warn!(%domain, "no NS records found for domain");
        return ApiResponse::NotFound;
    }

    ApiResponse::Json(Settings {
        provider_id: app.provider.id.clone(),
        provider_name: app.provider.name.clone(),
        provider_display_name: Some(app.provider.display_name.clone()),
        url_sync_ux: app.provider.sync_url.clone(),
        url_api: app.provider.api_url.clone(),
    })
}

pub struct App {
    provider: ProviderConfig,
    dns: DnsServer,
    html: minijinja::Environment<'static>,
    templates: Templates,
}

impl App {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let mut html = minijinja::Environment::new();
        let files =
            fs::read_dir(&config.http.html).context("failed to read HTML templates directory")?;

        for file in files {
            let file = file.context("failed to read HTML template directory entry")?;
            let path = file.path();
            if !path.is_file() {
                continue;
            }

            let contents = fs::read_to_string(&path).context(format!(
                "failed to read HTML template file {}",
                path.display()
            ))?;

            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };

            html.add_template_owned(name.to_owned(), contents)
                .context(format!("failed to register HTML template {name}"))?;
        }

        Ok(Self {
            provider: config.provider,
            dns: DnsServer::new(config.dns)
                .await
                .context("failed to create DNS server")?,
            html,
            templates: Templates::new(config.templates)
                .context("failed to initialize templates")?,
        })
    }

    pub fn into_router(self) -> Router {
        Router::new()
            .route("/v2/{domain}/settings", get(settings))
            .route(
                "/v2/domainTemplates/providers/{provider}/services/{service}",
                get(supported),
            )
            .route(
                "/v2/domainTemplates/providers/{provider}/services/{service}/apply",
                get(apply),
            )
            .with_state(Arc::new(self))
    }
}

struct DnsServer {
    addr: SocketAddr,
}

impl DnsServer {
    async fn new(config: DnsConfig) -> anyhow::Result<Self> {
        Ok(Self {
            addr: lookup_host((config.server.as_str(), 53))
                .await
                .context("failed to resolve DNS server address")?
                .next()
                .ok_or(anyhow::Error::msg(format!(
                    "no address found for DNS server {:?}",
                    &config.server
                )))?,
        })
    }

    pub async fn connect(&self) -> anyhow::Result<Client> {
        let (stream, sender) =
            TcpClientStream::new(self.addr, None, None, TokioRuntimeProvider::new());
        let client = Client::new(stream, sender, None);
        let (client, bg) = client
            .await
            .context("failed to establish DNS client connection")?;
        tokio::spawn(bg);
        Ok(client)
    }
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

    fn get(&self, provider: &str, service: &str) -> Result<Option<Template>, ()> {
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    provider_id: String,
    provider_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_display_name: Option<String>,
    #[serde(rename = "urlSyncUX")]
    url_sync_ux: String,
    #[serde(rename = "urlAPI")]
    url_api: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Template {
    provider_id: String,
    provider_name: String,
    service_id: String,
    service_name: String,
    logo_url: Option<String>,
    version: Option<usize>,
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
    records: Vec<Record>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateVersion {
    version: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    r#type: DcRecordType,
    host: String,
    points_to: Option<String>,
    ttl: u32,
    data: Option<String>,
    #[serde(default)]
    txt_conflict_matching_mode: MatchingMode,
    txt_conflict_matching_prefix: Option<String>,
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
pub struct Config {
    pub http: HttpConfig,
    templates: TemplateConfig,
    dns: DnsConfig,
    provider: ProviderConfig,
}

#[derive(Debug, Deserialize)]
struct TemplateConfig {
    cache: PathBuf,
    remote: String,
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub listen: SocketAddr,
    html: PathBuf,
}

#[derive(Debug, Deserialize)]
struct DnsConfig {
    server: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ProviderConfig {
    id: String,
    name: String,
    display_name: String,
    sync_url: String,
    api_url: String,
}

#[derive(Debug, Serialize)]
enum ApiResponse<T> {
    Html(String),
    Json(T),
    BadRequest(ApiError),
    Internal,
    NotFound,
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Html(html) => (StatusCode::OK, Html(html)).into_response(),
            Self::Json(data) => (StatusCode::OK, Json(data)).into_response(),
            Self::BadRequest(error) => (StatusCode::BAD_REQUEST, Json(error)).into_response(),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ApiError {
                    message: "request processing failed".to_owned(),
                }),
            )
                .into_response(),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                Json(ApiError {
                    message: "resource not found".to_owned(),
                }),
            )
                .into_response(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApiError {
    message: String,
}
