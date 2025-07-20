use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, atomic::AtomicBool},
};

use anyhow::Context;
use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
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
        rr::Name,
        rr::{DNSClass, RecordType},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
    },
};
use hickory_resolver::{Resolver, name_server::TokioConnectionProvider};
use serde::{Deserialize, Serialize};
use tokio::{net::lookup_host, sync::Mutex};
use tracing::{debug, info, warn};

async fn supported(
    Path(supported): Path<Supported>,
    State(app): State<Arc<App>>,
) -> ApiResponse<TemplateVersion> {
    debug!(provider = %supported.provider, service = %supported.service, "received request for service");
    match app.templates.get(&supported.provider, &supported.service) {
        Ok(Some(template)) => ApiResponse::Ok(TemplateVersion {
            version: template.version,
        }),
        Ok(None) => ApiResponse::NotFound,
        Err(()) => ApiResponse::Internal,
    }
}

#[derive(Debug, Deserialize)]
struct Supported {
    provider: String,
    service: String,
}

async fn settings(
    Path(domain): Path<String>,
    State(app): State<Arc<App>>,
) -> ApiResponse<Settings> {
    let name = match Name::from_str(&domain) {
        Ok(name) => name,
        Err(error) => {
            warn!(%error, "failed to parse domain name");
            return ApiResponse::BadRequest(ApiError {
                message: format!("invalid domain name: {error}"),
            });
        }
    };

    let result = app
        .client
        .lock()
        .await
        .query(name, DNSClass::IN, RecordType::NS)
        .await;

    ApiResponse::Ok(Settings {
        provider_id: app.provider.id.clone(),
        provider_name: app.provider.name.clone(),
        provider_display_name: Some(app.provider.display_name.clone()),
        url_sync_ux: app.provider.sync_url.clone(),
        url_api: app.provider.api_url.clone(),
    })
}

pub struct App {
    provider: ProviderConfig,
    client: Mutex<Client>,
    resolver: Resolver<TokioConnectionProvider>,
    templates: Templates,
}

impl App {
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let addr = lookup_host((config.dns.server.as_str(), 53))
            .await
            .context("failed to resolve DNS server address")?
            .next()
            .ok_or(anyhow::Error::msg(format!(
                "no address found for DNS server {:?}",
                &config.dns.server
            )))?;
        let (stream, sender) = TcpClientStream::new(addr, None, None, TokioRuntimeProvider::new());
        let client = Client::new(stream, sender, None);
        let (client, bg) = client
            .await
            .context("failed to establish DNS client connection")?;
        tokio::spawn(bg);

        Ok(Self {
            provider: config.provider,
            client: Mutex::new(client),
            resolver: Resolver::<TokioConnectionProvider>::builder(
                TokioConnectionProvider::default(),
            )?
            .build(),
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
            .with_state(Arc::new(self))
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
    version: usize,
    sync_pub_key_domain: Option<String>,
    description: String,
    variable_description: String,
    host_required: Option<bool>,
    records: Vec<Record>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateVersion {
    version: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    r#type: String,
    host: String,
    points_to: String,
    ttl: u32,
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
    Ok(T),
    BadRequest(ApiError),
    Internal,
    NotFound,
}

impl<T: Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Ok(data) => (StatusCode::OK, Json(data)).into_response(),
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
