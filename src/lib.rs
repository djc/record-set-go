use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::{self, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::Context;
use axum::{
    Router,
    extract::{Json, Path, Query, RawQuery, State},
    http::{StatusCode, Uri},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use hickory_client::{
    client::{Client, ClientHandle},
    proto::{
        dnssec::{rdata::tsig::TsigAlgorithm, tsig::TSigner},
        op::{MessageSigner, ResponseCode},
        rr::{DNSClass, Name, RData, Record, RecordSet, RecordType},
        runtime::TokioRuntimeProvider,
        tcp::TcpClientStream,
    },
};
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;
use tracing::{debug, warn};

mod templates;
use templates::{RecordUpdate, Template, TemplateConfig, Templates};

async fn preview(
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

    let mut update = Update::default();
    update.records.reserve(template.records.len());
    for record in &template.records {
        match record.update(&query) {
            Ok(record) => update.records.push(record),
            Err(error) => {
                return ApiResponse::BadRequest(ApiError {
                    message: error.to_owned(),
                });
            }
        }
    }

    let mut client = match app.dns.connect().await {
        Ok(client) => client,
        Err(error) => {
            warn!(%error, "failed to connect to DNS server");
            return ApiResponse::Internal;
        }
    };

    let (current, records) = (&mut update.current, &update.records);
    for update in records {
        let ty = update.r#type;
        let mut message = match client.query(update.name.clone(), DNSClass::IN, ty).await {
            Ok(message) => message,
            Err(error) => {
                warn!(%error, "failed to query DNS for current records");
                return ApiResponse::Internal;
            }
        };

        for answer in message.take_answers() {
            if answer.record_type() != ty || answer.name() != &update.name {
                continue;
            }

            current
                .entry((update.name.clone(), ty))
                .or_default()
                .push(answer);
        }
    }

    let preview = Preview {
        properties: &properties,
        template: &template,
        records: &update.records,
        update: &update,
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

async fn apply(State(app): State<Arc<App>>, Json(update): Json<Update>) -> ApiResponse<()> {
    let mut new = HashMap::<(Name, RecordType), Vec<(RData, u32)>>::default();
    for update in update.records {
        new.entry((update.name, update.r#type))
            .or_default()
            .push((update.data, update.ttl));
    }

    let mut client = match app.dns.connect().await {
        Ok(client) => client,
        Err(error) => {
            warn!(%error, "failed to connect to DNS server");
            return ApiResponse::Internal;
        }
    };

    for ((name, ty), records) in new {
        let mut set = RecordSet::new(name.clone(), ty, 0);
        for (data, ttl) in records {
            set.add_rdata(data);
            set.set_ttl(ttl);
        }

        match client.append(set, name.clone(), false).await {
            Ok(response) if response.response_code() == ResponseCode::NoError => {
                debug!(?response, %name, %ty, "appended records")
            }
            Ok(response) => {
                warn!(?response, %name, %ty, "failed to append record");
                return ApiResponse::Internal;
            }
            Err(error) => {
                warn!(%error, %name, %ty, "failed to append record");
                return ApiResponse::Internal;
            }
        }
    }

    ApiResponse::Json(())
}

#[derive(Serialize)]
struct Preview<'a> {
    properties: &'a Properties,
    template: &'a Template,
    update: &'a Update,
    records: &'a [RecordUpdate],
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Update {
    current: HashMap<(Name, RecordType), Vec<Record>>,
    records: Vec<RecordUpdate>,
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

            match path.extension().and_then(|ext| ext.to_str()) {
                Some("html") | Some("j2") => {}
                _ => continue,
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
                get(preview),
            )
            .route("/apply", post(apply))
            .with_state(Arc::new(self))
    }
}

struct DnsServer {
    addr: SocketAddr,
    signer: Arc<dyn MessageSigner>,
}

impl DnsServer {
    async fn new(config: DnsConfig) -> anyhow::Result<Self> {
        let key = fs::read(&config.key_file).context(format!(
            "failed to read TSIG key file {}",
            config.key_file.display()
        ))?;

        let signer = TSigner::new(
            key,
            TsigAlgorithm::HmacSha256,
            Name::from_str(&config.key_name).context("failed to parse TSIG key name")?,
            300,
        )
        .context("failed to create TSIG signer")?;

        Ok(Self {
            addr: lookup_host((config.server.as_str(), 53))
                .await
                .context("failed to resolve DNS server address")?
                .next()
                .ok_or(anyhow::Error::msg(format!(
                    "no address found for DNS server {:?}",
                    &config.server
                )))?,
            signer: Arc::new(signer),
        })
    }

    pub async fn connect(&self) -> anyhow::Result<Client> {
        let (stream, sender) =
            TcpClientStream::new(self.addr, None, None, TokioRuntimeProvider::new());
        let client = Client::new(stream, sender, Some(self.signer.clone()));
        let (client, bg) = client
            .await
            .context("failed to establish DNS client connection")?;
        tokio::spawn(bg);
        Ok(client)
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TemplateVersion {
    version: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub http: HttpConfig,
    templates: TemplateConfig,
    dns: DnsConfig,
    provider: ProviderConfig,
}

impl Config {
    pub fn update_paths(&mut self, base: &path::Path) {
        self.http.update_paths(base);
        self.dns.update_paths(base);
        self.templates.update_paths(base);
    }
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    pub listen: SocketAddr,
    html: PathBuf,
}

impl HttpConfig {
    fn update_paths(&mut self, base: &path::Path) {
        self.html = base.join(&self.html);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct DnsConfig {
    server: String,
    key_name: String,
    key_file: PathBuf,
}

impl DnsConfig {
    fn update_paths(&mut self, base: &path::Path) {
        self.key_file = base.join(&self.key_file);
    }
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
