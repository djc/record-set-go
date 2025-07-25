use std::{fs, path::PathBuf};

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tracing::{debug, info};

use record_set_go::{App, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let options = Options::parse();
    debug!(?options, "parsed options");
    let config = fs::read_to_string(&options.config).context(format!(
        "failed to read config file {:?}",
        options.config.display()
    ))?;

    let mut config = toml::from_str::<Config>(&config).context("failed to parse config file")?;
    debug!(?config, "parsed config");
    if let Some(base) = options.config.parent() {
        config.update_paths(base);
    }

    let addr = config.http.listen;
    let app = App::new(config)
        .await
        .context("failed to create application")?;

    let listener = TcpListener::bind(addr)
        .await
        .context("failed to bind TCP listener")?;
    info!(%addr, "HTTP interface listening");
    Ok(axum::serve(listener, app.into_router()).await?)
}

#[derive(Debug, Parser)]
struct Options {
    #[clap(long)]
    config: PathBuf,
}
