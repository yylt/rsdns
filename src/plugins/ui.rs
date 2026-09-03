//! `ui` stage — built-in web UI + Prometheus `/metrics` HTTP endpoint.
//!
//! Not part of the query pipeline.  When a `ui:` section is configured,
//! `main` starts a small hyper HTTP/1.1 + HTTP/2 server exposing two paths:
//!
//! - `/` — mobile-friendly HTML dashboard (compiled into the binary via
//!   [`include_str!`]) that fetches `/metrics` and renders memory / cache /
//!   query metrics as colored rounded cards.
//! - `/metrics` — the shared [`MetricsRegistry`] in Prometheus text format
//!   (unchanged).
//!
//! Any other path returns 404.  Without the section, no listener is
//! started but counters still run.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use log::{info, warn};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

/// The dashboard HTML, embedded into the binary at compile time.
const UI_HTML: &str = include_str!("ui.html");

/// Path serving the Prometheus text exposition format.
const METRICS_PATH: &str = "/metrics";

#[derive(Debug, Clone, Deserialize, Default)]
pub struct UiConfig {
    /// Listen address, default `"127.0.0.1:8153"` (loopback only).
    #[serde(default = "default_ui_bind")]
    pub bind: String,
}

fn default_ui_bind() -> String {
    "127.0.0.1:8153".to_string()
}

/// Reads (and validates) the optional `ui:` section.
pub fn config(config: &Config) -> Option<UiConfig> {
    let raw = config.plugin_sections.get("ui")?;
    match serde_yaml::from_value(raw.clone()) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            warn!("invalid ui config, ui disabled: {}", e);
            None
        }
    }
}

/// Resolves the optional `ui:` section into a listener + config.
/// Returns `None` when the section is absent; an invalid `bind` is a
/// startup error (propagated via `?`).
pub async fn bind_listener(cfg: &UiConfig) -> std::io::Result<TcpListener> {
    let addr: SocketAddr = cfg
        .bind
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad bind: {}", e)))?;
    let listener = crate::common::bind::bind_tcp_listener(addr)?;
    info!("ui listening on http://{} (/, /metrics)", addr);
    Ok(listener)
}

/// Serves `/` (dashboard) and `/metrics` forever on an already-bound listener.
pub async fn serve_ui(listener: TcpListener, _cfg: UiConfig, registry: MetricsRegistry) -> std::io::Result<()> {
    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if let Err(e) = stream.set_nodelay(true) {
            warn!("ui accept from {} failed to set TCP_NODELAY: {}", peer_addr, e);
            continue;
        }
        let io = TokioIo::new(stream);
        let registry = registry.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let registry = registry.clone();
                async move { handle_ui(req, registry) }
            });
            // Auto builder sniffs the connection preface and serves both
            // HTTP/1.1 and HTTP/2 (like the DoH server).
            if let Err(err) = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                warn!("ui connection error: {:?}", err);
            }
        });
    }
}

fn handle_ui(req: Request<Incoming>, registry: MetricsRegistry) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match req.uri().path() {
        "/" => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(UI_HTML)))
            .unwrap()),
        METRICS_PATH => {
            let body = registry.encode_text();
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .unwrap()),
    }
}
