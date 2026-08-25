//! `metrics` stage — Prometheus `/metrics` HTTP endpoint.
//!
//! Not part of the query pipeline.  When a `metrics:` section is configured,
//! `main` starts a small hyper HTTP/1 server exposing the shared
//! [`MetricsRegistry`] text format.  Without the section, no listener is
//! started but counters still run.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use log::{info, warn};
use serde::Deserialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::config::Config;
use crate::metrics::MetricsRegistry;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MetricsConfig {
    /// Listen address, e.g. `"0.0.0.0:9153"`.
    #[serde(default = "default_metrics_bind")]
    pub bind: String,
    /// Metrics path, default `/metrics`.
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_bind() -> String {
    "0.0.0.0:9153".to_string()
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

/// Reads (and validates) the optional `metrics:` section.
pub fn config(config: &Config) -> Option<MetricsConfig> {
    let raw = config.plugin_sections.get("metrics")?;
    match serde_yaml::from_value(raw.clone()) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            warn!("invalid metrics config, metrics disabled: {}", e);
            None
        }
    }
}

/// Resolves the optional `metrics:` section into a listener + config.
/// Returns `None` when the section is absent; an invalid `bind` is a
/// startup error (propagated via `?`).
pub async fn bind_listener(cfg: &MetricsConfig) -> std::io::Result<TcpListener> {
    let addr: SocketAddr = cfg
        .bind
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("bad bind: {}", e)))?;
    let listener = crate::common::bind::bind_tcp_listener(addr)?;
    info!("metrics listening on http://{}", addr);
    Ok(listener)
}

/// Serves `/metrics` forever on an already-bound listener.
pub async fn serve_metrics(
    listener: TcpListener,
    cfg: MetricsConfig,
    registry: MetricsRegistry,
) -> std::io::Result<()> {
    let path = cfg.path.clone();

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        if let Err(e) = stream.set_nodelay(true) {
            warn!("metrics accept from {} failed to set TCP_NODELAY: {}", peer_addr, e);
            continue;
        }
        let io = hyper_util::rt::TokioIo::new(stream);
        let registry = registry.clone();
        let path = path.clone();
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let registry = registry.clone();
                let path = path.clone();
                async move { handle_metrics(req, registry, &path) }
            });
            if let Err(err) = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(io, service)
                .await
            {
                warn!("metrics connection error: {:?}", err);
            }
        });
    }
}

fn handle_metrics(
    req: Request<Incoming>,
    registry: MetricsRegistry,
    path: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path() != path {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("not found\n")))
            .unwrap());
    }
    let body = registry.encode_text();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}
