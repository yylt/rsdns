mod common;
mod config;
#[cfg(feature = "jemalloc")]
mod jemalloc_conf;
mod metrics;
mod notify;
mod plugins;
mod query;
mod server;
mod upstream;

use clap::Parser;
use log::{error, warn};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::common::rslog;
use crate::common::tls::server_config;

use config::Config;
use server::{DnsServer, Pipeline};

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser, Debug)]
#[command(
    name = "rsdns",
    version = concat!(
        env!("XRAY_RS_VERSION"),
        "\ncommit: ",
        env!("XRAY_RS_GIT_COMMIT"),
        "\nbranch: ",
        env!("XRAY_RS_GIT_BRANCH"),
        "\nrustc: ",
        env!("XRAY_RS_RUSTC_VERSION"),
        "\ntarget: ",
        env!("XRAY_RS_BUILD_TARGET"),
        "\nprofile: ",
        env!("XRAY_RS_BUILD_PROFILE"),
        "\nbuilt: ",
        env!("XRAY_RS_BUILD_TIME"),
    ),
    about,
    long_about = None
)]
struct Args {
    #[arg(short = 'c', long = "config", default_value = "rsdns.yaml")]
    config: PathBuf,
    /// Number of tokio worker threads (multi-thread runtime only;
    /// default = available parallelism).
    #[arg(short = 't', long = "threads")]
    threads: Option<usize>,
    /// Tokio runtime thread model: `multi` (default) or `single`.
    #[arg(long = "thread-model", default_value = "multi", value_parser = ["single", "multi"])]
    thread_model: String,
}

fn main() -> std::process::ExitCode {
    let args = Args::parse();
    let _guard = rslog::init(log::LevelFilter::Info);

    let config = match Config::from_file(&args.config.to_string_lossy()) {
        Ok(c) => c,
        Err(e) => {
            error!("failed to load config {}: {}", args.config.display(), e);
            return std::process::ExitCode::FAILURE;
        }
    };

    let rt = match build_runtime(&args) {
        Ok(rt) => rt,
        Err(e) => {
            error!("failed to build tokio runtime: {}", e);
            return std::process::ExitCode::FAILURE;
        }
    };

    match rt.block_on(run(config)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            error!("rsdns exited with error: {}", e);
            std::process::ExitCode::FAILURE
        }
    }
}

/// Builds the tokio runtime from the `--thread-model` / `--threads` options.
fn build_runtime(args: &Args) -> std::io::Result<tokio::runtime::Runtime> {
    match args.thread_model.as_str() {
        "single" => tokio::runtime::Builder::new_current_thread().enable_all().build(),
        _ => {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            if let Some(n) = args.threads {
                builder.worker_threads(n);
            }
            builder.enable_all().build()
        }
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 共享指标注册表。
    let metrics = metrics::MetricsRegistry::new();

    // 2. 初始化各管道阶段（固定顺序；groups 为前置阶段；upstreams 组装后
    //    注入 rules 阶段，供 forward/cname 直接查询）。
    let logs = plugins::logs::init(&config, &metrics).await?;
    let hosts = plugins::hosts::init(&config, &metrics);
    let groups = plugins::groups::init(&config, &metrics);
    let cache = plugins::cache::init(&config, &metrics);
    let upstreams = upstream::init(&config, &metrics).await?;
    let rules = plugins::rules::init(&config, &metrics, upstreams);
    let speed = plugins::speed::init(&config);

    let pipeline = Pipeline {
        logs,
        hosts,
        groups,
        cache,
        rules,
        speed,
    };
    let server = Arc::new(DnsServer::new(pipeline));

    // 3. 解析监听地址；加密 bind（tls:// / https:// / h3://）的 TLS 证书在
    //    绑定之前解析（`tls::server_config`）。任一失败 → 返回错误，进程
    //    退出非零（配合 systemd notify：不发送 READY=1）。
    let mut udp_binds = Vec::new();
    let mut tcp_binds = Vec::new();
    let mut tls_binds = Vec::new();
    let mut doh_binds = Vec::new();
    let mut doh3_binds = Vec::new();
    for bind in &config.binds {
        match parse_bind(&bind.address)? {
            BindKind::Udp(addr) => udp_binds.push(addr),
            BindKind::Tcp(addr) => tcp_binds.push(addr),
            BindKind::Tls(addr) => tls_binds.push(addr),
            BindKind::Doh(addr) => doh_binds.push(addr),
            BindKind::Doh3(addr) => doh3_binds.push(addr),
        }
    }
    let tls_config = if !tls_binds.is_empty() || !doh_binds.is_empty() || !doh3_binds.is_empty() {
        Some(server_config(&config)?)
    } else {
        None
    };

    // 4. 绑定全部监听器（UDP/TCP/DoT/DoH/DoH3 + 可选 ui）。任一绑定
    //    失败 → 整体失败退出。
    let mut bound_udp = Vec::new();
    let mut bound_tcp = Vec::new();
    let mut bound_tls = Vec::new();
    let mut bound_doh = Vec::new();
    let mut bound_doh3 = Vec::new();
    for addr in udp_binds {
        bound_udp.push((server.bind_udp(addr).await?, addr));
    }
    for addr in tcp_binds {
        bound_tcp.push((server.bind_tcp(addr).await?, addr));
    }
    for addr in tls_binds {
        bound_tls.push((server.bind_tcp(addr).await?, addr));
    }
    for addr in doh_binds {
        bound_doh.push((server.bind_tcp(addr).await?, addr));
    }
    for addr in doh3_binds {
        bound_doh3.push((server.bind_udp(addr).await?, addr));
    }

    let ui_listener = if let Some(cfg) = plugins::ui::config(&config) {
        Some((plugins::ui::bind_listener(&cfg).await?, cfg))
    } else {
        None
    };

    // 5. 全部绑定成功 → 通知 systemd 服务已 ready（无 NOTIFY_SOCKET 时为空操作）。
    if let Err(e) = notify::sd_notify_ready() {
        warn!("systemd notify failed (non-fatal): {}", e);
    }

    // 6. 并发启动 accept 循环：UDP/TCP/DoT/DoH/DoH3 监听 + ui HTTP 端点。
    let mut tasks = tokio::task::JoinSet::new();
    for (sock, addr) in bound_tcp {
        let server = server.clone();
        tasks.spawn(async move {
            if let Err(e) = server.serve_tcp(sock, addr).await {
                error!("TCP listener on {} failed: {}", addr, e);
            }
        });
    }
    for (sock, addr) in bound_udp {
        let server = server.clone();
        tasks.spawn(async move {
            if let Err(e) = server.serve_udp(sock, addr).await {
                error!("UDP listener on {} failed: {}", addr, e);
            }
        });
    }
    if let Some(tls_config) = tls_config.as_ref() {
        let tls_config = tls_config.clone();
        for (sock, addr) in bound_tls {
            let server = server.clone();
            let tls_config = tls_config.clone();
            tasks.spawn(async move {
                if let Err(e) = server.serve_dot(sock, tls_config, addr).await {
                    error!("DoT listener on {} failed: {}", addr, e);
                }
            });
        }
        for (sock, addr) in bound_doh {
            let server = server.clone();
            let tls_config = tls_config.clone();
            tasks.spawn(async move {
                if let Err(e) = server.serve_doh(sock, tls_config, addr).await {
                    error!("DoH listener on {} failed: {}", addr, e);
                }
            });
        }
        for (sock, addr) in bound_doh3 {
            let server = server.clone();
            let tls_config = tls_config.clone();
            tasks.spawn(async move {
                if let Err(e) = server.serve_doh3(sock, tls_config, addr).await {
                    error!("DoH3 listener on {} failed: {}", addr, e);
                }
            });
        }
    }

    if let Some((listener, cfg)) = ui_listener {
        let registry = metrics.clone();
        tasks.spawn(async move {
            if let Err(e) = plugins::ui::serve_ui(listener, cfg, registry).await {
                error!("ui server failed: {}", e);
            }
        });
    }

    // 无 ui 监听端点时，jemalloc 指标仍周期刷新（供调试/本地观察）。
    #[cfg(feature = "jemalloc")]
    plugins::jemalloc::spawn_refresh(metrics.clone(), std::time::Duration::from_secs(10));

    // 6. 等待任意 listener 结束（通常不会）。
    if let Some(Err(e)) = tasks.join_next().await {
        error!("listener task panicked: {}", e);
    }

    // 7. 关闭前 flush 日志。
    server.flush_logs().await;
    Ok(())
}

/// A parsed bind address, discriminated by its URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindKind {
    /// Plain `ip:port` — UDP.
    Udp(SocketAddr),
    /// `tcp://ip:port` — TCP.
    Tcp(SocketAddr),
    /// `tls://ip:port` — DNS-over-TLS.
    Tls(SocketAddr),
    /// `https://ip:port` — DNS-over-HTTPS (HTTP/1.1 + HTTP/2).
    Doh(SocketAddr),
    /// `h3://ip:port` — DNS-over-HTTP/3.
    Doh3(SocketAddr),
}

/// Parses a bind address string.  Prefix rules:
///
/// - no prefix → UDP; `tcp://` → TCP; `tls://` → DoT; `https://` → DoH;
///   `h3://` → DoH3.
/// - `https://` / `h3://` may carry the RFC 8484 path `/dns-query`; any
///   other path is a startup error.
/// - any other scheme (e.g. `quic://`) is a startup error.
fn parse_bind(s: &str) -> Result<BindKind, Box<dyn std::error::Error>> {
    if let Some(rest) = s.strip_prefix("tcp://") {
        return Ok(BindKind::Tcp(rest.parse()?));
    }
    if let Some(rest) = s.strip_prefix("tls://") {
        return Ok(BindKind::Tls(rest.parse()?));
    }
    if let Some(rest) = s.strip_prefix("https://") {
        return Ok(BindKind::Doh(parse_doh_addr(rest, "https://")?));
    }
    if let Some(rest) = s.strip_prefix("h3://") {
        return Ok(BindKind::Doh3(parse_doh_addr(rest, "h3://")?));
    }
    if s.contains("://") {
        return Err(format!(
            "unsupported bind scheme in \"{s}\": only tcp://, tls://, https:// and h3:// are supported"
        )
        .into());
    }
    Ok(BindKind::Udp(s.parse()?))
}

/// Parses the part after `https://` / `h3://`: an optional `/dns-query`
/// path (the RFC 8484 default, and the only one allowed) followed by the
/// socket address.  A path is rejected unless it is exactly `dns-query`.
fn parse_doh_addr(rest: &str, scheme: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let (addr, path) = match rest.split_once('/') {
        Some((addr, path)) => (addr, Some(path)),
        None => (rest, None),
    };
    let addr: SocketAddr = addr.parse()?;
    match path {
        None | Some("dns-query") => Ok(addr),
        Some(other) => {
            Err(format!("unsupported DoH path \"/{other}\" in \"{scheme}{rest}\": only /dns-query is allowed").into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bind_kinds() {
        assert_eq!(parse_bind("0.0.0.0:53").unwrap(), BindKind::Udp("0.0.0.0:53".parse().unwrap()));
        assert_eq!(
            parse_bind("tcp://0.0.0.0:53").unwrap(),
            BindKind::Tcp("0.0.0.0:53".parse().unwrap())
        );
        assert_eq!(
            parse_bind("tls://0.0.0.0:853").unwrap(),
            BindKind::Tls("0.0.0.0:853".parse().unwrap())
        );
        assert_eq!(
            parse_bind("https://0.0.0.0:8443").unwrap(),
            BindKind::Doh("0.0.0.0:8443".parse().unwrap())
        );
        assert_eq!(
            parse_bind("https://0.0.0.0:8443/dns-query").unwrap(),
            BindKind::Doh("0.0.0.0:8443".parse().unwrap())
        );
        assert_eq!(
            parse_bind("h3://0.0.0.0:8443").unwrap(),
            BindKind::Doh3("0.0.0.0:8443".parse().unwrap())
        );
        assert_eq!(
            parse_bind("h3://[::1]:8443").unwrap(),
            BindKind::Doh3("[::1]:8443".parse().unwrap())
        );
    }

    #[test]
    fn test_parse_bind_invalid() {
        // unsupported schemes
        assert!(parse_bind("quic://0.0.0.0:853").is_err());
        assert!(parse_bind("udp://0.0.0.0:53").is_err());
        assert!(parse_bind("foo://0.0.0.0:53").is_err());
        // DoH path must be exactly /dns-query
        assert!(parse_bind("https://0.0.0.0:8443/other").is_err());
        assert!(parse_bind("h3://0.0.0.0:8443/dns-query").is_ok());
        assert!(parse_bind("https://0.0.0.0:8443/dns-query?x=1").is_err());
        // malformed address
        assert!(parse_bind("not-an-addr").is_err());
    }
}
