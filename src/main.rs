mod common;
mod config;
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
    let logs = plugins::logs::init(&config, &metrics);
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

    // 3. 先绑定全部监听器（UDP/TCP + 可选 metrics）。任一绑定失败 → 返回
    //    错误，进程退出非零（配合 systemd notify：不发送 READY=1）。
    let mut udp_binds = Vec::new();
    let mut tcp_binds = Vec::new();
    for bind in &config.binds {
        let addr: SocketAddr = parse_bind(&bind.address)?;
        if bind.address.starts_with("tcp://") {
            tcp_binds.push((server.bind_tcp(addr).await?, addr));
        } else {
            udp_binds.push((server.bind_udp(addr).await?, addr));
        }
    }

    let metrics_listener = if let Some(cfg) = plugins::metrics::config(&config) {
        Some((plugins::metrics::bind_listener(&cfg).await?, cfg))
    } else {
        None
    };

    // 4. 全部绑定成功 → 通知 systemd 服务已 ready（无 NOTIFY_SOCKET 时为空操作）。
    if let Err(e) = notify::sd_notify_ready() {
        warn!("systemd notify failed (non-fatal): {}", e);
    }

    // 5. 并发启动 accept 循环：UDP/TCP 监听 + metrics HTTP 端点。
    let mut tasks = tokio::task::JoinSet::new();
    for (sock, addr) in tcp_binds {
        let server = server.clone();
        tasks.spawn(async move {
            if let Err(e) = server.serve_tcp(sock, addr).await {
                error!("TCP listener on {} failed: {}", addr, e);
            }
        });
    }
    for (sock, addr) in udp_binds {
        let server = server.clone();
        tasks.spawn(async move {
            if let Err(e) = server.serve_udp(sock, addr).await {
                error!("UDP listener on {} failed: {}", addr, e);
            }
        });
    }

    if let Some((listener, cfg)) = metrics_listener {
        let registry = metrics.clone();
        tasks.spawn(async move {
            if let Err(e) = plugins::metrics::serve_metrics(listener, cfg, registry).await {
                error!("metrics server failed: {}", e);
            }
        });
    }

    // 6. 等待任意 listener 结束（通常不会）。
    if let Some(Err(e)) = tasks.join_next().await {
        error!("listener task panicked: {}", e);
    }

    // 7. 关闭前 flush 日志。
    server.flush_logs().await;
    Ok(())
}

fn parse_bind(s: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let s = s.strip_prefix("tcp://").unwrap_or(s);
    s.parse::<SocketAddr>().map_err(|e| e.into())
}
