//! DNS upstream module: connection primitives, connection pool and named
//! upstream groups.
//!
//! Layout:
//!
//! - [`config`] — configuration types (`upstreams[]` / `servers` / `pool`)
//! - [`conn`] — `Exchange` (`DnsExchange`) + connection factory types
//! - [`factory`] — protocol-specific connection factories
//! - [`pool`] — adaptive connection pool
//! - this module — [`UpstreamClient`], [`UpstreamGroup`], [`Upstreams`]
//!   and [`init`] (parse → bootstrap resolve → assemble → [`Upstreams`])
//!
//! ## Error classification
//!
//! `UpstreamClient::query()` returns `io::Result<Message>`.  Errors
//! (returned as `Err(_)`) indicate that **no valid DNS response was
//! received** — the caller should retry the next server in the group
//! (`UpstreamGroup`) or return a SERVFAIL to the client.
//!
//! Errors that **do** produce `Err` (and thus trigger retry or SERVFAIL):
//!
//! | Source layer       | Example error                  | io::ErrorKind      |
//! |--------------------|--------------------------------|--------------------|
//! | Pool exhausted     | `NotConnected` — no address available / all failed to connect | NotConnected |
//! | Connection setup   | TCP connect / TLS handshake / QUIC handshake timeout or refused | TimedOut, ConnectionRefused, ConnectionReset |
//! | Connection dead    | `DnsExchange` background task exited / sender channel closed | BrokenPipe, Other |
//! | DNS transport      | `dns timeout` — no response within `dns_timeout` | TimedOut |
//! | Stream closed      | Multiplexer or QUIC stream terminated | ConnectionAborted, ConnectionReset, UnexpectedEof |
//! | DNS format         | Wire-format parse error in response | Other |
//! | Mux queue overflow | `mux request queue full` (256 outstanding requests) | Other |
//!
//! Errors that do **not** produce `Err` (they arrive as `Ok(Message)`)
//! because a valid DNS response was received:
//!
//! | DNS rcode       | Meaning                        | Handler responsibility |
//! |-----------------|--------------------------------|------------------------|
//! | SERVFAIL        | Upstream resolver failed       | Propagated as-is; caller may return SERVFAIL |
//! | NXDOMAIN        | Name does not exist            | Cached as negative (NxDomain) in `cache_upstream_response` |
//! | REFUSED         | Upstream refused the query     | Propagated as-is |
//! | FORMERR         | Upstream rejected query format | Propagated as-is |
//! | NoError (empty) | No records of requested type   | Cached as negative (NoData) in `cache_upstream_response` |
//!
//! `UpstreamGroup` retry semantics:
//!
//! - **Serial mode**: iterates clients in config order; first `Ok` response
//!   wins; on `Err`, moves to the next client.  Returns the last error if
//!   all clients fail.
//! - **Parallel mode**: races all clients concurrently; first `Ok` wins;
//!   on `Err`, waits for remaining.  Returns the last error if all fail.
//! - **Random mode**: picks a random order per query, then behaves like
//!   serial (first `Ok` wins, next on error).
//! - **RoundRobin mode**: rotates the starting client per query, then
//!   behaves like serial.
//!
//! All fallback modes (serial/random/round-robin) skip clients currently in
//! **cooldown** (see [`config::CooldownConfig`]) — a per-client circuit
//! breaker that trips after `threshold` transport errors within `window`
//! and skips the client for `cooldown`.  If every client is in cooldown, a
//! `NotConnected` error is returned immediately.
//!
//! In all modes, retry is at the **server** (UpstreamClient) granularity,
//! not at the connection level.  Connection-level retry (same server,
//! different address) is handled internally by `ConnectionPool::checkout()`.

pub mod config;
pub mod conn;
pub mod factory;
pub mod pool;

use ahash::AHashMap;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use hickory_net::xfer::{DnsHandle, FirstAnswer};
use hickory_proto::op::{DnsRequest, DnsRequestOptions, Edns, Message};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use log::{info, warn};
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::common::tls::default_tls_client_config;

use crate::config::Config;
use crate::metrics::{Counter, MetricsRegistry};

use self::config::{parse_cooldown, CooldownConfig, QueryModeConfig, RawPoolConfig};
use self::pool::{ConnectionPool, PreferFamily};

/// A single upstream DNS client backed by a connection pool.
///
/// Cheap to clone — all clones share the same pool via `Arc`.
#[derive(Clone)]
pub struct UpstreamClient {
    pool: Arc<ConnectionPool>,
}

impl UpstreamClient {
    /// Creates a client that draws connections from `pool`.
    pub fn new(pool: Arc<ConnectionPool>) -> Self {
        Self { pool }
    }

    /// The transport protocol of this client's pool ("udp"/"tcp"/"tls"/"doh"/"doh3"/"doq").
    pub fn proto(&self) -> &'static str {
        self.pool.proto()
    }

    /// Sends a DNS query through the pool and returns the response.
    ///
    /// Internally calls `pool.checkout()` to obtain an `Exchange`, then
    /// `sender.send(request).first_answer().await` with the pool's per-request
    /// DNS timeout.
    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        let guard = self
            .pool
            .checkout()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no available connection in pool"))?;

        let request = DnsRequest::new(msg.clone(), DnsRequestOptions::default());
        let result = tokio::time::timeout(self.pool.dns_timeout(), guard.sender().send(request).first_answer())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "dns timeout"))
            .and_then(|response| response.map(|m| m.into_message()).map_err(io::Error::other));

        match result {
            Ok(message) => {
                guard.record_success();
                Ok(message)
            }
            Err(err) => {
                guard.record_failure();
                Err(err)
            }
        }
    }
}

/// Inserts the EDNS Client Subnet option into `msg` if not already present.
///
/// When `msg` carries no EDNS OPT record yet, one is created with hickory's
/// defaults and the option is inserted; an existing OPT record is left
/// untouched apart from the inserted option.
pub(crate) fn apply_edns(msg: &mut Message, subnet: &ClientSubnet) {
    let Some(edns) = msg.edns.as_mut() else {
        let mut edns = Edns::default();
        edns.options_mut().insert(EdnsOption::Subnet(*subnet));
        msg.set_edns(edns);
        return;
    };
    if edns.option(EdnsCode::Subnet).is_none() {
        edns.options_mut().insert(EdnsOption::Subnet(*subnet));
    }
}

/// A group of upstream clients queried concurrently.
/// Keyed by the upstream pool name from the config.
pub struct UpstreamGroup {
    clients: Vec<UpstreamClient>,
    mode: QueryModeConfig,
    cooldown: Option<CooldownConfig>,
    /// Round-robin cursor (per group, shared across queries).
    rr_cursor: AtomicUsize,
    /// Per-client cooldown state, one entry per client.
    breaker: Vec<Breaker>,
}

/// Sliding-window circuit breaker for one client.
struct Breaker {
    /// Recent transport-error timestamps (for window counting).
    errors: Mutex<VecDeque<Instant>>,
    /// Until when this client is skipped.
    cool_until: Mutex<Option<Instant>>,
}

impl Breaker {
    fn new() -> Self {
        Self {
            errors: Mutex::new(VecDeque::new()),
            cool_until: Mutex::new(None),
        }
    }

    fn in_cooldown(&self, now: Instant) -> bool {
        self.cool_until.lock().is_some_and(|until| until > now)
    }

    fn record_failure(&self, cfg: CooldownConfig, now: Instant) {
        // Drop errors outside the window, then push the new one.
        let mut errors = self.errors.lock();
        while errors.front().is_some_and(|t| now.duration_since(*t) > cfg.window) {
            errors.pop_front();
        }
        errors.push_back(now);
        if errors.len() as u32 >= cfg.threshold {
            *self.cool_until.lock() = Some(now + cfg.cooldown);
        }
    }

    fn record_success(&self) {
        self.errors.lock().clear();
    }
}

impl UpstreamGroup {
    /// Creates a group with a cooldown policy.
    pub fn with_cooldown(
        clients: Vec<UpstreamClient>,
        mode: QueryModeConfig,
        cooldown: Option<CooldownConfig>,
    ) -> Self {
        let n = clients.len();
        Self {
            clients,
            mode,
            cooldown,
            rr_cursor: AtomicUsize::new(0),
            breaker: (0..n).map(|_| Breaker::new()).collect(),
        }
    }

    /// The protocol of the first client (for metrics labeling).
    pub fn proto(&self) -> &'static str {
        self.clients.first().map(|c| c.proto()).unwrap_or("mixed")
    }

    /// Sends `msg` using the group's configured query mode.
    pub async fn query(&self, msg: &Message) -> io::Result<Message> {
        match self.mode {
            QueryModeConfig::Serial => self.query_ordered(msg, &self.serial_order()).await,
            QueryModeConfig::Random => self.query_ordered(msg, &self.random_order()).await,
            QueryModeConfig::RoundRobin => self.query_ordered(msg, &self.round_robin_order()).await,
            QueryModeConfig::Parallel => self.query_parallel(msg).await,
        }
    }

    /// Returns client indices in config order.
    fn serial_order(&self) -> Vec<usize> {
        (0..self.clients.len()).collect()
    }

    /// Returns client indices in a random order.
    fn random_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.clients.len()).collect();
        order.shuffle(&mut rand::rng());
        order
    }

    /// Returns client indices starting from a rotating cursor (wrap-around).
    fn round_robin_order(&self) -> Vec<usize> {
        let n = self.clients.len();
        if n == 0 {
            return Vec::new();
        }
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % n;
        (0..n).map(|i| (start + i) % n).collect()
    }

    /// Ordered fallback: try each client (skipping cooldown) in `order`;
    /// first `Ok` wins; records failures/successes for the breaker.
    async fn query_ordered(&self, msg: &Message, order: &[usize]) -> io::Result<Message> {
        let mut first_err: Option<io::Error> = None;
        let mut tried_any = false;
        let now = Instant::now();
        let cooldown = self.cooldown;
        for &idx in order {
            let Some(client) = self.clients.get(idx) else { continue };
            let breaker = &self.breaker[idx];
            if cooldown.is_some() && breaker.in_cooldown(now) {
                continue;
            }
            tried_any = true;
            match client.query(msg).await {
                Ok(response) => {
                    if cooldown.is_some() {
                        breaker.record_success();
                    }
                    return Ok(response);
                }
                Err(e) => {
                    if let Some(cfg) = cooldown {
                        breaker.record_failure(cfg, Instant::now());
                    }
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if !tried_any {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "all upstreams in cooldown"));
        }
        Err(first_err.unwrap_or_else(|| io::Error::other(NO_UPSTREAMS_MSG)))
    }

    async fn query_parallel(&self, msg: &Message) -> io::Result<Message> {
        // Parallel mode also respects cooldown: clients in cooldown are
        // skipped; if all are skipped, fail fast with NotConnected.
        let now = Instant::now();
        let cooldown = self.cooldown;
        let indices: Vec<usize> = self
            .clients
            .iter()
            .enumerate()
            .filter(|(i, _)| !(cooldown.is_some() && self.breaker[*i].in_cooldown(now)))
            .map(|(i, _)| i)
            .collect();
        if indices.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "all upstreams in cooldown"));
        }

        let mut futs: FuturesUnordered<_> = indices
            .iter()
            .map(|&i| {
                let client = self.clients[i].clone();
                let m = msg.clone();
                async move { (i, client.query(&m).await) }
            })
            .collect();

        let mut first_err: Option<io::Error> = None;
        while let Some((idx, result)) = futs.next().await {
            match result {
                Ok(response) => {
                    if cooldown.is_some() {
                        self.breaker[idx].record_success();
                    }
                    return Ok(response);
                }
                Err(e) => {
                    if let Some(cfg) = cooldown {
                        self.breaker[idx].record_failure(cfg, Instant::now());
                    }
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        Err(first_err.unwrap_or_else(|| io::Error::other(NO_UPSTREAMS_MSG)))
    }
}

const NO_UPSTREAMS_MSG: &str = "no upstream servers configured";

// ---------------------------------------------------------------------------
// Upstream config parsing
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum UpstreamConfig {
    Pool {
        pool: Arc<ConnectionPool>,
    },
    NeedResolve {
        server_name: String,
        port: u16,
        factory: conn::ConnFactory,
        raw_pool: Option<RawPoolConfig>,
        proto: &'static str,
        /// Address family filter applied when bootstrap-resolving `server_name`.
        prefer_family: PreferFamily,
    },
}

impl UpstreamConfig {
    fn needs_resolve(&self) -> bool {
        matches!(self, Self::NeedResolve { .. })
    }

    fn from_tls_url(rest: &str, tls_name: Option<String>, raw_pool: Option<RawPoolConfig>) -> Option<Self> {
        let (host, port) = parse_host_port(rest)?;
        let tls_config = default_tls_client_config();
        // TLS server name: explicit `server_name` wins, otherwise the address host.
        let tls_name = tls_name.unwrap_or_else(|| host.clone());
        match host.as_str().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool_cfg = raw_pool.unwrap_or_default().into_pool_config();
                let pool =
                    ConnectionPool::with_proto(vec![addr], factory::tls_factory(tls_name, tls_config), pool_cfg, "tls");
                Some(Self::Pool { pool })
            }
            Err(_) => {
                let factory = factory::tls_factory(tls_name, tls_config);
                let prefer_family = raw_pool.as_ref().map_or(PreferFamily::Any, |p| p.prefer_family());
                Some(Self::NeedResolve {
                    server_name: host,
                    port,
                    factory,
                    raw_pool,
                    proto: "tls",
                    prefer_family,
                })
            }
        }
    }

    fn from_http_url(addr: &str, tls_name: Option<String>, raw_pool: Option<RawPoolConfig>) -> Option<Self> {
        let parsed: url::Url = addr.parse().ok()?;
        let host: Arc<str> = parsed.host_str()?.to_string().into();
        let port = parsed.port_or_known_default().unwrap_or(443);
        let path: Arc<str> = match parsed.query() {
            Some(q) => format!("{}?{}", parsed.path(), q),
            None => parsed.path().to_string(),
        }
        .into();

        let tls_config = default_tls_client_config();
        let is_h3 = parsed.scheme() != "https";
        // TLS server name (SNI + DoH Host header): explicit `server_name`
        // wins, otherwise the address host.
        let tls_name: Arc<str> = tls_name.unwrap_or_else(|| host.to_string()).into();
        let factory: conn::ConnFactory = if is_h3 {
            factory::doh3_factory(tls_name.clone(), path.clone(), tls_config.clone())
        } else {
            factory::doh_factory(tls_name.clone(), path.clone(), tls_config.clone())
        };
        let proto = if is_h3 { "doh3" } else { "doh" };

        let pool_cfg = raw_pool.clone().unwrap_or_default().into_pool_config();
        match host.as_ref().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool = ConnectionPool::with_proto(vec![addr], factory, pool_cfg, proto);
                Some(Self::Pool { pool })
            }
            Err(_) => {
                let prefer_family = raw_pool.as_ref().map_or(PreferFamily::Any, |p| p.prefer_family());
                Some(Self::NeedResolve {
                    server_name: host.to_string(),
                    port,
                    factory,
                    raw_pool,
                    proto,
                    prefer_family,
                })
            }
        }
    }

    fn from_quic_url(rest: &str, tls_name: Option<String>, raw_pool: Option<RawPoolConfig>) -> Option<Self> {
        let (host, port) = parse_host_port(rest)?;
        let tls_config = default_tls_client_config();
        // TLS server name: explicit `server_name` wins, otherwise the address host.
        let tls_name: Arc<str> = tls_name.unwrap_or_else(|| host.clone()).into();
        match host.as_str().parse::<IpAddr>() {
            Ok(ip) => {
                let addr = SocketAddr::new(ip, port);
                let pool_cfg = raw_pool.unwrap_or_default().into_pool_config();
                let pool =
                    ConnectionPool::with_proto(vec![addr], factory::doq_factory(tls_name, tls_config), pool_cfg, "doq");
                Some(Self::Pool { pool })
            }
            Err(_) => {
                let factory = factory::doq_factory(tls_name, tls_config);
                let prefer_family = raw_pool.as_ref().map_or(PreferFamily::Any, |p| p.prefer_family());
                Some(Self::NeedResolve {
                    server_name: host,
                    port,
                    factory,
                    raw_pool,
                    proto: "doq",
                    prefer_family,
                })
            }
        }
    }
}

fn build_tcp_pool(addr: SocketAddr, raw_pool: Option<RawPoolConfig>) -> Arc<ConnectionPool> {
    let pool_cfg = raw_pool.unwrap_or_default().into_pool_config();
    ConnectionPool::with_proto(vec![addr], factory::tcp_factory(), pool_cfg, "tcp")
}

fn build_udp_pool(addr: SocketAddr, raw_pool: Option<RawPoolConfig>) -> Arc<ConnectionPool> {
    let pool_cfg = raw_pool.unwrap_or_default().into_pool_config();
    ConnectionPool::with_proto(vec![addr], factory::udp_factory(), pool_cfg, "udp")
}

/// Parses a host[:port] pair for the UDP/TCP protocols, defaulting to port 53.
///
/// Returns `Some((host, port))` for any syntactically valid host (IP literal
/// or domain); `None` only for an empty host or a malformed port.  A bare
/// domain like `dns.pub` is accepted — resolution happens later through the
/// bootstrap clients (`NeedResolve`).
fn parse_host_port_default_53(s: &str) -> Option<(String, u16)> {
    if s.is_empty() {
        return None;
    }
    // Whole string is an IP literal (e.g. bare IPv6 `2001:4860::8888`).
    if s.parse::<IpAddr>().is_ok() {
        return Some((s.to_string(), 53));
    }
    // Bracketed IPv6: `[addr]` / `[addr]:port`.
    if let Some(rest) = s.strip_prefix('[') {
        let (addr, port) = rest.split_once(']')?;
        if addr.is_empty() || addr.parse::<IpAddr>().is_err() {
            return None;
        }
        let port = port.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).unwrap_or(53);
        return Some((addr.to_string(), port));
    }
    // `host:port` — port must be numeric.
    match s.rsplit_once(':') {
        Some((host, port_str)) if !host.is_empty() => port_str.parse::<u16>().ok().map(|port| (host.to_string(), port)),
        // `:port` alone has no host.
        Some(("", _)) => None,
        // Bare host — default DNS port.
        _ => Some((s.to_string(), 53)),
    }
}

/// Builds a `NeedResolve` config for a UDP/TCP server whose address host is
/// a domain (to be resolved via the bootstrap clients at startup).
fn tcp_need_resolve(host: String, port: u16, raw_pool: Option<RawPoolConfig>) -> UpstreamConfig {
    let prefer_family = raw_pool.as_ref().map_or(PreferFamily::Any, |p| p.prefer_family());
    UpstreamConfig::NeedResolve {
        server_name: host,
        port,
        factory: factory::tcp_factory(),
        raw_pool,
        proto: "tcp",
        prefer_family,
    }
}

fn udp_need_resolve(host: String, port: u16, raw_pool: Option<RawPoolConfig>) -> UpstreamConfig {
    let prefer_family = raw_pool.as_ref().map_or(PreferFamily::Any, |p| p.prefer_family());
    UpstreamConfig::NeedResolve {
        server_name: host,
        port,
        factory: factory::udp_factory(),
        raw_pool,
        proto: "udp",
        prefer_family,
    }
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    s.rsplit_once(':')
        .and_then(|(host, port_str)| port_str.parse::<u16>().ok().map(|port| (host.to_string(), port)))
        .or_else(|| Some((s.to_string(), 853)))
}

fn scheme(addr: &str) -> (Option<&str>, &str) {
    for p in ["udp://", "tcp://", "tls://", "https://", "h3://", "quic://"] {
        if let Some(rest) = addr.strip_prefix(p) {
            return (Some(p), rest);
        }
    }
    (None, addr)
}

fn parse_upstream(addr: &str, server_name: Option<String>, raw_pool: Option<RawPoolConfig>) -> Option<UpstreamConfig> {
    use UpstreamConfig as U;
    match scheme(addr) {
        (Some("udp://"), rest) | (None, rest) => {
            let (host, port) = parse_host_port_default_53(rest)?;
            match host.as_str().parse::<IpAddr>() {
                Ok(ip) => {
                    let sock_addr = SocketAddr::new(ip, port);
                    let pool = build_udp_pool(sock_addr, raw_pool);
                    Some(U::Pool { pool })
                }
                Err(_) => Some(udp_need_resolve(host, port, raw_pool)),
            }
        }
        (Some("tcp://"), rest) => {
            let (host, port) = parse_host_port_default_53(rest)?;
            match host.as_str().parse::<IpAddr>() {
                Ok(ip) => {
                    let sock_addr = SocketAddr::new(ip, port);
                    let pool = build_tcp_pool(sock_addr, raw_pool);
                    Some(U::Pool { pool })
                }
                Err(_) => Some(tcp_need_resolve(host, port, raw_pool)),
            }
        }
        (Some("tls://"), rest) => U::from_tls_url(rest, server_name, raw_pool),
        (Some("https://"), _) | (Some("h3://"), _) => U::from_http_url(addr, server_name, raw_pool),
        (Some("quic://"), rest) => U::from_quic_url(rest, server_name, raw_pool),
        _ => None,
    }
}

fn classify_upstream(addr: &str) -> &'static str {
    match scheme(addr).0 {
        Some("udp://") | None => "UDP",
        Some("tcp://") => "TCP",
        Some("tls://") => "TLS",
        Some("https://") => "DoH",
        Some("h3://") => "DoH3",
        Some("quic://") => "DoQ",
        Some(_) => "UDP",
    }
}

// ---------------------------------------------------------------------------
// Bootstrap resolution
// ---------------------------------------------------------------------------

async fn bootstrap_resolve_all(
    bootstrap_clients: &[UpstreamClient],
    targets: &[(usize, UpstreamConfig)],
) -> Vec<(usize, Vec<SocketAddr>)> {
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::{RData, RecordType};

    async fn resolve_host_all(
        bootstrap_clients: &[UpstreamClient],
        host: &str,
        port: u16,
        prefer_family: PreferFamily,
    ) -> Vec<SocketAddr> {
        let mut addrs = Vec::new();

        for qtype in [RecordType::A, RecordType::AAAA] {
            match prefer_family {
                PreferFamily::Ipv4 if qtype != RecordType::A => continue,
                PreferFamily::Ipv6 if qtype != RecordType::AAAA => continue,
                _ => {}
            }
            let Ok(msg) = make_query_msg(host, qtype) else { continue };

            for client in bootstrap_clients {
                match client.query(&msg).await {
                    Ok(resp) => {
                        for answer in &resp.answers {
                            match answer.data {
                                RData::A(ip) => {
                                    addrs.push(SocketAddr::new(IpAddr::V4(ip.0), port));
                                }
                                RData::AAAA(ip) => {
                                    addrs.push(SocketAddr::new(IpAddr::V6(ip.0), port));
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Bootstrap query failed for {} ({}): {}", host, qtype, e);
                    }
                }
            }
        }
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    let mut results = Vec::new();
    for (idx, cfg) in targets {
        let (host_str, port, prefer_family) = match cfg {
            UpstreamConfig::NeedResolve {
                server_name,
                port,
                prefer_family,
                ..
            } => (server_name.clone(), *port, *prefer_family),
            _ => continue,
        };
        let addrs = resolve_host_all(bootstrap_clients, &host_str, port, prefer_family).await;
        results.push((*idx, addrs));
    }
    results
}

fn build_resolved_pool(cfg: &UpstreamConfig, addrs: Vec<SocketAddr>) -> Arc<ConnectionPool> {
    let UpstreamConfig::NeedResolve {
        factory,
        raw_pool,
        proto,
        ..
    } = cfg
    else {
        unreachable!("only called with NeedResolve configs");
    };
    let pool_cfg = raw_pool.clone().unwrap_or_default().into_pool_config();
    ConnectionPool::with_proto(addrs, factory.clone(), pool_cfg, proto)
}

// ---------------------------------------------------------------------------
// Upstreams + init
// ---------------------------------------------------------------------------

struct UpstreamMetrics {
    query_total: Counter,
    error_total: Counter,
}

impl UpstreamMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            query_total: registry.counter("rsdns_upstream_query_total", "Upstream queries", &["upstream", "proto"]),
            error_total: registry.counter("rsdns_upstream_error_total", "Upstream errors", &["upstream", "kind"]),
        }
    }
}

/// The assembled named upstream pools.
///
/// A concrete type (not a trait object) — the only consumer is the `rules`
/// stage, which holds an `Arc<Upstreams>` directly.
pub struct Upstreams {
    groups: AHashMap<String, UpstreamGroup>,
    metrics: UpstreamMetrics,
}

impl Upstreams {
    /// Sends `msg` to the named upstream pool and returns the response.
    pub async fn query(&self, name: &str, msg: &Message) -> io::Result<Message> {
        let group = self
            .groups
            .get(name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("upstream {} not found", name)))?;
        let result = group.query(msg).await;

        let proto = group.proto();
        self.metrics.query_total.with_label_values(&[name, proto]).inc();
        if let Err(e) = &result {
            let kind = classify_error(e);
            self.metrics.error_total.with_label_values(&[name, kind]).inc();
        }
        result
    }
}

fn classify_error(e: &io::Error) -> &'static str {
    match e.kind() {
        io::ErrorKind::TimedOut => "timeout",
        io::ErrorKind::ConnectionRefused => "refused",
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => "reset",
        _ => "other",
    }
}

/// Builds [`Upstreams`] from the top-level `upstreams[]` array:
/// parse servers → resolve domain servers via the IP-address servers →
/// assemble named groups → register metrics.
///
/// A server whose address is an IP is used directly.  A server whose
/// address is a domain is resolved through the IP-address servers (the
/// bootstrap resolvers) and the resolved addresses are used for the pool.
pub async fn init(config: &Config, registry: &MetricsRegistry) -> Result<Arc<Upstreams>, String> {
    let mut all_configs: Vec<UpstreamConfig> = Vec::new();
    let mut upstream_map: Vec<(String, Vec<usize>, QueryModeConfig, Option<CooldownConfig>)> = Vec::new();

    info!("rsdns starting, upstream pools: {}", config.upstreams.len());
    for group in &config.upstreams {
        let servers = &group.servers;
        info!("  upstream pool '{}': {} server(s)", group.name, servers.len());
        let cooldown = match &group.cooldown {
            Some(spec) => match parse_cooldown(spec) {
                Ok(cd) => cd,
                Err(e) => {
                    warn!("  upstream pool '{}': {}", group.name, e);
                    None
                }
            },
            None => None,
        };
        let mut indices = Vec::new();
        for server in servers {
            let idx = all_configs.len();
            let protocol_label = classify_upstream(&server.address);
            info!("    protocol '{}' server: {}", protocol_label, server.address);

            if let Some(cfg) = parse_upstream(&server.address, server.server_name.clone(), server.pool.clone()) {
                all_configs.push(cfg);
                indices.push(idx);
            } else {
                warn!("    failed to parse upstream: {}", server.address);
            }
        }
        upstream_map.push((group.name.clone(), indices, group.mode, cooldown));
    }

    // Phase 1: bootstrap resolvers — every server whose address is an IP.
    let bootstrap_clients: Vec<UpstreamClient> = all_configs
        .iter()
        .filter_map(|cfg| match cfg {
            UpstreamConfig::Pool { pool } => Some(UpstreamClient::new(pool.clone())),
            _ => None,
        })
        .collect();
    info!("bootstrap clients (IP servers): {}", bootstrap_clients.len());
    if bootstrap_clients.is_empty() && all_configs.iter().any(UpstreamConfig::needs_resolve) {
        return Err("no IP-address upstream server configured to resolve domain upstreams".into());
    }

    // Phase 2: resolve domain upstreams via the IP-address servers.
    let dynamic_indices: Vec<usize> = all_configs
        .iter()
        .enumerate()
        .filter(|(_, c)| c.needs_resolve())
        .map(|(i, _)| i)
        .collect();

    if !dynamic_indices.is_empty() {
        info!("resolving {} dynamic upstream(s) via bootstrap...", dynamic_indices.len());
        let dynamic_entries: Vec<(usize, UpstreamConfig)> =
            dynamic_indices.iter().map(|&i| (i, all_configs[i].clone())).collect();
        let resolved = bootstrap_resolve_all(&bootstrap_clients, &dynamic_entries).await;

        for (idx, addrs) in resolved {
            if addrs.is_empty() {
                return Err(format!("failed to resolve dynamic upstream index={}", idx));
            }
            info!("    resolved index={}, addresses {:?}", idx, addrs);
            let pool = build_resolved_pool(&all_configs[idx], addrs);
            all_configs[idx] = UpstreamConfig::Pool { pool };
        }
    }

    // Phase 3: assemble groups + attach pool metrics per group
    let metrics = UpstreamMetrics::new(registry);
    let pool_metrics = pool::PoolMetrics::register(registry);

    let groups: AHashMap<String, UpstreamGroup> = upstream_map
        .into_iter()
        .map(|(name, indices, mode, cooldown)| {
            let clients: Vec<UpstreamClient> = indices
                .iter()
                .filter_map(|&i| match &all_configs[i] {
                    UpstreamConfig::Pool { pool } => {
                        pool.set_pool_identity(&name, &pool_metrics);
                        Some(UpstreamClient::new(pool.clone()))
                    }
                    _ => None,
                })
                .collect();
            (name, UpstreamGroup::with_cooldown(clients, mode, cooldown))
        })
        .collect();

    Ok(Arc::new(Upstreams { groups, metrics }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::RecordType;
    use std::net::IpAddr;
    use std::str::FromStr;
    use std::time::Duration;

    #[test]
    fn test_parse_host_port_default_53() {
        // IPs and ports.
        assert_eq!(parse_host_port_default_53("223.5.5.5"), Some(("223.5.5.5".into(), 53)));
        assert_eq!(parse_host_port_default_53("223.5.5.5:5353"), Some(("223.5.5.5".into(), 5353)));
        assert_eq!(parse_host_port_default_53("dns.pub"), Some(("dns.pub".into(), 53)));
        assert_eq!(parse_host_port_default_53("dns.pub:5353"), Some(("dns.pub".into(), 5353)));
        assert_eq!(parse_host_port_default_53("dot.pub"), Some(("dot.pub".into(), 53)));
        // Bare IPv6 (whole string is an IP literal).
        assert_eq!(
            parse_host_port_default_53("2001:4860::8888"),
            Some(("2001:4860::8888".into(), 53))
        );
        // Bracketed IPv6.
        assert_eq!(
            parse_host_port_default_53("[2001:4860::8888]"),
            Some(("2001:4860::8888".into(), 53))
        );
        assert_eq!(
            parse_host_port_default_53("[2001:4860::8888]:5353"),
            Some(("2001:4860::8888".into(), 5353))
        );
        // Invalid inputs.
        assert_eq!(parse_host_port_default_53(""), None);
        assert_eq!(parse_host_port_default_53(":53"), None);
        assert_eq!(parse_host_port_default_53("dns.pub:notaport"), None);
    }

    #[test]
    fn test_parse_upstream_domain_needs_resolve() {
        // Bare domain (UDP, default port 53).
        let cfg = parse_upstream("dns.pub", None, None).expect("bare domain parses");
        let UpstreamConfig::NeedResolve {
            server_name,
            port,
            proto,
            ..
        } = cfg
        else {
            panic!("expected NeedResolve");
        };
        assert_eq!(server_name, "dns.pub");
        assert_eq!(port, 53);
        assert_eq!(proto, "udp");

        // tcp:// domain (default port 53).
        let cfg = parse_upstream("tcp://dns.pub", None, None).expect("tcp domain parses");
        let UpstreamConfig::NeedResolve {
            server_name,
            port,
            proto,
            ..
        } = cfg
        else {
            panic!("expected NeedResolve");
        };
        assert_eq!(server_name, "dns.pub");
        assert_eq!(port, 53);
        assert_eq!(proto, "tcp");

        // Explicit port is preserved.
        let cfg = parse_upstream("tcp://dns.pub:5353", None, None).expect("tcp domain with port parses");
        let UpstreamConfig::NeedResolve {
            server_name,
            port,
            proto,
            ..
        } = cfg
        else {
            panic!("expected NeedResolve");
        };
        assert_eq!(server_name, "dns.pub");
        assert_eq!(port, 5353);
        assert_eq!(proto, "tcp");
    }

    #[tokio::test]
    async fn test_parse_upstream_ip_is_pool() {
        // Bare IP (UDP).
        let cfg = parse_upstream("223.5.5.5", None, None).expect("bare IP parses");
        match cfg {
            UpstreamConfig::Pool { pool } => assert_eq!(pool.proto(), "udp"),
            _ => panic!("expected Pool"),
        }

        // tcp:// IP.
        let cfg = parse_upstream("tcp://8.8.8.8", None, None).expect("tcp IP parses");
        match cfg {
            UpstreamConfig::Pool { pool } => assert_eq!(pool.proto(), "tcp"),
            _ => panic!("expected Pool"),
        }

        // tcp:// IP with explicit port.
        let cfg = parse_upstream("tcp://8.8.8.8:5353", None, None).expect("tcp IP with port parses");
        match cfg {
            UpstreamConfig::Pool { pool } => assert_eq!(pool.proto(), "tcp"),
            _ => panic!("expected Pool"),
        }
    }

    #[test]
    fn test_parse_cooldown_spec() {
        let c = parse_cooldown("1m:10:10s").unwrap().unwrap();
        assert_eq!(c.window, Duration::from_secs(60));
        assert_eq!(c.threshold, 10);
        assert_eq!(c.cooldown, Duration::from_secs(10));

        // Bare numbers = seconds; hours supported.
        let c = parse_cooldown("30:3:5").unwrap().unwrap();
        assert_eq!(c.window, Duration::from_secs(30));
        assert_eq!(c.threshold, 3);
        assert_eq!(c.cooldown, Duration::from_secs(5));

        let c = parse_cooldown("2h:1:1m").unwrap().unwrap();
        assert_eq!(c.window, Duration::from_secs(7200));
        assert_eq!(c.cooldown, Duration::from_secs(60));

        // Empty = disabled; malformed / zero rejected.
        assert_eq!(parse_cooldown("").unwrap(), None);
        assert_eq!(parse_cooldown("   ").unwrap(), None);
        for bad in ["1m:10", "1m:10:10s:extra", "1m:0:10s", "x:1:1s", "1m:1:", "1m:abc:10s"] {
            assert!(parse_cooldown(bad).is_err(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn test_breaker_trips_on_threshold_within_window() {
        let cfg = CooldownConfig {
            window: Duration::from_secs(60),
            threshold: 3,
            cooldown: Duration::from_secs(10),
        };
        let b = Breaker::new();
        let now = Instant::now();
        assert!(!b.in_cooldown(now));
        b.record_failure(cfg, now);
        b.record_failure(cfg, now + Duration::from_millis(1));
        assert!(!b.in_cooldown(now + Duration::from_millis(2)));
        // Third error within the window trips the breaker.
        b.record_failure(cfg, now + Duration::from_millis(2));
        assert!(b.in_cooldown(now + Duration::from_millis(3)));
        // After cooldown elapses it recovers.
        assert!(!b.in_cooldown(now + cfg.cooldown + Duration::from_secs(1)));
        // A success clears the error window.
        let b2 = Breaker::new();
        b2.record_failure(cfg, now);
        b2.record_failure(cfg, now + Duration::from_millis(1));
        b2.record_success();
        assert_eq!(b2.errors.lock().len(), 0);
        assert!(!b2.in_cooldown(now + Duration::from_millis(2)));
    }

    #[test]
    fn test_breaker_window_expiry_evicts_old_errors() {
        let cfg = CooldownConfig {
            window: Duration::from_secs(5),
            threshold: 2,
            cooldown: Duration::from_secs(10),
        };
        let b = Breaker::new();
        let now = Instant::now();
        b.record_failure(cfg, now);
        // Old error falls out of the window → second error does not trip.
        b.record_failure(cfg, now + Duration::from_secs(6));
        assert!(!b.in_cooldown(now + Duration::from_secs(6)));
    }

    #[test]
    fn test_group_modes_build_orders() {
        // Round-robin rotates the starting index across calls.
        let g = UpstreamGroup::with_cooldown(vec![client(), client(), client()], QueryModeConfig::RoundRobin, None);
        let o1 = g.round_robin_order();
        let o2 = g.round_robin_order();
        let o3 = g.round_robin_order();
        assert_eq!(o1, vec![0, 1, 2]);
        assert_eq!(o2, vec![1, 2, 0]);
        assert_eq!(o3, vec![2, 0, 1]);

        // Random order is always a permutation of all indices.
        let g =
            UpstreamGroup::with_cooldown(vec![client(), client(), client(), client()], QueryModeConfig::Random, None);
        for _ in 0..10 {
            let mut o = g.random_order();
            let mut sorted = o.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, vec![0, 1, 2, 3]);
            assert_eq!(o.len(), 4);
            // No duplicates.
            o.sort_unstable();
            o.dedup();
            assert_eq!(o.len(), 4);
        }

        // Serial = config order.
        let g = UpstreamGroup::with_cooldown(vec![client(), client(), client()], QueryModeConfig::Serial, None);
        assert_eq!(g.serial_order(), vec![0, 1, 2]);
    }

    fn client() -> UpstreamClient {
        let pool = ConnectionPool::with_proto(vec![], factory::udp_factory(), Default::default(), "udp");
        UpstreamClient::new(pool)
    }

    fn subnet(s: &str) -> ClientSubnet {
        ClientSubnet::from_str(s).unwrap()
    }

    #[test]
    fn test_apply_edns_adds_subnet_option() {
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        assert!(msg.edns.is_none());
        apply_edns(&mut msg, &subnet("203.0.113.0/24"));
        let edns = msg.edns.as_ref().expect("edns set");
        let EdnsOption::Subnet(cs) = edns.option(EdnsCode::Subnet).expect("subnet option") else {
            panic!("expected Subnet option");
        };
        assert_eq!(cs.addr(), IpAddr::from([203, 0, 113, 0]));
        assert_eq!(cs.source_prefix(), 24);
        assert_eq!(cs.scope_prefix(), 0);
    }

    #[test]
    fn test_apply_edns_preserves_existing_options() {
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        let mut edns = Edns::default();
        edns.set_max_payload(1400);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
        apply_edns(&mut msg, &subnet("2001:db8::/32"));
        let edns = msg.edns.as_ref().unwrap();
        assert_eq!(edns.max_payload(), 1400);
        assert!(edns.flags().dnssec_ok);
        let EdnsOption::Subnet(cs) = edns.option(EdnsCode::Subnet).expect("subnet option") else {
            panic!("expected Subnet option");
        };
        assert_eq!(cs.addr(), IpAddr::from_str("2001:db8::").unwrap());
        assert_eq!(cs.source_prefix(), 32);
    }

    #[test]
    fn test_apply_edns_does_not_duplicate() {
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        apply_edns(&mut msg, &subnet("10.0.0.0/8"));
        apply_edns(&mut msg, &subnet("10.0.0.0/8"));
        let edns = msg.edns.as_ref().unwrap();
        assert_eq!(edns.options().get_all(EdnsCode::Subnet).len(), 1);
    }
}
