//! Minimal connection pool: an idle cache of long-lived DNS connections.
//!
//! Each [`Exchange`] (`DnsExchange`) is a cloneable multiplexing handle — a
//! single connection carries any number of concurrent queries — so the pool
//! does not manage capacity or sharing.  It only:
//!
//! - **Caches** idle connections to avoid re-paying the TCP/TLS/QUIC
//!   handshake on every query (UDP benefits little; connections are cheap).
//! - **Lazily creates** a connection on checkout when the cache is empty,
//!   rotating through the resolved upstream addresses.
//! - **Discards on failure**: a failed query is never returned to the cache;
//!   the next checkout simply creates a fresh connection (dead connections
//!   fail fast, so this self-heals without health checks).
//! - **Expires idle connections** older than `idle_timeout` on checkout.
//!
//! There is no background task: an `Exchange` whose clones are all dropped
//! shuts itself down, so nothing leaks.

use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use super::conn::{ConnFactory, Exchange};

/// Address family preference used when bootstrap-resolving domain upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferFamily {
    Any,
    Ipv4,
    Ipv6,
}

/// Tunable parameters for the connection pool.
///
/// All fields have sensible defaults (see [`Default`] impl).  Users
/// override them in rsdns.yaml via `pool:` blocks.
pub struct PoolConfig {
    /// Connections unused longer than this are dropped on next checkout.
    pub idle_timeout: Duration,
    /// Timeout for transport-level connection establishment.
    pub connect_timeout: Duration,
    /// Per-request DNS timeout applied by `UpstreamClient::query()`.
    pub dns_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            dns_timeout: Duration::from_secs(5),
        }
    }
}

/// A single idle connection held by the pool.
struct CachedConn {
    sender: Exchange,
    /// When this connection was last checked out / returned.
    last_used: Instant,
}

impl CachedConn {
    fn is_expired(&self, idle_timeout: Duration) -> bool {
        self.last_used.elapsed() > idle_timeout
    }
}

pub struct CheckoutGuard {
    sender: Option<Exchange>,
    pool: Weak<ConnectionPool>,
    reported: bool,
}

impl CheckoutGuard {
    pub fn sender(&self) -> &Exchange {
        self.sender.as_ref().expect("sender already returned")
    }

    pub fn record_success(mut self) {
        self.report(true);
    }

    pub fn record_failure(mut self) {
        self.report(false);
    }

    fn report(&mut self, success: bool) {
        if self.reported {
            return;
        }
        if let (Some(sender), Some(pool)) = (self.sender.take(), self.pool.upgrade()) {
            pool.release(sender, success);
        }
        self.reported = true;
    }
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        self.report(true);
    }
}

/// Manages a cache of long-lived DNS connections.
pub struct ConnectionPool {
    /// Idle connections, most-recently-used first.  Protected by a
    /// `parking_lot::Mutex` — lock is held only for push/pop, never across
    /// `.await`.
    cache: Mutex<VecDeque<CachedConn>>,
    /// Resolved upstream addresses; rotated through round-robin when a new
    /// connection must be created.
    addresses: Vec<SocketAddr>,
    /// Protocol-specific factory closure (from [`crate::factory`]).
    factory: ConnFactory,
    /// Transport protocol label: "udp"/"tcp"/"tls"/"doh"/"doh3"/"doq".
    proto: &'static str,
    /// Copy of the pool configuration (timeouts).
    config: PoolConfig,
    /// Round-robin cursor for address selection.
    cursor: AtomicUsize,
    /// Metric hooks (registered by the upstream plugin; optional).
    pool_metrics: parking_lot::Mutex<Option<Arc<PoolMetrics>>>,
    /// Upstream pool name this pool belongs to (for metric labels).
    identity: parking_lot::Mutex<Option<String>>,
}

/// Pool-level metrics, registered by the upstream plugin.
#[derive(Clone)]
pub struct PoolMetrics {
    pub pool_connections: crate::metrics::Gauge,
    pub pool_checkout_total: crate::metrics::Counter,
}

impl PoolMetrics {
    /// Registers the pool metric families on `registry`.
    pub fn register(registry: &crate::metrics::MetricsRegistry) -> Arc<Self> {
        Arc::new(Self {
            pool_connections: registry.gauge(
                "rsdns_upstream_pool_connections",
                "Idle connections per upstream pool",
                &["upstream", "proto"],
            ),
            pool_checkout_total: registry.counter(
                "rsdns_upstream_pool_checkout_total",
                "Pool checkouts",
                &["upstream", "result"],
            ),
        })
    }
}

impl ConnectionPool {
    /// Associates this pool with a named upstream (for metric labels).
    pub fn set_pool_identity(&self, name: &str, metrics: &Arc<PoolMetrics>) {
        *self.identity.lock() = Some(name.to_string());
        *self.pool_metrics.lock() = Some(metrics.clone());
        self.update_connection_gauge();
    }

    fn update_connection_gauge(&self) {
        let metrics = self.pool_metrics.lock().clone();
        let identity = self.identity.lock().clone();
        if let (Some(m), Some(name)) = (metrics, identity) {
            m.pool_connections
                .with_label_values(&[&name, self.proto])
                .set(self.cache.lock().len() as u64);
        }
    }

    fn record_checkout(&self, result: &'static str) {
        let metrics = self.pool_metrics.lock().clone();
        let identity = self.identity.lock().clone();
        if let (Some(m), Some(name)) = (metrics, identity) {
            m.pool_checkout_total.with_label_values(&[&name, result]).inc();
        }
    }

    /// Creates a pool with an explicit transport-protocol label.
    pub fn with_proto(
        mut addresses: Vec<SocketAddr>,
        factory: ConnFactory,
        config: PoolConfig,
        proto: &'static str,
    ) -> Arc<Self> {
        addresses.sort_unstable();
        addresses.dedup();
        Arc::new(Self {
            cache: Mutex::new(VecDeque::new()),
            addresses,
            factory,
            proto,
            config,
            cursor: AtomicUsize::new(0),
            pool_metrics: parking_lot::Mutex::new(None),
            identity: parking_lot::Mutex::new(None),
        })
    }

    /// Transport protocol label.
    pub fn proto(&self) -> &'static str {
        self.proto
    }

    /// Per-request DNS timeout.
    pub fn dns_timeout(&self) -> Duration {
        self.config.dns_timeout
    }

    /// Picks the next address round-robin.
    fn next_addr(&self) -> Option<SocketAddr> {
        let n = self.addresses.len();
        if n == 0 {
            return None;
        }
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        Some(self.addresses[idx])
    }

    /// Returns an [`Exchange`] for querying the upstream.
    ///
    /// Reuses the most recently returned idle connection (dropping it if it
    /// expired); otherwise creates a fresh connection, trying each address
    /// round-robin until one connects.  Returns `None` only when no address
    /// is available or all addresses fail to connect.
    pub async fn checkout(self: &Arc<Self>) -> Option<CheckoutGuard> {
        // Prefer a fresh idle connection.
        {
            let mut cache = self.cache.lock();
            while let Some(conn) = cache.pop_front() {
                if conn.is_expired(self.config.idle_timeout) {
                    continue;
                }
                let guard = CheckoutGuard {
                    sender: Some(conn.sender),
                    pool: Arc::downgrade(self),
                    reported: false,
                };
                self.record_checkout("cached");
                return Some(guard);
            }
        }

        // Cache empty / all expired — build a new connection.
        let max_attempts = self.addresses.len().max(1);
        for _ in 0..max_attempts {
            let addr = self.next_addr()?;
            match super::conn::build_exchange(&self.factory, addr, self.config.connect_timeout).await {
                Ok(sender) => {
                    let guard = CheckoutGuard {
                        sender: Some(sender),
                        pool: Arc::downgrade(self),
                        reported: false,
                    };
                    self.record_checkout("created");
                    return Some(guard);
                }
                Err(_) => continue, // try the next address
            }
        }
        None
    }

    /// Returns a connection to the cache on success; discards it on failure.
    fn release(&self, sender: Exchange, success: bool) {
        if !success {
            return;
        }
        self.cache.lock().push_front(CachedConn {
            sender,
            last_used: Instant::now(),
        });
        self.update_connection_gauge();
    }
}
