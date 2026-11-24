//! One shared multiplexing Exchange per upstream, with bounded, cancellation-safe
//! checkout and lazy idle replacement. No background pool maintenance is needed.

use parking_lot::Mutex;
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

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

const MAX_IN_FLIGHT: usize = 32;
const FAILURE_THRESHOLD: usize = 3;

struct CachedConn {
    sender: Exchange,
    generation: u64,
    addr_index: usize,
    last_used: Instant,
    in_flight: usize,
    consecutive_failures: usize,
}

#[derive(Default)]
struct AddressState {
    failure_level: u32,
    retry_after: Option<tokio::time::Instant>,
}

impl AddressState {
    fn record_failure(&mut self) {
        self.failure_level = (self.failure_level + 1).min(5);
        self.retry_after = Some(tokio::time::Instant::now() + Duration::from_secs(1 << self.failure_level));
    }
}

#[derive(Default)]
struct PoolState {
    connection: Option<CachedConn>,
    generation: u64,
    addresses: Vec<AddressState>,
}

pub struct CheckoutGuard {
    sender: Exchange,
    pool: Weak<ConnectionPool>,
    generation: u64,
    reported: bool,
    _permit: OwnedSemaphorePermit,
}

impl CheckoutGuard {
    pub fn sender(&self) -> &Exchange {
        &self.sender
    }

    pub fn record_success(mut self) {
        self.report(Some(Ok(())));
    }

    pub fn record_failure(mut self, error: &io::Error) {
        self.report(Some(Err(error)));
    }

    fn report(&mut self, result: Option<Result<(), &io::Error>>) {
        if !self.reported {
            if let Some(pool) = self.pool.upgrade() {
                pool.release(self.generation, result);
            }
            self.reported = true;
        }
    }
}

impl Drop for CheckoutGuard {
    fn drop(&mut self) {
        // Dropping a losing/aborted request is neither success nor failure.
        self.report(None);
    }
}

/// A bounded pool sharing a single long-lived multiplexing connection.
pub struct ConnectionPool {
    state: Mutex<PoolState>,
    /// Only connection establishment holds this lock across await.
    connecting: AsyncMutex<()>,
    permits: Arc<Semaphore>,
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
    pub response_failures_total: crate::metrics::Counter,
}

impl PoolMetrics {
    /// Registers the pool metric families on `registry`.
    pub fn register(registry: &crate::metrics::MetricsRegistry) -> Arc<Self> {
        Arc::new(Self {
            response_failures_total: registry.counter(
                "rsdns_upstream_response_failures_total",
                "Upstream SERVFAIL and REFUSED responses per server attempt",
                &["upstream", "proto", "rcode"],
            ),
            pool_connections: registry.gauge(
                "rsdns_upstream_pool_connections",
                "Cached shared connections per upstream pool",
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
        let state = self.state.lock();
        self.update_connection_gauge(&state);
    }

    fn update_connection_gauge(&self, state: &PoolState) {
        let metrics = self.pool_metrics.lock().clone();
        let identity = self.identity.lock().clone();
        if let (Some(m), Some(name)) = (metrics, identity) {
            m.pool_connections
                .with_label_values(&[&name, self.proto])
                .set(u64::from(state.connection.is_some()));
        }
    }

    fn record_checkout(&self, result: &'static str) {
        let metrics = self.pool_metrics.lock().clone();
        let identity = self.identity.lock().clone();
        if let (Some(m), Some(name)) = (metrics, identity) {
            m.pool_checkout_total.with_label_values(&[&name, result]).inc();
        }
    }

    pub(super) fn record_response_failure(&self, rcode: hickory_proto::op::ResponseCode) {
        let metrics = self.pool_metrics.lock().clone();
        let identity = self.identity.lock().clone();
        if let (Some(metrics), Some(name)) = (metrics, identity) {
            metrics
                .response_failures_total
                .with_label_values(&[&name, self.proto, crate::metrics::rcode_label(rcode.into())])
                .inc();
        }
    }

    /// Creates a pool with an explicit transport-protocol label.
    pub fn with_proto(
        mut addresses: Vec<SocketAddr>,
        factory: ConnFactory,
        config: PoolConfig,
        proto: &'static str,
    ) -> Arc<Self> {
        let mut seen = HashSet::new();
        addresses.retain(|addr| seen.insert(*addr));
        Arc::new(Self {
            state: Mutex::new(PoolState {
                addresses: (0..addresses.len()).map(|_| AddressState::default()).collect(),
                ..PoolState::default()
            }),
            connecting: AsyncMutex::new(()),
            permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
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

    /// Waits for capacity, then clones the cached Exchange or creates one.
    /// The deadline bounds queueing, lock acquisition and connection building.
    /// Cancelling this future releases capacity without penalizing an address.
    pub async fn checkout(self: &Arc<Self>, deadline: tokio::time::Instant) -> io::Result<CheckoutGuard> {
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "checkout deadline"));
        }
        let permit = tokio::time::timeout_at(deadline, self.permits.clone().acquire_owned())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "checkout capacity timeout"))?
            .map_err(|_| io::Error::new(io::ErrorKind::NotConnected, "pool closed"))?;
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "checkout deadline"));
        }
        if let Some((sender, generation)) = self.cached_sender() {
            self.record_checkout("cached");
            return Ok(self.guard(sender, generation, permit));
        }

        let _connecting = tokio::time::timeout_at(deadline, self.connecting.lock())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "checkout connection lock timeout"))?;
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "checkout deadline"));
        }
        // Another checkout may have established a connection while we waited.
        if let Some((sender, generation)) = self.cached_sender() {
            self.record_checkout("cached");
            return Ok(self.guard(sender, generation, permit));
        }

        let mut last_error = io::Error::new(io::ErrorKind::NotConnected, "no available upstream address");
        for _ in 0..self.addresses.len() {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "checkout deadline"));
            }
            let addr_index = self.cursor.fetch_add(1, Ordering::Relaxed) % self.addresses.len();
            if self.state.lock().addresses[addr_index]
                .retry_after
                .is_some_and(|retry| retry > now)
            {
                continue;
            }
            let addr = self.addresses[addr_index];
            let connect_deadline = deadline.min(now + self.config.connect_timeout);
            let result = tokio::time::timeout_at(
                connect_deadline,
                super::conn::build_exchange(&self.factory, addr, self.config.connect_timeout),
            )
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")));
            match result {
                Ok(sender) => {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "checkout deadline"));
                    }
                    let mut state = self.state.lock();
                    state.generation += 1;
                    let generation = state.generation;
                    state.connection = Some(CachedConn {
                        sender: sender.clone(),
                        generation,
                        addr_index,
                        last_used: Instant::now(),
                        in_flight: 1,
                        consecutive_failures: 0,
                    });
                    self.update_connection_gauge(&state);
                    self.record_checkout("created");
                    return Ok(self.guard(sender, generation, permit));
                }
                Err(error) => {
                    self.state.lock().addresses[addr_index].record_failure();
                    log::warn!("upstream {} connect to {} failed: {}", self.proto, addr, error);
                    last_error = error;
                }
            }
        }
        self.record_checkout("failed");
        Err(last_error)
    }

    fn guard(self: &Arc<Self>, sender: Exchange, generation: u64, permit: OwnedSemaphorePermit) -> CheckoutGuard {
        CheckoutGuard {
            sender,
            pool: Arc::downgrade(self),
            generation,
            reported: false,
            _permit: permit,
        }
    }

    fn cached_sender(&self) -> Option<(Exchange, u64)> {
        let mut state = self.state.lock();
        if state.connection.as_ref().is_some_and(|conn| {
            conn.sender.is_closed() || (conn.in_flight == 0 && conn.last_used.elapsed() > self.config.idle_timeout)
        }) {
            let conn = state.connection.take().unwrap();
            if conn.sender.is_closed() {
                state.addresses[conn.addr_index].record_failure();
            }
            self.update_connection_gauge(&state);
        }
        let conn = state.connection.as_mut()?;
        conn.in_flight += 1;
        Some((conn.sender.clone(), conn.generation))
    }

    fn release(&self, generation: u64, result: Option<Result<(), &io::Error>>) {
        let mut state = self.state.lock();
        let Some(conn) = state.connection.as_mut().filter(|conn| conn.generation == generation) else {
            // A late completion must not modify or evict the replacement.
            return;
        };
        conn.in_flight -= 1;
        conn.last_used = Instant::now();
        let addr_index = conn.addr_index;
        let evict = match result {
            None => false,
            Some(Ok(())) => {
                conn.consecutive_failures = 0;
                false
            }
            Some(Err(error))
                if error.kind() == io::ErrorKind::TimedOut
                    || error
                        .get_ref()
                        .is_some_and(|inner| inner.is::<super::ResponseFailure>()) =>
            {
                // Count completion order within this generation. Concurrent
                // successes reset the streak; old generations never contribute.
                conn.consecutive_failures += 1;
                conn.consecutive_failures >= FAILURE_THRESHOLD
            }
            Some(Err(error)) => {
                conn.consecutive_failures = 0;
                matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                        | io::ErrorKind::UnexpectedEof
                )
            }
        };
        if matches!(result, Some(Ok(()))) {
            state.addresses[addr_index] = AddressState::default();
        }
        if evict {
            state.addresses[addr_index].record_failure();
            state.connection = None;
            self.update_connection_gauge(&state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::Context;

    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::xfer::{DnsHandle, FirstAnswer};
    use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};

    fn pending<F: Future>(future: Pin<&mut F>) {
        let mut context = Context::from_waker(futures::task::noop_waker_ref());
        assert!(future.poll(&mut context).is_pending());
    }

    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(2)
    }

    fn expire_backoff(pool: &ConnectionPool) {
        for address in &mut pool.state.lock().addresses {
            address.retry_after = Some(tokio::time::Instant::now());
        }
    }

    fn udp_exchange(addr: SocketAddr) -> Exchange {
        super::super::conn::exchange_from(
            hickory_net::udp::UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build(),
        )
    }

    fn counting_pool(config: PoolConfig) -> (Arc<ConnectionPool>, Arc<AtomicUsize>) {
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let factory: ConnFactory = Arc::new(move |addr| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(udp_exchange(addr)) })
        });
        let pool = ConnectionPool::with_proto(vec!["127.0.0.1:53".parse().unwrap()], factory, config, "udp");
        (pool, count)
    }

    #[tokio::test]
    async fn concurrent_checkout_builds_once_and_cancelled_waits_release_capacity() {
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = calls.clone();
        let gate = Arc::new(Semaphore::new(0));
        let factory_gate = gate.clone();
        let factory: ConnFactory = Arc::new(move |addr| {
            entered.fetch_add(1, Ordering::SeqCst);
            let gate = factory_gate.clone();
            Box::pin(async move {
                gate.acquire().await.unwrap().forget();
                Ok(udp_exchange(addr))
            })
        });
        let pool =
            ConnectionPool::with_proto(vec!["127.0.0.1:53".parse().unwrap()], factory, PoolConfig::default(), "udp");
        let mut first = Box::pin(pool.checkout(deadline()));
        pending(first.as_mut());
        let mut second = Box::pin(pool.checkout(deadline()));
        pending(second.as_mut());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Cancelling the builder and a lock waiter frees both permits and lock.
        drop(first);
        drop(second);
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
        assert_eq!(pool.state.lock().addresses[0].failure_level, 0);
        let mut builder = Box::pin(pool.checkout(deadline()));
        pending(builder.as_mut());
        let mut waiter = Box::pin(pool.checkout(deadline()));
        pending(waiter.as_mut());
        gate.add_permits(1);
        let mut guards = vec![builder.await.unwrap(), waiter.await.unwrap()];
        for _ in 2..MAX_IN_FLIGHT {
            guards.push(pool.checkout(deadline()).await.unwrap());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(pool.permits.available_permits(), 0);
        let queued = pool.checkout(deadline());
        assert!(tokio::time::timeout(Duration::ZERO, queued).await.is_err());
        assert_eq!(pool.permits.available_permits(), 0);
        drop(guards);
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().consecutive_failures, 0);
    }

    #[tokio::test]
    async fn simultaneous_cold_checkouts_share_one_build() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let guards = tokio::time::timeout(
            Duration::from_secs(2),
            futures::future::join_all((0..MAX_IN_FLIGHT).map(|_| pool.checkout(deadline()))),
        )
        .await
        .unwrap();
        assert!(guards.iter().all(Result::is_ok));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().in_flight, MAX_IN_FLIGHT);
    }

    #[tokio::test]
    async fn late_old_failure_does_not_evict_replacement_and_gauge_tracks_cache() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let registry = crate::metrics::MetricsRegistry::default();
        pool.set_pool_identity("test", &PoolMetrics::register(&registry));
        let gauge = "rsdns_upstream_pool_connections{upstream=\"test\",proto=\"udp\"} ";
        assert!(registry.encode_text().contains(&format!("{gauge}0")));
        let first = pool.checkout(deadline()).await.unwrap();
        let old = pool.checkout(deadline()).await.unwrap();
        assert!(registry.encode_text().contains(&format!("{gauge}1")));
        first.record_failure(&io::Error::from(io::ErrorKind::BrokenPipe));
        assert!(registry.encode_text().contains(&format!("{gauge}0")));
        expire_backoff(&pool);
        let replacement = pool.checkout(deadline()).await.unwrap();
        let generation = replacement.generation;
        old.record_failure(&io::Error::from(io::ErrorKind::ConnectionReset));
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().generation, generation);
        assert!(registry.encode_text().contains(&format!("{gauge}1")));
        replacement.record_success();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failure_streak_resets_on_success_request_error_but_not_cancellation() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        let servfail = io::Error::other(super::super::ResponseFailure(ResponseCode::ServFail));
        for error in [&timeout, &servfail] {
            pool.checkout(deadline()).await.unwrap().record_failure(error);
        }
        drop(pool.checkout(deadline()).await.unwrap());
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().consecutive_failures, 2);
        pool.checkout(deadline()).await.unwrap().record_success();
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().consecutive_failures, 0);
        pool.checkout(deadline()).await.unwrap().record_failure(&timeout);
        pool.checkout(deadline())
            .await
            .unwrap()
            .record_failure(&io::Error::other("HTTP status / stream error"));
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().consecutive_failures, 0);
        for _ in 0..FAILURE_THRESHOLD {
            pool.checkout(deadline()).await.unwrap().record_failure(&timeout);
        }
        assert!(pool.state.lock().connection.is_none());
        expire_backoff(&pool);
        pool.checkout(deadline()).await.unwrap().record_success();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn mixed_failures_back_off_once_and_stale_failures_leave_replacement_unchanged() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        let servfail = io::Error::other(super::super::ResponseFailure(ResponseCode::ServFail));
        let refused = io::Error::other(super::super::ResponseFailure(ResponseCode::Refused));
        let old_timeout = pool.checkout(deadline()).await.unwrap();
        let old_response = pool.checkout(deadline()).await.unwrap();
        for (index, error) in [&timeout, &servfail].into_iter().enumerate() {
            pool.checkout(deadline()).await.unwrap().record_failure(error);
            let state = pool.state.lock();
            assert_eq!(state.connection.as_ref().unwrap().consecutive_failures, index + 1);
            assert_eq!(state.addresses[0].failure_level, 0);
            assert!(state.addresses[0].retry_after.is_none());
        }
        drop(pool.checkout(deadline()).await.unwrap());
        pool.checkout(deadline()).await.unwrap().record_failure(&refused);
        assert!(pool.state.lock().connection.is_none());
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        assert!(pool.state.lock().addresses[0].retry_after.is_some());
        assert!(pool.checkout(deadline()).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        expire_backoff(&pool);
        let replacement = pool.checkout(deadline()).await.unwrap();
        let generation = replacement.generation;
        for error in [&servfail, &refused] {
            pool.checkout(deadline()).await.unwrap().record_failure(error);
        }
        old_timeout.record_failure(&timeout);
        old_response.record_failure(&refused);
        {
            let state = pool.state.lock();
            let connection = state.connection.as_ref().unwrap();
            assert_eq!(connection.generation, generation);
            assert_eq!(connection.consecutive_failures, 2);
            assert_eq!(connection.in_flight, 1);
            assert_eq!(state.addresses[0].failure_level, 1);
        }
        replacement.record_success();
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().consecutive_failures, 0);
        assert_eq!(pool.state.lock().addresses[0].failure_level, 0);
        assert!(pool.state.lock().addresses[0].retry_after.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn idle_replacement_never_interrupts_in_flight_requests() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let active = pool.checkout(deadline()).await.unwrap();
        pool.state.lock().connection.as_mut().unwrap().last_used = Instant::now() - Duration::from_secs(60);
        let shared = pool.checkout(deadline()).await.unwrap();
        assert_eq!(shared.generation, active.generation);
        drop(active);
        drop(shared);
        pool.state.lock().connection.as_mut().unwrap().last_used = Instant::now() - Duration::from_secs(60);
        pool.checkout(deadline()).await.unwrap().record_success();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn address_attempts_preserve_order_and_recover_from_failure() {
        let attempted = Arc::new(Mutex::new(Vec::new()));
        let seen = attempted.clone();
        let factory: ConnFactory = Arc::new(move |addr| {
            let mut attempts = seen.lock();
            attempts.push(addr);
            let recover = attempts.len() > 2;
            Box::pin(async move {
                if recover {
                    Ok(udp_exchange(addr))
                } else {
                    Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                }
            })
        });
        let first = "127.0.0.2:53".parse().unwrap();
        let second = "127.0.0.1:53".parse().unwrap();
        let pool = ConnectionPool::with_proto(vec![first, second, first], factory, PoolConfig::default(), "udp");
        assert_eq!(pool.addresses, vec![first, second]);
        assert!(pool.checkout(deadline()).await.is_err());
        assert_eq!(*attempted.lock(), vec![first, second]);
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
        assert!(pool.state.lock().connection.is_none());
        expire_backoff(&pool);
        pool.checkout(deadline()).await.unwrap().record_success();
        assert_eq!(*attempted.lock(), vec![first, second, first]);
    }

    #[tokio::test]
    async fn exited_driver_is_replaced_even_without_a_reported_connection_error() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let pool = ConnectionPool::with_proto(
                vec![listener.local_addr().unwrap()],
                super::super::factory::tcp_factory(Duration::from_secs(1), Duration::from_secs(1)),
                PoolConfig::default(),
                "tcp",
            );
            let old = pool.checkout(deadline()).await.unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
            // Wait for the actual hickory background driver to observe EOF.
            // The enclosing deadline bounds this loop without timing assumptions.
            while !old.sender().is_closed() {
                tokio::task::yield_now().await;
            }
            assert!(pool.checkout(deadline()).await.is_err());
            expire_backoff(&pool);
            let replacement = pool.checkout(deadline()).await.unwrap();
            assert_ne!(old.generation, replacement.generation);
            let (socket, _) = listener.accept().await.unwrap();
            old.record_failure(&io::Error::other("unclassified sender failure"));
            assert!(!replacement.sender().is_closed());
            assert_eq!(
                pool.state.lock().connection.as_ref().unwrap().generation,
                replacement.generation
            );
            replacement.record_success();
            drop(socket);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn backoff_doubles_caps_and_only_dns_success_resets_it() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let error = io::Error::from(io::ErrorKind::ConnectionReset);
        for (index, seconds) in [2, 4, 8, 16, 32, 32].into_iter().enumerate() {
            let guard = pool.checkout(deadline()).await.unwrap();
            // Neither expiry nor connection establishment resets the level.
            assert_eq!(pool.state.lock().addresses[0].failure_level, index.min(5) as u32);
            let before = tokio::time::Instant::now();
            guard.record_failure(&error);
            let after = tokio::time::Instant::now();
            {
                let state = pool.state.lock();
                let address = &state.addresses[0];
                let retry = address.retry_after.unwrap();
                assert!(retry >= before + Duration::from_secs(seconds));
                assert!(retry <= after + Duration::from_secs(seconds));
            }
            // All cooling must return immediately, even with no remaining build.
            assert_eq!(
                pool.checkout(deadline()).await.err().unwrap().kind(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(calls.load(Ordering::SeqCst), index + 1);
            expire_backoff(&pool);
        }
        let guard = pool.checkout(deadline()).await.unwrap();
        assert_eq!(pool.state.lock().addresses[0].failure_level, 5);
        guard.record_success();
        assert_eq!(pool.state.lock().addresses[0].failure_level, 0);
        assert!(pool.state.lock().addresses[0].retry_after.is_none());
        pool.checkout(deadline()).await.unwrap().record_failure(&error);
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
    }

    #[tokio::test]
    async fn late_generation_success_and_concurrent_failures_do_not_change_backoff() {
        let (pool, _) = counting_pool(PoolConfig::default());
        let first = pool.checkout(deadline()).await.unwrap();
        let late_success = pool.checkout(deadline()).await.unwrap();
        let late_failure = pool.checkout(deadline()).await.unwrap();
        let timeout = io::Error::from(io::ErrorKind::TimedOut);
        first.record_failure(&io::Error::from(io::ErrorKind::BrokenPipe));
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        late_success.record_success();
        late_failure.record_failure(&timeout);
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        expire_backoff(&pool);
        let mut guards = Vec::new();
        for _ in 0..MAX_IN_FLIGHT {
            guards.push(pool.checkout(deadline()).await.unwrap());
        }
        for guard in guards {
            guard.record_failure(&timeout);
        }
        // Exactly one penalty at the third timeout, not one per stale guard.
        assert_eq!(pool.state.lock().addresses[0].failure_level, 2);
        assert!(pool.state.lock().connection.is_none());
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
    }

    #[tokio::test]
    async fn capacity_and_connection_lock_timeout_do_not_penalize_ip() {
        let (pool, calls) = counting_pool(PoolConfig::default());
        let held = pool
            .permits
            .clone()
            .acquire_many_owned(MAX_IN_FLIGHT as u32)
            .await
            .unwrap();
        assert_eq!(
            pool.checkout(tokio::time::Instant::now() + Duration::from_millis(1))
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(pool.state.lock().addresses[0].failure_level, 0);
        drop(held);
        let lock = pool.connecting.lock().await;
        assert_eq!(
            pool.checkout(tokio::time::Instant::now() + Duration::from_millis(1))
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(pool.state.lock().addresses[0].failure_level, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
        drop(lock);
    }

    #[tokio::test]
    async fn build_deadline_is_observable_and_connect_timeout_can_try_next_ip() {
        let first: SocketAddr = "127.0.0.1:53".parse().unwrap();
        let second: SocketAddr = "127.0.0.2:53".parse().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let attempted = calls.clone();
        let factory: ConnFactory = Arc::new(move |addr| {
            attempted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if addr == first {
                    futures::future::pending::<()>().await;
                }
                Ok(udp_exchange(addr))
            })
        });
        let pool = ConnectionPool::with_proto(
            vec![first, second],
            factory.clone(),
            PoolConfig {
                connect_timeout: Duration::from_millis(1),
                ..PoolConfig::default()
            },
            "udp",
        );
        let guard = pool.checkout(deadline()).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(pool.state.lock().connection.as_ref().unwrap().addr_index, 1);
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        guard.record_success();
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        assert_eq!(pool.state.lock().addresses[1].failure_level, 0);

        let pool = ConnectionPool::with_proto(vec![first, second], factory, PoolConfig::default(), "udp");
        assert_eq!(
            pool.checkout(tokio::time::Instant::now() + Duration::from_millis(1))
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(pool.state.lock().addresses[0].failure_level, 1);
        assert_eq!(pool.state.lock().addresses[1].failure_level, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(pool.permits.available_permits(), MAX_IN_FLIGHT);
    }

    #[tokio::test]
    async fn shared_udp_exchange_keeps_requests_independent() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let pool = ConnectionPool::with_proto(
                vec![addr],
                super::super::factory::udp_factory(),
                PoolConfig::default(),
                "udp",
            );
            let server = async {
                let mut received = Vec::new();
                let mut buf = [0; 4096];
                for _ in 0..2 {
                    let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                    received.push((Message::from_vec(&buf[..len]).unwrap(), peer));
                }
                // Respond in reverse order, after both requests have arrived.
                for (message, peer) in received.into_iter().rev() {
                    socket
                        .send_to(&message.into_response().to_vec().unwrap(), peer)
                        .await
                        .unwrap();
                }
            };
            let query = |name: &'static str| {
                let pool = pool.clone();
                async move {
                    let guard = pool.checkout(deadline()).await.unwrap();
                    let mut message = Message::query();
                    let query = Query::query(Name::from_ascii(name).unwrap(), RecordType::A);
                    message.add_query(query.clone());
                    let answer = guard
                        .sender()
                        .send(DnsRequest::new(message, DnsRequestOptions::default()))
                        .first_answer()
                        .await
                        .unwrap()
                        .into_message();
                    assert_eq!(answer.queries, vec![query]);
                    guard.record_success();
                }
            };
            tokio::join!(server, query("one.example."), query("two.example."));
            assert_eq!(pool.state.lock().connection.as_ref().unwrap().in_flight, 0);
        })
        .await
        .unwrap();
    }
}
