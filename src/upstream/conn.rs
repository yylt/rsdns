//! Connection abstraction layer for rsdns.
//!
//! This module provides the core connection primitives:
//!
//! - [`Exchange`]: a [`DnsExchange`] (hickory-net's cloneable `DnsHandle`)
//!   backed by a spawned [`DnsExchangeBackground`] task.  Multiple callers
//!   multiplex requests over a single TCP/TLS/QUIC stream.
//!
//! - [`ConnFactory`]: a type-erased async factory closure that builds an
//!   [`Exchange`] from a `SocketAddr`.  Each protocol (UDP, TCP, TLS, DoH,
//!   DoH3, DoQ) supplies its own factory in [`super::factory`].
//!
//! - [`build_exchange`]: convenience helper that calls a `ConnFactory` with
//!   a connect timeout.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::{DnsExchange, DnsHandle, DnsRequestSender};
use hickory_proto::op::DnsRequest;

/// A cloneable DNS handle with explicit background-driver liveness.
#[derive(Clone)]
pub struct Exchange {
    inner: DnsExchange<TokioRuntimeProvider>,
    closed: Arc<AtomicBool>,
}

impl Exchange {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl DnsHandle for Exchange {
    type Response = <DnsExchange<TokioRuntimeProvider> as DnsHandle>::Response;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        self.inner.send(request)
    }

    fn is_verifying_dnssec(&self) -> bool {
        self.inner.is_verifying_dnssec()
    }

    fn is_using_edns(&self) -> bool {
        self.inner.is_using_edns()
    }
}

struct DriverLifetime(Arc<AtomicBool>);

impl Drop for DriverLifetime {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Type-erased async factory: given a `SocketAddr`, produces an [`Exchange`].
///
/// Each protocol module (`udp_factory`, `tcp_factory`, …) returns one of
/// these.  The connection pool stores a `ConnFactory` and calls it to
/// create new connections on demand.
pub type ConnFactory =
    Arc<dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = io::Result<Exchange>> + Send>> + Send + Sync>;

/// Wraps a `DnsRequestSender` in a [`DnsExchange`] and spawns its background
/// driver task.
pub fn exchange_from<S: DnsRequestSender>(stream: S) -> Exchange {
    let (inner, bg) = DnsExchange::from_stream(stream);
    let closed = Arc::new(AtomicBool::new(false));
    let lifetime = DriverLifetime(closed.clone());
    tokio::spawn(async move {
        // Mark closed on normal exit, panic, or task cancellation, including
        // cancellation before the driver is polled for the first time.
        let _lifetime = lifetime;
        bg.await
    });
    Exchange { inner, closed }
}

/// Builds an [`Exchange`] by invoking a `ConnFactory` with a connect timeout.
///
/// Returns `io::ErrorKind::TimedOut` if connect exceeds `connect_timeout`,
/// or the factory's own error on failure.
pub async fn build_exchange(
    factory: &ConnFactory,
    addr: SocketAddr,
    connect_timeout: Duration,
) -> io::Result<Exchange> {
    tokio::time::timeout(connect_timeout, factory(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timeout"))?
}
