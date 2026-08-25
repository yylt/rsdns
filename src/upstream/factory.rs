//! Protocol-specific connection factories.
//!
//! Each public function returns a [`ConnFactory`] — an `Arc<dyn Fn(SocketAddr) ->
//! Pin<Box<dyn Future<…>>>>>` closure that, given a resolved `SocketAddr`, creates a
//! fresh [`Exchange`] for that protocol.
//!
//! All factories use `.build()` rather than `.exchange()`, giving the connection
//! pool ([`super::pool::ConnectionPool`]) full control over when the background
//! driver task is spawned via [`exchange_from`].
//!
//! ## Protocol notes
//!
//! | Protocol  | hickory-net type          | Wrapping |
//! |-----------|---------------------------|----------|
//! | UDP       | `UdpClientStream`         | none (implements `DnsRequestSender` directly) |
//! | TCP       | `TcpClientStream`         | `DnsMultiplexer` (drives Stream + Send sides) |
//! | TLS (DoT) | `TlsClientStream` (alias) | `DnsMultiplexer` (same as TCP) |
//! | DoH (h2)  | `HttpsClientStream`       | none (HTTP/2 native multiplexing) |
//! | DoH3 (h3) | `H3ClientStream`          | none (QUIC native multiplexing) |
//! | DoQ       | `QuicClientStream`        | none (QUIC native multiplexing) |
//!
//! `DnsMultiplexer` is required for TCP and TLS because the raw client stream is
//! dual-faced: `send_message()` queues requests and returns a response stream,
//! while `poll_next()` drives I/O to actually send queued bytes and dispatch
//! incoming responses to the correct active request.  `DnsExchange` polls that
//! `Stream` side in its background task.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::xfer::dns_multiplexer::DnsMultiplexer;
use rustls::pki_types::ServerName;

use super::conn::{exchange_from, ConnFactory};

/// Per-request DNS timeout used inside the multiplexer / stream.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Protocol factories
// ---------------------------------------------------------------------------

// ── UDP ────────────────────────────────────────────────────────────

pub fn udp_factory() -> ConnFactory {
    Arc::new(|addr: SocketAddr| {
        let fut = async move {
            let stream = hickory_net::udp::UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
            Ok(exchange_from(stream))
        };
        Box::pin(fut)
    })
}

// ── TCP ────────────────────────────────────────────────────────────

pub fn tcp_factory() -> ConnFactory {
    Arc::new(|addr: SocketAddr| {
        let fut = async move {
            let (stream, handle) =
                hickory_net::tcp::TcpClientStream::new(addr, None, Some(DNS_TIMEOUT), TokioRuntimeProvider::default());
            let tcp_stream = stream.await.map_err(|e| io::Error::other(e.to_string()))?;
            let mux = DnsMultiplexer::new(tcp_stream, handle);
            Ok(exchange_from(mux))
        };
        Box::pin(fut)
    })
}

// ── TLS (DNS-over-TLS) ─────────────────────────────────────────────

pub fn tls_factory(server_name: String, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let server_name_str = server_name.clone();
        let client_config = tls_config.clone();
        let fut = async move {
            let sn = ServerName::try_from(server_name_str)
                .map_err(|e| io::Error::other(format!("invalid server name: {}", e)))?;
            let (stream, handle) =
                hickory_net::tls::tls_client_connect(addr, sn, client_config, TokioRuntimeProvider::default());
            let tls_stream = stream.await.map_err(|e| io::Error::other(e.to_string()))?;
            let mux = DnsMultiplexer::new(tls_stream, handle);
            Ok(exchange_from(mux))
        };
        Box::pin(fut)
    })
}

// ── DoH (DNS-over-HTTPS, HTTP/2) ───────────────────────────────────

pub fn doh_factory(host: Arc<str>, path: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let path = path.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let stream = hickory_net::h2::HttpsClientStream::builder(tls_config, TokioRuntimeProvider::default())
                .build(addr, host, path)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(exchange_from(stream))
        };
        Box::pin(fut)
    })
}

// ── DoH3 (DNS-over-HTTP/3) ─────────────────────────────────────────

pub fn doh3_factory(host: Arc<str>, path: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let path = path.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let quic_config = tls_config.as_ref().clone();
            let stream = hickory_net::h3::H3ClientStream::builder()
                .crypto_config(quic_config)
                .build(addr, host, path)
                .await
                .map_err(|e| normalize_h3_error(e.to_string()))?;
            Ok(exchange_from(stream))
        };
        Box::pin(fut)
    })
}

// ── DoQ (DNS-over-QUIC) ────────────────────────────────────────────

pub fn doq_factory(host: Arc<str>, tls_config: Arc<rustls::ClientConfig>) -> ConnFactory {
    Arc::new(move |addr: SocketAddr| {
        let host = host.clone();
        let tls_config = tls_config.clone();
        let fut = async move {
            let quic_config = tls_config.as_ref().clone();
            let stream = hickory_net::quic::QuicClientStream::builder()
                .crypto_config(quic_config)
                .build(addr, host)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;
            Ok(exchange_from(stream))
        };
        Box::pin(fut)
    })
}

fn normalize_h3_error(err: String) -> io::Error {
    if is_h3_cleanup_error(&err) {
        io::Error::new(io::ErrorKind::ConnectionAborted, "h3 connection closed")
    } else {
        io::Error::other(err)
    }
}

fn is_h3_cleanup_error(err: &str) -> bool {
    err.contains("H3_NO_ERROR")
        || err.contains("ApplicationClose")
        || err.contains("connection closed")
        || err.contains("stream closed")
}
