//! TCP listener binding helpers (moved from the `xray-rs` transport module).

use std::net::SocketAddr;

/// Listen backlog used by all TCP inbound listeners.  tokio's
/// `TcpListener::bind` hard-codes 128 via mio; a larger backlog lets the
/// kernel queue more pending connections under burst load.
pub const DEFAULT_LISTEN_BACKLOG: u32 = 1024;

/// Binds a TCP listener with `SO_REUSEADDR` and [`DEFAULT_LISTEN_BACKLOG`]
/// instead of tokio's hard-coded backlog of 128.
pub fn bind_tcp_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = if addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(DEFAULT_LISTEN_BACKLOG)
}
