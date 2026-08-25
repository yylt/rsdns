//! systemd `sd_notify` support: tell the service manager rsdns is ready.
//!
//! For `Type=notify` systemd services, systemd injects `$NOTIFY_SOCKET`
//! (an AF_UNIX datagram socket address).  Sending `READY=1` there marks the
//! service as started.  Without the variable (plain foreground run) this
//! module is a no-op.
//!
//! The send is a single blocking datagram, called once during startup before
//! entering the event loop, so a plain `std::os::unix::net::UnixDatagram`
//! (not tokio) is fine.

use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr as UnixSocketAddr, UnixDatagram};
use std::path::Path;

/// Sends `READY=1` to systemd via `$NOTIFY_SOCKET`, if set.
///
/// Returns `Ok(())` when no notification is required or the datagram was
/// sent; `Err` when the address is invalid or the send failed (logged as a
/// warning by the caller — never fatal).
pub fn sd_notify_ready() -> Result<(), Box<dyn std::error::Error>> {
    let Some(sock) = std::env::var("NOTIFY_SOCKET").ok().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let addr = parse_socket_addr(&sock)?;
    let socket = UnixDatagram::unbound()?;
    socket.connect_addr(&addr)?;
    socket.send(b"READY=1")?;
    Ok(())
}

/// Resolves `$NOTIFY_SOCKET` to a Unix socket address.
///
/// `@name` → Linux abstract namespace socket; `/path` → filesystem socket;
/// anything else is treated as relative to `/run/systemd/system` (per
/// `sd_notify(3)`).
fn parse_socket_addr(s: &str) -> std::io::Result<UnixSocketAddr> {
    if let Some(name) = s.strip_prefix('@') {
        UnixSocketAddr::from_abstract_name(name)
    } else if s.starts_with('/') {
        UnixSocketAddr::from_pathname(Path::new(s))
    } else {
        UnixSocketAddr::from_pathname(Path::new(&format!("/run/systemd/system/{s}")))
    }
}
