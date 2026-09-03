//! rsdns server: UDP/TCP/TLS/DoH/DoH3 listeners driving the fixed query pipeline.
//!
//! The pipeline is a fixed sequence of stages (`logs → hosts → groups →
//! cache → rules`); each stage short-circuits with [`Step::Respond`] when a
//! response is ready.  There is **no** upstream pipeline stage: the
//! assembled [`crate::upstream::Upstreams`] is held directly by the `rules`
//! stage (forward / cname).  This module keeps only the wire handling:
//! socket binding, message (de)serialization, and per-query [`QueryContext`]
//! construction/teardown around the pipeline.

use hickory_proto::op::Message;

use bytes::Buf;
use log::{error, info};
use std::io;
use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio_rustls::TlsAcceptor;

use crate::plugins::cache::CacheKey;
use crate::plugins::util::build_servfail;
use crate::plugins::{cache, groups, hosts, logs, rules, speed};
use crate::query::{QueryContext, Step};

const MAX_DNS_SIZE: usize = 4096;

/// The RFC 8484 DNS-over-HTTPS query path.
const DOH_PATH: &str = "/dns-query";
/// `application/dns-message` media type (RFC 8484).
const DNS_MESSAGE: &str = "application/dns-message";

/// All pipeline stages, initialized once at startup.
pub struct Pipeline {
    pub logs: logs::Logs,
    pub hosts: hosts::Hosts,
    pub groups: groups::Groups,
    pub cache: cache::Cache,
    pub rules: rules::Rules,
    pub speed: speed::Speed,
}

pub struct DnsServer {
    pipeline: Arc<Pipeline>,
}

impl DnsServer {
    pub fn new(pipeline: Pipeline) -> Self {
        Self {
            pipeline: Arc::new(pipeline),
        }
    }

    pub async fn serve_udp(&self, socket: UdpSocket, addr: SocketAddr) -> io::Result<()> {
        let socket = Arc::new(socket);
        info!("rsdns listening on UDP {}", addr);

        let mut buf = vec![0u8; MAX_DNS_SIZE];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();

            let socket = socket.clone();
            let self_clone = self.clone_inner();
            tokio::spawn(async move {
                match self_clone.handle_query(&data, src, "udp").await {
                    Ok(response) => {
                        if let Err(e) = socket.send_to(&response, src).await {
                            error!("Failed to send UDP response: {}", e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle query: {}", e);
                    }
                }
            });
        }
    }

    pub async fn serve_tcp(&self, listener: TcpListener, addr: SocketAddr) -> io::Result<()> {
        info!("rsdns listening on TCP {}", addr);

        loop {
            let (mut stream, src) = listener.accept().await?;
            if let Err(e) = stream.set_nodelay(true) {
                error!("TCP accept from {} failed to set TCP_NODELAY: {}", src, e);
                continue;
            }
            let self_clone = self.clone_inner();
            tokio::spawn(async move {
                let mut len_buf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    error!("TCP read len from {}: {}", src, e);
                    return;
                }
                let req_len = u16::from_be_bytes(len_buf) as usize;

                if req_len > MAX_DNS_SIZE {
                    error!("TCP request too large from {}: {}", src, req_len);
                    return;
                }

                let mut data = vec![0u8; req_len];
                if let Err(e) = stream.read_exact(&mut data).await {
                    error!("TCP read data from {}: {}", src, e);
                    return;
                }

                match self_clone.handle_query(&data, src, "tcp").await {
                    Ok(response) => {
                        let len = (response.len() as u16).to_be_bytes();
                        if stream.write_all(&len).await.is_err() {
                            return;
                        }
                        if let Err(e) = stream.write_all(&response).await {
                            error!("Failed to send TCP response to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle TCP query from {}: {}", src, e);
                    }
                }
            });
        }
    }

    /// DNS-over-TLS (RFC 7858): TCP length-prefixed DNS messages over TLS.
    pub async fn serve_dot(
        &self,
        listener: TcpListener,
        tls: Arc<rustls::ServerConfig>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        info!("rsdns listening on DoT {}", addr);
        let acceptor = TlsAcceptor::from(tls);

        loop {
            let (stream, src) = listener.accept().await?;
            let self_clone = self.clone_inner();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("DoT TLS handshake from {} failed: {}", src, e);
                        return;
                    }
                };
                if let Err(e) = stream.get_ref().0.set_nodelay(true) {
                    error!("DoT accept from {} failed to set TCP_NODELAY: {}", src, e);
                }
                let mut len_buf = [0u8; 2];
                if let Err(e) = stream.read_exact(&mut len_buf).await {
                    error!("DoT read len from {}: {}", src, e);
                    return;
                }
                let req_len = u16::from_be_bytes(len_buf) as usize;
                if req_len > MAX_DNS_SIZE {
                    error!("DoT request too large from {}: {}", src, req_len);
                    return;
                }
                let mut data = vec![0u8; req_len];
                if let Err(e) = stream.read_exact(&mut data).await {
                    error!("DoT read data from {}: {}", src, e);
                    return;
                }

                match self_clone.handle_query(&data, src, "tls").await {
                    Ok(response) => {
                        let len = (response.len() as u16).to_be_bytes();
                        if stream.write_all(&len).await.is_err() {
                            return;
                        }
                        if let Err(e) = stream.write_all(&response).await {
                            error!("Failed to send DoT response to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to handle DoT query from {}: {}", src, e);
                    }
                }
            });
        }
    }

    /// DNS-over-HTTPS (RFC 8484): HTTP/1.1 + HTTP/2 on one TLS connection
    /// (hyper auto builder sniffs the HTTP/2 preface).
    pub async fn serve_doh(
        &self,
        listener: TcpListener,
        tls: Arc<rustls::ServerConfig>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        info!("rsdns listening on DoH {}", addr);
        let acceptor = TlsAcceptor::from(tls);

        loop {
            let (stream, src) = listener.accept().await?;
            let self_clone = self.clone_inner();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        error!("DoH TLS handshake from {} failed: {}", src, e);
                        return;
                    }
                };
                let io = TokioIo::new(tls_stream);
                let service = service_fn(move |req| {
                    let server = self_clone.clone_inner();
                    async move { Ok::<_, io::Error>(server.handle_doh_request(req, src, "doh").await) }
                });
                if let Err(e) = AutoBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await
                {
                    error!("DoH connection from {} closed with error: {}", src, e);
                }
            });
        }
    }

    /// DNS-over-HTTP/3 (RFC 8484 over QUIC), reusing hickory's `H3Server`.
    pub async fn serve_doh3(
        &self,
        socket: UdpSocket,
        tls: Arc<rustls::ServerConfig>,
        addr: SocketAddr,
    ) -> io::Result<()> {
        info!("rsdns listening on DoH3 {}", addr);
        let mut server = hickory_net::h3::h3_server::H3Server::with_socket_and_tls_config(socket, tls)
            .map_err(|e| io::Error::other(e.to_string()))?;

        loop {
            let Some((mut conn, src)) = server.accept().await.map_err(|e| io::Error::other(e.to_string()))? else {
                error!("DoH3 accept returned None on {}", addr);
                continue;
            };
            let self_clone = self.clone_inner();
            tokio::spawn(async move {
                while let Some(req) = conn.accept().await {
                    match req {
                        Ok((request, mut stream)) => {
                            // 与 DoH 相同的 RFC 8484 语义，只是 body 来自
                            // HTTP/3 的 RequestStream。
                            let method = request.method().clone();
                            let uri = request.uri().clone();
                            let content_type = request
                                .headers()
                                .get(hyper::header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());

                            let mut body = Vec::new();
                            let mut body_ok = true;
                            loop {
                                match stream.recv_data().await {
                                    Ok(Some(buf)) => {
                                        let mut buf = buf;
                                        body.extend_from_slice(&buf.copy_to_bytes(buf.remaining()));
                                    }
                                    Ok(None) => break,
                                    Err(e) => {
                                        error!("DoH3 read body from {}: {}", src, e);
                                        body_ok = false;
                                        break;
                                    }
                                }
                            }
                            let body = if body_ok { Some(body) } else { None };

                            let response = self_clone
                                .handle_doh_wire(method, uri, content_type, body, src, "doh3")
                                .await;
                            let status = response.status();
                            let content_type = response
                                .headers()
                                .get(hyper::header::CONTENT_TYPE)
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.to_string());
                            let body = response.into_body();
                            let mut h3_resp = hyper::Response::builder().status(status);
                            if let Some(ct) = content_type {
                                h3_resp = h3_resp.header(hyper::header::CONTENT_TYPE, ct);
                            }
                            if let Err(e) = stream.send_response(h3_resp.body(()).unwrap()).await {
                                error!("DoH3 send response headers to {}: {}", src, e);
                                continue;
                            }
                            match body.collect().await {
                                Ok(collected) => {
                                    let bytes = collected.to_bytes();
                                    if !bytes.is_empty() && stream.send_data(bytes).await.is_err() {
                                        continue;
                                    }
                                    if let Err(e) = stream.finish().await {
                                        error!("DoH3 finish stream to {}: {}", src, e);
                                    }
                                }
                                Err(e) => {
                                    error!("DoH3 collect response body for {}: {}", src, e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("DoH3 request from {} failed: {}", src, e);
                        }
                    }
                }
            });
        }
    }

    /// Shared DoH / DoH3 request handling (RFC 8484):
    /// `POST /dns-query` with `Content-Type: application/dns-message`, or
    /// `GET /dns-query?dns=<base64url no padding>`.  Other paths → 404;
    /// wrong content type on POST → 415; missing/invalid query → 400.
    async fn handle_doh_request(
        &self,
        req: hyper::Request<Incoming>,
        src: SocketAddr,
        proto: &'static str,
    ) -> hyper::Response<Full<bytes::Bytes>> {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // POST body 读取失败 → 400。
        let body = if method == Method::POST {
            match req.into_body().collect().await {
                Ok(collected) => Some(collected.to_bytes().to_vec()),
                Err(e) => {
                    error!("DoH read body from {}: {}", src, e);
                    None
                }
            }
        } else {
            None
        };

        self.handle_doh_wire(method, uri, content_type, body, src, proto).await
    }

    /// RFC 8484 request semantics shared by DoH (hyper) and DoH3 (h3).
    /// `body` is the POST body (None when the transport failed to read it).
    async fn handle_doh_wire(
        &self,
        method: Method,
        uri: hyper::Uri,
        content_type: Option<String>,
        body: Option<Vec<u8>>,
        src: SocketAddr,
        proto: &'static str,
    ) -> hyper::Response<Full<bytes::Bytes>> {
        let mut resp = hyper::Response::new(Full::new(bytes::Bytes::new()));
        if uri.path() != DOH_PATH {
            *resp.status_mut() = StatusCode::NOT_FOUND;
            return resp;
        }

        let data: Option<Vec<u8>> = match method {
            Method::POST => {
                match content_type.as_deref() {
                    Some(c) if c.eq_ignore_ascii_case(DNS_MESSAGE) => {}
                    _ => {
                        *resp.status_mut() = StatusCode::UNSUPPORTED_MEDIA_TYPE;
                        return resp;
                    }
                }
                body
            }
            Method::GET => {
                let q = uri
                    .query()
                    .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")).map(percent_decode));
                q.and_then(|v| decode_base64url(&v))
            }
            _ => {
                *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                return resp;
            }
        };

        let Some(data) = data else {
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        };

        match self.handle_query(&data, src, proto).await {
            Ok(response) => {
                resp.headers_mut().insert(
                    hyper::header::CONTENT_TYPE,
                    hyper::header::HeaderValue::from_static(DNS_MESSAGE),
                );
                *resp.body_mut() = Full::new(bytes::Bytes::from(response));
            }
            Err(e) => {
                error!("Failed to handle {} query from {}: {}", proto, src, e);
                *resp.status_mut() = StatusCode::BAD_REQUEST;
            }
        }
        resp
    }

    pub fn clone_inner(&self) -> Self {
        Self {
            pipeline: self.pipeline.clone(),
        }
    }

    /// Flushes pending query log lines (called at shutdown).
    pub async fn flush_logs(&self) {
        self.pipeline.logs.flush().await;
    }

    /// Runs the fixed pipeline: logs → hosts → groups → cache → rules,
    /// then writes the upstream response back to cache and serializes the
    /// response.  Cache hits are always fresh (moka evicts expired entries
    /// on read), so a cache hit short-circuits and a miss continues to the
    /// rules stage.
    async fn handle_query(&self, data: &[u8], client_addr: SocketAddr, proto: &'static str) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        let msg = Message::from_vec(data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let query = msg
            .queries
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no question"))?;

        let mut name = query.name().to_lowercase().to_ascii();
        name.truncate(name.trim_end_matches('.').len());
        let qtype = query.query_type();

        let cache_key = CacheKey::new(name.clone(), qtype);
        let msg_id = msg.id;

        let mut ctx = QueryContext::new(msg, cache_key, client_addr, proto, start, data.len());

        // Fixed pipeline.  Stage order is intentional:
        //   hosts   (static overrides, may short-circuit)
        //   groups  (resolve group, sets skip_cache — never short-circuits)
        //   cache   (cache-first lookup; fresh short-circuits, miss
        //            continues — expired entries are evicted by moka)
        //   rules   (routing rules, terminal: block/cname/forward/nxdomain)
        // Upstream is queried directly by the rules stage via its own
        // `Arc<Upstreams>`.
        let mut step = if self.pipeline.hosts.handle(&mut ctx).is_respond() {
            Step::Respond
        } else {
            self.pipeline.groups.handle(&mut ctx);
            self.pipeline.cache.lookup(&mut ctx).await
        };

        if !step.is_respond() {
            step = self.pipeline.rules.handle(&mut ctx).await;
        }
        let _ = step;

        // Fallback: pipeline exhausted without a response → SERVFAIL.
        if ctx.response.is_none() {
            ctx.response = Some(build_servfail(&ctx.msg));
        }

        // speed 阶段：对 A/AAAA 应答按测速 RTT 排序（后置 pass，不短路）。
        self.pipeline.speed.handle(&mut ctx).await;

        // hosts 别名无 IP 分支：解析目标被改写为原域名，最终应答按客户端
        // 查询名（original_name）呈现 —— 恢复 question 与 answer owner。
        if let Some(original) = ctx.original_name.take() {
            if let Ok(n) = hickory_proto::rr::Name::from_utf8(&original) {
                if let Some(resp) = ctx.response.as_mut() {
                    if let Some(q) = resp.queries.first_mut() {
                        q.set_name(n.clone());
                    }
                    for ans in &mut resp.answers {
                        ans.name = n.clone();
                    }
                }
            }
        }

        if let Some(r) = ctx.response.as_mut() {
            r.metadata.id = msg_id;
        }
        // 回卷：cache 写入（原 TTL）→ 查询日志。
        self.pipeline.cache.write_back(&ctx).await;
        self.pipeline.logs.log_query(&ctx).await;

        ctx.response
            .as_ref()
            .unwrap()
            .to_vec()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// 绑定 UDP socket，若地址为 IPv6 则同时设置双栈（IPV6_V6ONLY=0），
    /// 使一个 socket 可同时处理 IPv4 和 IPv6 流量。
    pub async fn bind_udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        let socket = if addr.is_ipv6() {
            let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            sock.set_only_v6(false)?;
            sock.set_reuse_address(true)?;
            sock.bind(&socket2::SockAddr::from(addr))?;
            sock.set_nonblocking(true)?;
            // SAFETY: sock is a valid fd we just created and configured
            let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(sock.into_raw_fd()) };
            UdpSocket::from_std(std_socket)?
        } else {
            UdpSocket::bind(addr).await?
        };
        Ok(socket)
    }

    /// 绑定 TCP listener，若地址为 IPv6 则设置双栈（IPV6_V6ONLY=0）。
    pub async fn bind_tcp(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        let listener = if addr.is_ipv6() {
            let sock = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
            sock.set_only_v6(false)?;
            sock.set_reuse_address(true)?;
            sock.bind(&socket2::SockAddr::from(addr))?;
            sock.listen(crate::common::bind::DEFAULT_LISTEN_BACKLOG as i32)?;
            sock.set_nonblocking(true)?;
            // SAFETY: sock is a valid fd we just created and configured
            let std_listener = unsafe { std::net::TcpListener::from_raw_fd(sock.into_raw_fd()) };
            TcpListener::from_std(std_listener)?
        } else {
            crate::common::bind::bind_tcp_listener(addr)?
        };
        Ok(listener)
    }
}

/// RFC 4648 base64url without padding (used for the DoH `?dns=` parameter).
///
/// `+` and `/` are already URL-safe here (a raw URI query is percent-encoded
/// by the client; `%XX` escapes are left untouched and rejected by the
/// decoder), so only the alphabet + padding differences from standard base64
/// need handling.
fn decode_base64url(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if s.is_empty() || s.len() % 4 == 1 || !s.bytes().all(|b| TABLE.contains(&b)) {
        return None;
    }
    let mut bits = 0u32;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(s.len() * 3 / 4 + 3);
    for b in s.bytes() {
        let v = TABLE.iter().position(|&t| t == b)? as u32;
        bits = (bits << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    // Leftover bits (nbits == 4 with one '=' pad, or nbits == 2 with two)
    // must be zero per RFC 4648 §3.5.
    if nbits > 0 && (bits & ((1 << nbits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

/// Decodes URI percent-escapes (`%XX`) in a query-string value.  Invalid
/// escapes (not two hex digits) are left as-is, so a malformed `?dns=`
/// value eventually fails base64url decoding → 400.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::tls::{generate_self_signed, load_server_config};
    use crate::config::Config;
    use crate::plugins::util::make_query_msg;
    use crate::plugins::{cache, groups, hosts, logs, rules, speed};
    use crate::upstream;
    use crate::upstream::conn::exchange_from;
    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::xfer::{DnsHandle, FirstAnswer};
    use hickory_proto::op::{DnsRequest, DnsRequestOptions};
    use hickory_proto::rr::RecordType;
    use rustls::pki_types::ServerName;
    use std::io::BufReader;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsConnector;

    fn test_query(name: &str) -> Vec<u8> {
        make_query_msg(name, RecordType::A).unwrap().to_vec().unwrap()
    }

    /// A server whose pipeline answers `test.example` from hosts (no
    /// upstream / network needed).
    async fn test_server() -> Arc<DnsServer> {
        let metrics = crate::metrics::MetricsRegistry::new();
        let config = Config::from_yaml_str("hosts:\n  - \"127.0.0.1 test.example\"\nupstreams: []\n").unwrap();
        let logs = logs::init(&config, &metrics).await.unwrap();
        let hosts = hosts::init(&config, &metrics);
        let groups = groups::init(&config, &metrics);
        let cache = cache::init(&config, &metrics);
        let upstreams = upstream::init(&config, &metrics).await.unwrap();
        let rules = rules::init(&config, &metrics, upstreams);
        let speed = speed::init(&config);
        Arc::new(DnsServer::new(Pipeline {
            logs,
            hosts,
            groups,
            cache,
            rules,
            speed,
        }))
    }

    /// Server TLS config + a client config that trusts the same cert.
    fn test_tls_pair() -> (Arc<rustls::ServerConfig>, rustls::ClientConfig) {
        let (cert, key) = generate_self_signed().unwrap();
        let server_cfg = load_server_config(&cert, &key).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut BufReader::new(&cert[..]))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
        {
            roots.add(c).unwrap();
        }
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (server_cfg, client_cfg)
    }

    #[test]
    fn test_decode_base64url() {
        // "hello" → base64url no padding
        assert_eq!(decode_base64url("aGVsbG8").as_deref(), Some(b"hello".as_slice()));
        // 1-byte input (2 padding chars)
        assert_eq!(decode_base64url("ZA").as_deref(), Some(b"d".as_slice()));
        // 2-byte input (1 padding char)
        assert_eq!(decode_base64url("aGk").as_deref(), Some(b"hi".as_slice()));
        // URL-safe alphabet
        assert_eq!(decode_base64url("_-4").unwrap().len(), 2);
        // invalid: length mod 4 == 1, bad chars
        assert!(decode_base64url("a").is_none());
        assert!(decode_base64url("aGVsbG8!").is_none());
        // standard-base64 '+' is not in the URL-safe alphabet
        assert!(decode_base64url("a+b/").is_none());
        // non-zero trailing bits are rejected
        assert!(decode_base64url("YR").is_none());
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("aGVsbG8"), "aGVsbG8");
        assert_eq!(percent_decode("aGV%2BbG8"), "aGV+bG8");
        // invalid escapes left intact (then fail base64url → 400)
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    /// DoT: TLS handshake, then RFC 1035 length-prefixed DNS roundtrip.
    #[tokio::test]
    async fn test_serve_dot_roundtrip() {
        let server = test_server().await;
        let (tls_config, client_cfg) = test_tls_pair();
        let listener = server.bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let tls = tls_config.clone();
        tokio::spawn(async move {
            srv.serve_dot(listener, tls, addr).await.unwrap();
        });

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();

        let query = test_query("test.example");
        tls.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
        tls.write_all(&query).await.unwrap();
        tls.flush().await.unwrap();

        let mut len_buf = [0u8; 2];
        tls.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        tls.read_exact(&mut resp).await.unwrap();

        let msg = Message::from_vec(&resp).unwrap();
        assert_eq!(msg.answers.len(), 1);
        let a = &msg.answers[0];
        assert_eq!(a.name.to_utf8(), "test.example.");
    }

    /// DoH over HTTP/1.1: hand-crafted POST /dns-query.
    #[tokio::test]
    async fn test_serve_doh_http1() {
        let server = test_server().await;
        let (tls_config, client_cfg) = test_tls_pair();
        let listener = server.bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let tls = tls_config.clone();
        tokio::spawn(async move {
            srv.serve_doh(listener, tls, addr).await.unwrap();
        });

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let stream = TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("127.0.0.1").unwrap(), stream)
            .await
            .unwrap();

        let body = test_query("test.example");
        let head = format!(
            "POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        tls.write_all(head.as_bytes()).await.unwrap();
        tls.write_all(&body).await.unwrap();
        tls.flush().await.unwrap();

        // Read until the end of headers, then the content-length body.
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let header_end = loop {
            let n = tls.read(&mut tmp).await.unwrap();
            assert!(n > 0, "connection closed before headers");
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let headers = String::from_utf8_lossy(&buf[..header_end]).to_string();
        assert!(headers.starts_with("HTTP/1.1 200"), "headers: {headers}");
        let content_length = headers
            .lines()
            .find_map(|l| {
                l.strip_prefix("content-length:")
                    .or_else(|| l.strip_prefix("Content-Length:"))
            })
            .and_then(|v| v.trim().parse::<usize>().ok())
            .expect("content-length header");

        let mut resp = buf[header_end..].to_vec();
        while resp.len() < content_length {
            let n = tls.read(&mut tmp).await.unwrap();
            assert!(n > 0, "connection closed before body");
            resp.extend_from_slice(&tmp[..n]);
        }
        let msg = Message::from_vec(&resp[..content_length]).unwrap();
        assert_eq!(msg.answers.len(), 1);
    }

    /// DoH over HTTP/2: use hickory's h2 DoH client on the same listener.
    #[tokio::test]
    async fn test_serve_doh_http2() {
        let server = test_server().await;
        let (tls_config, client_cfg) = test_tls_pair();
        let listener = server.bind_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = server.clone();
        let tls = tls_config.clone();
        tokio::spawn(async move {
            srv.serve_doh(listener, tls, addr).await.unwrap();
        });

        let stream = hickory_net::h2::HttpsClientStream::builder(Arc::new(client_cfg), TokioRuntimeProvider::default())
            .build(addr, Arc::<str>::from("127.0.0.1"), Arc::<str>::from("/dns-query"))
            .await
            .unwrap();
        let exchange = exchange_from(stream);
        let resp = exchange
            .send(DnsRequest::new(
                make_query_msg("test.example", RecordType::A).unwrap(),
                DnsRequestOptions::default(),
            ))
            .first_answer()
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
    }

    /// DoH3: hickory's H3ClientStream loopback query against serve_doh3.
    #[tokio::test]
    async fn test_serve_doh3_roundtrip() {
        let server = test_server().await;
        let (tls_config, client_cfg) = test_tls_pair();
        let socket = server.bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = socket.local_addr().unwrap();

        let srv = server.clone();
        let tls = tls_config.clone();
        tokio::spawn(async move {
            srv.serve_doh3(socket, tls, addr).await.unwrap();
        });

        let stream = hickory_net::h3::H3ClientStream::builder()
            .crypto_config(client_cfg)
            .build(addr, Arc::<str>::from("127.0.0.1"), Arc::<str>::from("/dns-query"))
            .await
            .unwrap();
        let exchange = exchange_from(stream);
        let resp = exchange
            .send(DnsRequest::new(
                make_query_msg("test.example", RecordType::A).unwrap(),
                DnsRequestOptions::default(),
            ))
            .first_answer()
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
    }

    /// Shared DoH routing: 404 for other paths, 415 for wrong content type,
    /// 400 for bad GET dns parameter.
    #[tokio::test]
    async fn test_doh_routing() {
        let server = test_server().await;
        let src = "127.0.0.1:5353".parse().unwrap();

        let resp = server
            .handle_doh_wire(Method::GET, "/other".parse().unwrap(), None, None, src, "doh")
            .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = server
            .handle_doh_wire(
                Method::POST,
                "/dns-query".parse().unwrap(),
                Some("text/plain".into()),
                Some(test_query("test.example")),
                src,
                "doh",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let resp = server
            .handle_doh_wire(
                Method::GET,
                "/dns-query?dns=!!!not-base64".parse().unwrap(),
                None,
                None,
                src,
                "doh",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // GET with a valid base64url query works.
        use data_encoding::BASE64URL_NOPAD;
        let query = test_query("test.example");
        let encoded = BASE64URL_NOPAD.encode(&query);
        let resp = server
            .handle_doh_wire(
                Method::GET,
                format!("/dns-query?dns={encoded}").parse().unwrap(),
                None,
                None,
                src,
                "doh",
            )
            .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let msg = Message::from_vec(&body).unwrap();
        assert_eq!(msg.answers.len(), 1);
    }
}
