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
use hickory_proto::op::ResponseCode;

use bytes::Buf;
use log::{error, info};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::FromRawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::service::service_fn;
use hyper::{Method, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Sleep};
use tokio_rustls::TlsAcceptor;

use crate::plugins::cache::CacheKey;
use crate::plugins::util::build_servfail;
use crate::plugins::{balance, cache, cloudflare, groups, hosts, logs, rules};
use crate::query::{QueryContext, Step};

const MAX_DNS_SIZE: usize = 4096;
const MAX_REQUEST_SIZE: usize = u16::MAX as usize;
const MAX_CONNECTIONS: usize = 1024;
const MAX_REQUESTS: usize = 1024;
const MAX_STREAMS: usize = 32;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const DOT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub cloudflare: cloudflare::Cloudflare,
    pub balance: balance::Balance,
}

/// End-to-end server metrics, recorded once per inbound query in
/// [`DnsServer::handle_query`].
#[derive(Clone)]
pub struct ServerMetrics {
    queries_total: crate::metrics::Counter,
    parse_errors_total: crate::metrics::Counter,
    rcode_total: crate::metrics::Counter,
    qtype_total: crate::metrics::Counter,
    duration_seconds: crate::metrics::Histogram,
}

impl ServerMetrics {
    pub fn new(registry: &crate::metrics::MetricsRegistry) -> Self {
        Self {
            queries_total: registry.counter("rsdns_queries_total", "Inbound DNS queries", &["proto"]),
            parse_errors_total: registry.counter(
                "rsdns_query_parse_errors_total",
                "Inbound packet parse failures",
                &[],
            ),
            rcode_total: registry.counter("rsdns_query_rcode_total", "Final response rcode distribution", &["rcode"]),
            qtype_total: registry.counter("rsdns_query_qtype_total", "Query type distribution", &["qtype"]),
            duration_seconds: registry.histogram(
                "rsdns_query_duration_seconds",
                "End-to-end query handling latency",
                &["proto"],
                crate::metrics::DEFAULT_BUCKETS,
            ),
        }
    }
}

pub struct DnsServer {
    pipeline: Arc<Pipeline>,
    metrics: ServerMetrics,
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
}

impl DnsServer {
    pub fn new(pipeline: Pipeline, metrics: ServerMetrics) -> Self {
        Self {
            pipeline: Arc::new(pipeline),
            metrics,
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            requests: Arc::new(Semaphore::new(MAX_REQUESTS)),
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
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                continue;
            };
            if let Err(e) = stream.set_nodelay(true) {
                error!("DoT TCP_NODELAY from {}: {}", src, e);
                continue;
            }
            let server = self.clone_inner();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = async {
                    let mut stream = timeout(IO_TIMEOUT, acceptor.accept(stream)).await??;
                    server.handle_dot_stream(&mut stream, src).await
                }
                .await;
                if let Err(e) = result {
                    error!("DoT connection from {}: {}", src, e);
                }
            });
        }
    }

    async fn handle_dot_stream<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        src: SocketAddr,
    ) -> io::Result<()> {
        loop {
            let Some(data) = read_dot_message(stream).await? else {
                return Ok(());
            };
            let _permit = self
                .requests
                .try_acquire()
                .map_err(|_| io::Error::other("inbound request limit reached"))?;
            let response = self.handle_query(&data, src, "tls").await?;
            let len = u16::try_from(response.len()).map_err(|_| io::Error::other("DNS response too large"))?;
            timeout(IO_TIMEOUT, async {
                stream.write_all(&len.to_be_bytes()).await?;
                stream.write_all(&response).await?;
                stream.flush().await
            })
            .await??;
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
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                continue;
            };
            if let Err(e) = stream.set_nodelay(true) {
                error!("DoH TCP_NODELAY from {}: {}", src, e);
                continue;
            }
            let self_clone = self.clone_inner();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let tls_stream = match timeout(IO_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        error!("DoH TLS handshake from {} failed: {}", src, e);
                        return;
                    }
                    Err(e) => {
                        error!("DoH TLS handshake from {} timed out: {}", src, e);
                        return;
                    }
                };
                let io = TokioIo::new(WriteDeadline {
                    inner: tls_stream,
                    deadline: None,
                });
                let streams = Arc::new(Semaphore::new(MAX_STREAMS));
                let service = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let server = self_clone.clone_inner();
                    let permit = streams.clone().try_acquire_owned();
                    async move {
                        let response = match permit {
                            Ok(_permit) => server.handle_doh_request(req, src, "doh").await,
                            Err(_) => http_error(StatusCode::SERVICE_UNAVAILABLE),
                        };
                        Ok::<_, io::Error>(response)
                    }
                });
                let mut builder = AutoBuilder::new(TokioExecutor::new());
                builder.http1().timer(TokioTimer::new()).header_read_timeout(IO_TIMEOUT);
                builder.http2().max_concurrent_streams(MAX_STREAMS as u32);
                if let Err(e) = builder.serve_connection(io, service).await {
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
            let (mut conn, src) = match server.accept().await {
                Ok(Some(connection)) => connection,
                Ok(None) => return Ok(()),
                Err(e) => {
                    error!("DoH3 handshake on {} failed: {}", addr, e);
                    continue;
                }
            };
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                continue;
            };
            let server = self.clone_inner();
            tokio::spawn(async move {
                let _permit = permit;
                let mut tasks = JoinSet::new();
                loop {
                    while tasks.try_join_next().is_some() {}
                    // accept also resolves headers and is not cancellation-safe.
                    // Reap children without dropping/restarting the pending accept.
                    let request = {
                        let accept = conn.accept();
                        tokio::pin!(accept);
                        loop {
                            tokio::select! {
                                request = &mut accept => break request,
                                _ = tasks.join_next(), if !tasks.is_empty() => {}
                            }
                        }
                    };
                    let Some(request) = request else { break };
                    let (request, mut stream) = match request {
                        Ok(request) => request,
                        Err(e) => {
                            error!("DoH3 request from {}: {}", src, e);
                            break;
                        }
                    };
                    if tasks.len() >= MAX_STREAMS {
                        stream.stop_sending(0x10c_u64.into()); // H3_REQUEST_CANCELLED
                        let response = hyper::Response::builder()
                            .status(StatusCode::SERVICE_UNAVAILABLE)
                            .body(())
                            .unwrap();
                        let _ = timeout(IO_TIMEOUT, async {
                            stream.send_response(response).await?;
                            stream.finish().await
                        })
                        .await;
                        continue;
                    }
                    let server = server.clone_inner();
                    tasks.spawn(async move {
                        let (parts, ()) = request.into_parts();
                        let content_type = parts
                            .headers
                            .get(hyper::header::CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let permit = server.requests.try_acquire();
                        let response = if let Some(status) =
                            validate_doh_route(&parts.method, &parts.uri, content_type.as_deref())
                        {
                            http_error(status)
                        } else if permit.is_err() {
                            http_error(StatusCode::SERVICE_UNAVAILABLE)
                        } else {
                            let body = if parts.method == Method::POST {
                                match timeout(IO_TIMEOUT, async {
                                    let mut body = Vec::new();
                                    while let Some(mut chunk) =
                                        stream.recv_data().await.map_err(|_| StatusCode::BAD_REQUEST)?
                                    {
                                        if chunk.remaining() > MAX_REQUEST_SIZE - body.len() {
                                            return Err(StatusCode::PAYLOAD_TOO_LARGE);
                                        }
                                        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                                    }
                                    Ok(body)
                                })
                                .await
                                {
                                    Ok(body) => body,
                                    Err(_) => Err(StatusCode::REQUEST_TIMEOUT),
                                }
                            } else {
                                Ok(Vec::new())
                            };
                            match body {
                                Ok(body) => {
                                    server
                                        .handle_doh_wire(parts.method, parts.uri, content_type, Some(body), src, "doh3")
                                        .await
                                }
                                Err(status) => http_error(status),
                            }
                        };
                        // Stop unused/failed request bodies without preventing a response.
                        stream.stop_sending(0x10c_u64.into());
                        let (parts, body) = response.into_parts();
                        let response = hyper::Response::from_parts(parts, ());
                        let body = body.collect().await.unwrap().to_bytes();
                        let result = timeout(IO_TIMEOUT, async {
                            stream.send_response(response).await?;
                            if !body.is_empty() {
                                stream.send_data(body).await?;
                            }
                            stream.finish().await
                        })
                        .await;
                        if !matches!(result, Ok(Ok(()))) {
                            error!("DoH3 response to {} failed or timed out", src);
                        }
                    });
                }
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
            });
        }
    }

    /// Shared DoH / DoH3 request handling (RFC 8484):
    /// `POST /dns-query` with `Content-Type: application/dns-message`, or
    /// `GET /dns-query?dns=<base64url no padding>`.  Other paths → 404;
    /// wrong content type on POST → 415; missing/invalid query → 400.
    async fn handle_doh_request<B>(
        &self,
        req: hyper::Request<B>,
        src: SocketAddr,
        proto: &'static str,
    ) -> hyper::Response<Full<bytes::Bytes>>
    where
        B: hyper::body::Body + Unpin,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = req.method().clone();
        let uri = req.uri().clone();
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(status) = validate_doh_route(&method, &uri, content_type.as_deref()) {
            return http_error(status);
        }
        let Ok(_permit) = self.requests.try_acquire() else {
            return http_error(StatusCode::SERVICE_UNAVAILABLE);
        };
        let body = if method == Method::POST {
            match timeout(IO_TIMEOUT, Limited::new(req.into_body(), MAX_REQUEST_SIZE).collect()).await {
                Ok(Ok(collected)) => Some(collected.to_bytes().to_vec()),
                Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => {
                    return http_error(StatusCode::PAYLOAD_TOO_LARGE)
                }
                Ok(Err(_)) => return http_error(StatusCode::BAD_REQUEST),
                Err(_) => return http_error(StatusCode::REQUEST_TIMEOUT),
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
        if let Some(status) = validate_doh_route(&method, &uri, content_type.as_deref()) {
            return http_error(status);
        }
        let data = match method {
            Method::POST => body,
            Method::GET => uri
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("dns=")).map(percent_decode))
                .and_then(|v| decode_base64url(&v)),
            _ => unreachable!(),
        };
        let Some(data) = data else {
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return resp;
        };

        if data.len() > MAX_REQUEST_SIZE {
            return http_error(StatusCode::PAYLOAD_TOO_LARGE);
        }

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
            metrics: self.metrics.clone(),
            connections: self.connections.clone(),
            requests: self.requests.clone(),
        }
    }

    /// Flushes pending query log lines (called at shutdown).
    pub async fn flush_logs(&self) {
        self.pipeline.logs.flush().await;
    }

    /// Reopens the query log file (`SIGHUP` / `systemctl reload`), so an
    /// external `logrotate` can rename + create `query.log` without the
    /// process writing into the rotated inode.  Stdout mode is a no-op.
    pub async fn reopen_logs(&self) -> io::Result<()> {
        self.pipeline.logs.reopen().await
    }

    /// Runs the fixed pipeline: logs → hosts → groups → cache → rules,
    /// then writes the upstream response back to cache and serializes the
    /// response.  Cache hits are always fresh (moka evicts expired entries
    /// on read), so a cache hit short-circuits and a miss continues to the
    /// rules stage.
    async fn handle_query(&self, data: &[u8], client_addr: SocketAddr, proto: &'static str) -> io::Result<Vec<u8>> {
        let start = Instant::now();
        self.metrics.queries_total.with_label_values(&[proto]).inc();

        let msg = match Message::from_vec(data) {
            Ok(m) => m,
            Err(e) => {
                self.metrics.parse_errors_total.inc();
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        };

        let query = match msg.queries.first() {
            Some(q) => q,
            None => {
                self.metrics.parse_errors_total.inc();
                return Err(io::Error::new(io::ErrorKind::InvalidData, "no question"));
            }
        };

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

        // Cloudflare always sees the final response, including hosts/cache hits
        // and groups that skip cache or balance. Substituted records are then balanced.
        self.pipeline.cloudflare.handle(&mut ctx).await;

        // balance is a post-pass; only the matched group may bypass it.
        self.pipeline.balance.handle(&mut ctx).await;

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

        // 端到端指标：最终 rcode / 查询类型 / 处理耗时。
        let rcode: ResponseCode = ctx
            .response
            .as_ref()
            .map(|r| r.metadata.response_code)
            .unwrap_or(ResponseCode::ServFail);
        self.metrics
            .rcode_total
            .with_label_values(&[crate::metrics::rcode_label(rcode.into())])
            .inc();
        self.metrics
            .qtype_total
            .with_label_values(&[&format!("{}", qtype)])
            .inc();
        self.metrics
            .duration_seconds
            .with_label_values(&[proto])
            .observe(start.elapsed().as_secs_f64());

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

// A whole write/flush burst has one deadline, even when the peer only
// accepts small fragments. Idle keep-alive time does not start this clock.
struct WriteDeadline<S> {
    inner: S,
    deadline: Option<Pin<Box<Sleep>>>,
}

impl<S: Unpin> WriteDeadline<S> {
    fn poll_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(IO_TIMEOUT)));
        if deadline.as_mut().poll(cx).is_ready() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "DoH write timed out"))
        } else {
            Ok(())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_deadline(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if result.is_ready() {
            self.deadline = None;
        }
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_deadline(cx)?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn read_dot_message<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 2];
    // No bytes is a clean EOF. Once the first byte arrives, the entire
    // remaining header and body share one budget (not one per fragment).
    if timeout(DOT_IDLE_TIMEOUT, stream.read(&mut len[..1])).await?? == 0 {
        return Ok(None);
    }
    timeout(IO_TIMEOUT, async {
        stream.read_exact(&mut len[1..]).await?;
        let mut data = vec![0; u16::from_be_bytes(len) as usize];
        stream.read_exact(&mut data).await?;
        Ok(Some(data))
    })
    .await?
}

fn validate_doh_route(method: &Method, uri: &hyper::Uri, content_type: Option<&str>) -> Option<StatusCode> {
    if uri.path() != DOH_PATH {
        Some(StatusCode::NOT_FOUND)
    } else if method != Method::GET && method != Method::POST {
        Some(StatusCode::METHOD_NOT_ALLOWED)
    } else if method == Method::POST && !content_type.is_some_and(|c| c.eq_ignore_ascii_case(DNS_MESSAGE)) {
        Some(StatusCode::UNSUPPORTED_MEDIA_TYPE)
    } else {
        None
    }
}

fn http_error(status: StatusCode) -> hyper::Response<Full<bytes::Bytes>> {
    let mut response = hyper::Response::new(Full::new(bytes::Bytes::new()));
    *response.status_mut() = status;
    response
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
    use crate::plugins::{balance, cache, cloudflare, groups, hosts, logs, rules};
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
        test_server_config("hosts:\n  - \"127.0.0.1 test.example\"\nupstreams: []\n").await
    }

    async fn test_server_config(yaml: &str) -> Arc<DnsServer> {
        let metrics = crate::metrics::MetricsRegistry::new();
        let config = Config::from_yaml_str(yaml).unwrap();
        let logs = logs::init(&config, &metrics).await.unwrap();
        let hosts = hosts::init(&config, &metrics);
        let groups = groups::init(&config, &metrics);
        let cache = cache::init(&config, &metrics);
        let balance = balance::init(&config);
        let mut cloudflare = cloudflare::init(&config);
        let upstreams = upstream::init(&config, &metrics, &hosts, &balance).await.unwrap();
        cloudflare.attach_upstreams(upstreams.clone());
        let rules = rules::init(&config, &metrics, upstreams).unwrap();
        Arc::new(DnsServer::new(
            Pipeline {
                logs,
                hosts,
                groups,
                cache,
                rules,
                cloudflare,
                balance,
            },
            ServerMetrics::new(&metrics),
        ))
    }

    async fn check_cloudflare_postpass(source: &str, options: &str, expected: &[&str]) {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buf = [0; MAX_DNS_SIZE];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_vec(&buf[..len]).unwrap();
                let is_template = request.queries[0].name().to_utf8() == "template.example.";
                let mut response = crate::plugins::util::build_servfail(&request);
                response.metadata.response_code = ResponseCode::NoError;
                let ips = if is_template {
                    vec!["192.0.2.2", "192.0.2.1"]
                } else {
                    vec!["104.16.0.1"]
                };
                for ip in ips {
                    response.answers.push(Record::from_rdata(
                        request.queries[0].name().clone(),
                        300,
                        RData::A(A(ip.parse().unwrap())),
                    ));
                }
                socket.send_to(&response.to_vec().unwrap(), peer).await.unwrap();
            }
        });
        timeout(IO_TIMEOUT, async {
                let hosts = if source == "hosts" { "hosts:\n  - \"104.16.0.1 test.example\"\n" } else { "" };
                let server = test_server_config(&format!(
                    "{hosts}{options}cloudflare:\n  a: template.example@local\nupstreams:\n  - name: local\n    servers: [{{ address: {addr} }}]\n",
                )).await;
                if source == "cache" {
                    let msg = make_query_msg("test.example", RecordType::A).unwrap();
                    let mut ctx = QueryContext::new(msg.clone(), CacheKey::new("test.example", RecordType::A),
                        "127.0.0.1:1".parse().unwrap(), "udp", Instant::now(), 0);
                    let mut response = crate::plugins::util::build_servfail(&msg);
                    response.metadata.response_code = ResponseCode::NoError;
                    response.answers.push(Record::from_rdata(msg.queries[0].name().clone(), 300,
                        RData::A(A("104.16.0.1".parse().unwrap()))));
                    ctx.response = Some(response);
                    ctx.action = "forward".into();
                    server.pipeline.cache.write_back(&ctx).await;
                }
                for _ in 0..2 {
                    let response = server.handle_query(&test_query("test.example"), "127.0.0.1:1".parse().unwrap(), "udp").await.unwrap();
                    let response = Message::from_vec(&response).unwrap();
                    let ips: Vec<_> = response.answers.iter().map(|r| match &r.data {
                        RData::A(a) => a.0.to_string(),
                        other => panic!("unexpected answer {other:?}"),
                    }).collect();
                    assert_eq!(ips, expected, "{source}: {options}");
                }
        }).await.unwrap();
        responder.abort();
        let _ = responder.await;
    }

    #[tokio::test]
    async fn test_cloudflare_hosts_without_balance() {
        check_cloudflare_postpass("hosts", "", &["192.0.2.2", "192.0.2.1"]).await;
    }

    #[tokio::test]
    async fn test_cloudflare_cache_without_balance() {
        check_cloudflare_postpass("cache", "", &["192.0.2.2", "192.0.2.1"]).await;
    }

    #[tokio::test]
    async fn test_cloudflare_cache_group_skips_balance() {
        check_cloudflare_postpass("cache", "groups:\n  - name: bypass\n    domains: [test.example]\n    skip_balance: true\nbalance:\n  max_answers: 1\n", &["192.0.2.2", "192.0.2.1"]).await;
    }

    #[tokio::test]
    async fn test_cloudflare_cache_before_balance() {
        check_cloudflare_postpass(
            "cache",
            "balance:\n  prefers: [192.0.2.1/32]\n  max_answers: 1\n",
            &["192.0.2.1"],
        )
        .await;
    }

    #[tokio::test]
    async fn test_cloudflare_rules_group_skips_cache() {
        check_cloudflare_postpass("rules", "groups:\n  - name: bypass\n    domains: [test.example]\n    skip_cache: true\n    skip_balance: true\nbalance:\n  max_answers: 1\nrules:\n  - match: '*'\n    action: { type: forward, upstream: local }\n", &["192.0.2.2", "192.0.2.1"]).await;
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

        for _ in 0..2 {
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

        let untrusted = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(timeout(
            IO_TIMEOUT,
            hickory_net::h3::H3ClientStream::builder()
                .crypto_config(untrusted)
                .build(addr, Arc::<str>::from("127.0.0.1"), Arc::<str>::from(DOH_PATH))
        )
        .await
        .unwrap()
        .is_err());

        let stream = hickory_net::h3::H3ClientStream::builder()
            .crypto_config(client_cfg)
            .build(addr, Arc::<str>::from("127.0.0.1"), Arc::<str>::from("/dns-query"))
            .await
            .unwrap();
        let exchange = exchange_from(stream);
        let resp = timeout(
            IO_TIMEOUT,
            exchange
                .send(DnsRequest::new(
                    make_query_msg("test.example", RecordType::A).unwrap(),
                    DnsRequestOptions::default(),
                ))
                .first_answer(),
        )
        .await
        .unwrap()
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
    #[tokio::test]
    async fn test_doh_body_boundaries_and_early_route() {
        let server = test_server().await;
        let src = "127.0.0.1:5353".parse().unwrap();
        for (path, ct, size, status) in [
            (DOH_PATH, DNS_MESSAGE, MAX_REQUEST_SIZE, StatusCode::BAD_REQUEST),
            (DOH_PATH, DNS_MESSAGE, MAX_REQUEST_SIZE + 1, StatusCode::PAYLOAD_TOO_LARGE),
            ("/other", DNS_MESSAGE, MAX_REQUEST_SIZE + 1, StatusCode::NOT_FOUND),
            (DOH_PATH, "text/plain", MAX_REQUEST_SIZE + 1, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ] {
            let request = hyper::Request::post(path)
                .header(hyper::header::CONTENT_TYPE, ct)
                .body(Full::new(bytes::Bytes::from(vec![0; size])))
                .unwrap();
            assert_eq!(server.handle_doh_request(request, src, "doh").await.status(), status);
        }
        let permits = server.requests.acquire_many(MAX_REQUESTS as u32).await.unwrap();
        let request = hyper::Request::get(DOH_PATH)
            .body(Full::new(bytes::Bytes::new()))
            .unwrap();
        assert_eq!(
            server.handle_doh_request(request, src, "doh").await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(permits);
        assert_eq!(server.requests.available_permits(), MAX_REQUESTS);
    }

    #[tokio::test]
    async fn test_dot_frame_eof_and_truncation() {
        let mut empty = &b""[..];
        assert!(read_dot_message(&mut empty).await.unwrap().is_none());
        for frame in [&b"\x00"[..], &b"\x00\x02x"[..]] {
            let mut frame = frame;
            assert_eq!(
                read_dot_message(&mut frame).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
        let mut frame = vec![255, 255];
        frame.resize(MAX_REQUEST_SIZE + 2, 0);
        assert_eq!(
            read_dot_message(&mut frame.as_slice()).await.unwrap().unwrap().len(),
            MAX_REQUEST_SIZE
        );
    }

    #[tokio::test]
    async fn test_dot_request_limit_closes_connection() {
        let server = test_server().await;
        let (mut client, mut stream) = tokio::io::duplex(64);
        let permits = server.requests.acquire_many(MAX_REQUESTS as u32).await.unwrap();
        let srv = server.clone();
        let task =
            tokio::spawn(async move { srv.handle_dot_stream(&mut stream, "127.0.0.1:1".parse().unwrap()).await });
        let query = test_query("test.example");
        client.write_all(&(query.len() as u16).to_be_bytes()).await.unwrap();
        client.write_all(&query).await.unwrap();
        assert!(timeout(IO_TIMEOUT, task).await.unwrap().unwrap().is_err());
        drop(permits);
        assert_eq!(server.requests.available_permits(), MAX_REQUESTS);
    }
    #[tokio::test]
    async fn test_dropped_request_tasks_release_permits() {
        let permits = Arc::new(Semaphore::new(MAX_STREAMS));
        let mut tasks = JoinSet::new();
        for _ in 0..MAX_STREAMS {
            let permit = permits.clone().try_acquire_owned().unwrap();
            tasks.spawn(async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            });
        }
        assert!(permits.try_acquire().is_err());
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        assert_eq!(permits.available_permits(), MAX_STREAMS);
    }
    #[tokio::test]
    async fn test_doh3_slow_query_does_not_block_fast_query() {
        timeout(IO_TIMEOUT, async {
            let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server = test_server_config(&format!(
                "hosts:\n  - \"127.0.0.1 test.example\"\nupstreams:\n  - name: local\n    servers:\n      - address: {}\nrules:\n  - match: \"\"\n    action: {{ type: forward, upstream: local }}\n",
                upstream.local_addr().unwrap()
            )).await;
            let (tls, client) = test_tls_pair();
            let socket = server.bind_udp("127.0.0.1:0".parse().unwrap()).await.unwrap();
            let addr = socket.local_addr().unwrap();
            let srv = server.clone();
            let listener = tokio::spawn(async move { srv.serve_doh3(socket, tls, addr).await });
            let stream = hickory_net::h3::H3ClientStream::builder().crypto_config(client)
                .build(addr, Arc::<str>::from("127.0.0.1"), Arc::<str>::from(DOH_PATH)).await.unwrap();
            let exchange = exchange_from(stream);
            let slow_exchange = exchange.clone();
            let slow = tokio::spawn(async move {
                slow_exchange.send(DnsRequest::new(make_query_msg("slow.example", RecordType::A).unwrap(), DnsRequestOptions::default()))
                    .first_answer().await
            });
            let mut buf = [0; MAX_DNS_SIZE];
            upstream.recv_from(&mut buf).await.unwrap();
            let fast = exchange.send(DnsRequest::new(make_query_msg("test.example", RecordType::A).unwrap(), DnsRequestOptions::default()))
                .first_answer().await.unwrap();
            assert_eq!(fast.answers.len(), 1);
            assert!(!slow.is_finished());
            slow.abort();
            let _ = slow.await;
            listener.abort();
            let _ = listener.await;
        }).await.unwrap();
    }
    #[tokio::test]
    async fn test_doh_write_and_body_deadlines() {
        let server = test_server().await;
        let (tx, rx) = tokio::sync::mpsc::channel::<()>(1);
        let body = http_body_util::StreamBody::new(futures::stream::unfold(rx, |mut rx| async move {
            rx.recv()
                .await
                .map(|_| (Ok::<_, io::Error>(hyper::body::Frame::data(bytes::Bytes::new())), rx))
        }));
        let request = hyper::Request::post(DOH_PATH)
            .header(hyper::header::CONTENT_TYPE, DNS_MESSAGE)
            .body(Box::pin(body))
            .unwrap();
        let (inner, _peer) = tokio::io::duplex(1);
        let mut writer = WriteDeadline { inner, deadline: None };
        let write = async { writer.write_all(&[1, 2]).await.unwrap_err().kind() };
        let (write, response) =
            tokio::join!(write, server.handle_doh_request(request, "127.0.0.1:1".parse().unwrap(), "doh"));
        assert_eq!(write, io::ErrorKind::TimedOut);
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        drop(tx);
        assert_eq!(server.requests.available_permits(), MAX_REQUESTS);
    }
}
