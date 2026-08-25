//! rsdns server: UDP/TCP listeners driving the fixed query pipeline.
//!
//! The pipeline is a fixed sequence of stages (`logs → hosts → groups →
//! cache → rules`); each stage short-circuits with [`Step::Respond`] when a
//! response is ready.  There is **no** upstream pipeline stage: the
//! assembled [`crate::upstream::Upstreams`] is held directly by the `rules`
//! stage (forward / cname).  This module keeps only the wire handling:
//! socket binding, message (de)serialization, and per-query [`QueryContext`]
//! construction/teardown around the pipeline.

use hickory_proto::op::Message;

use log::{error, info};
use std::io;
use std::net::SocketAddr;
use std::os::fd::IntoRawFd;
use std::os::unix::io::FromRawFd;
use std::sync::Arc;
use std::time::Instant;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::plugins::cache::CacheKey;
use crate::plugins::util::build_servfail;
use crate::plugins::{cache, groups, hosts, logs, rules, speed};
use crate::query::{QueryContext, Step};

const MAX_DNS_SIZE: usize = 4096;

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
