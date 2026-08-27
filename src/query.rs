//! Per-query context threaded through the fixed rsdns pipeline.
//!
//! The pipeline is a fixed sequence of stages (see `server.rs`):
//!
//! ```text
//! logs → hosts → groups → cache → rules
//! ```
//!
//! `upstream` is **not** a pipeline stage: it is assembled at startup into
//! [`crate::upstream::Upstreams`] and held directly by the `rules` stage
//! (forward / cname) — no per-query injection is needed.
//!
//! Each stage reads and mutates the shared [`QueryContext`], and either
//! short-circuits with [`Step::Respond`] (a response is ready in
//! `ctx.response`) or continues with [`Step::Continue`].

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::net::SocketAddr;
use std::time::{Instant, SystemTime};

use super::plugins::cache::CacheKey;

/// What a pipeline stage wants the caller to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Continue to the next stage.
    Continue,
    /// `ctx.response` is ready; stop the pipeline.
    Respond,
}

impl Step {
    pub fn is_respond(self) -> bool {
        matches!(self, Step::Respond)
    }
}

/// Per-query context threaded through the whole pipeline.
pub struct QueryContext {
    /// The original query message.
    pub msg: Message,
    /// Cache key derived from the question (lowercased name + qtype).
    pub key: CacheKey,
    /// Client address.
    pub client: SocketAddr,
    /// "udp" or "tcp".
    pub proto: &'static str,
    /// When the query was received (monotonic, for `{duration}`).
    pub start: Instant,
    /// When the query was received, wall-clock — aligned with system time
    /// (for the `{time}` log placeholder).
    pub start_time: SystemTime,
    /// Size of the original request in bytes (for query logging).
    pub size: usize,

    // Control bits — stages may flip these.
    /// When set, the `logs` stage does not print this query.
    pub skip_log: bool,
    /// When set, the `cache` stage skips both lookup and write-back.
    pub skip_cache: bool,
    /// When set, the `speed` stage skips latency-ordered answer sorting
    /// (set by the groups stage for groups with `skip_speed: true`).
    pub skip_speed: bool,

    // State filled in by stages along the pipeline.
    /// Set by a responding stage (hosts / cache / rules).
    pub response: Option<Message>,
    /// Human-readable action label for logging/metrics (e.g. "hosts",
    /// "forward(default)", "block-nxdomain").
    pub action: String,
    /// Domain group the queried name belongs to (set by the groups stage).
    pub group: Option<String>,
    /// Placeholder captures from the matched rule target (e.g. `{1}` in
    /// `match: "{1}.example.com"`); index = placeholder number - 1.  Set by
    /// the rules stage; reused by actions (e.g. `cname.target`).
    pub captures: Vec<String>,
    /// The client-queried name before a hosts alias rewrite.  Set by the
    /// hosts stage when an alias without an IP mapping rewrites the query
    /// target to the original domain; the server restores the queried name
    /// on the final answer (question + answer owners).
    pub original_name: Option<String>,
}

impl QueryContext {
    pub fn new(
        msg: Message,
        key: CacheKey,
        client: SocketAddr,
        proto: &'static str,
        start: Instant,
        size: usize,
    ) -> Self {
        Self {
            msg,
            key,
            client,
            proto,
            start,
            start_time: SystemTime::now(),
            size,
            skip_log: false,
            skip_cache: false,
            skip_speed: false,
            response: None,
            action: String::new(),
            group: None,
            captures: Vec::new(),
            original_name: None,
        }
    }

    /// Convenience: the lowercase query name without trailing dot.
    pub fn name(&self) -> &str {
        &self.key.name
    }

    pub fn qtype(&self) -> RecordType {
        self.key.qtype
    }

    /// Rewrites the query target to `name` (hosts alias: alias → original
    /// domain).  Updates both the cache key and the message question so the
    /// remaining pipeline stages (groups / cache / rules / upstream) all
    /// operate on the new target.
    pub fn rewrite_name(&mut self, name: &str) {
        self.key.name = name.to_string();
        if let Ok(n) = hickory_proto::rr::Name::from_utf8(name) {
            if let Some(q) = self.msg.queries.first_mut() {
                q.set_name(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::RecordType;
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::time::Instant;

    fn ctx(name: &str) -> QueryContext {
        let msg = make_query_msg(name, RecordType::A).unwrap();
        QueryContext::new(
            msg,
            CacheKey::new(name, RecordType::A),
            SocketAddr::from_str("127.0.0.1:5353").unwrap(),
            "udp",
            Instant::now(),
            0,
        )
    }

    #[test]
    fn test_rewrite_name_updates_key_and_question() {
        let mut c = ctx("cdn1.example.com");
        c.rewrite_name("edge.example.com");
        assert_eq!(c.key.name, "edge.example.com");
        assert_eq!(c.name(), "edge.example.com");
        let q = c.msg.queries.first().unwrap();
        assert_eq!(q.name().to_utf8(), "edge.example.com");
    }
}
