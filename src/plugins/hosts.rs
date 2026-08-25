//! `hosts` stage — static host overrides.
//!
//! Looks up the queried name in the hosts trie; on hit, builds a response
//! and short-circuits the pipeline (`Step::Respond`), mirroring the old
//! `hosts`-first behaviour.
//!
//! Two line formats are supported:
//! - `IP domain [domain...]` — the classic static IP mapping;
//! - `original_domain alias1 alias2 ...` — aliases: querying an alias looks
//!   up the original domain's IP and answers under the **queried** name.
//!   When the original domain has no IP mapping, the query target is
//!   rewritten to the original domain and the pipeline continues (the
//!   server restores the queried name on the final answer).
//!
//! Inline entries build the trie at startup; `file://` entries are loaded
//! at startup and watched with the `notify` library, rebuilding the trie
//! and atomically swapping it on change.

use ahash::AHashMap;
use log::{error, info, warn};
use notify::{RecursiveMode, Watcher};
use parking_lot::RwLock;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use crate::common::domain_trie::{DomainSuffixTrie, DomainSuffixTrieBuilder};

use crate::config::Config;
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::plugins::util::{build_hosts_response, build_servfail, is_change_event};
use crate::query::{QueryContext, Step};

/// Result of a hosts trie lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// Direct hit on an IP mapping (the tag is an IP-list index).
    Ips(&'a [IpAddr]),
    /// Alias hit: the tag is the original domain, which must be looked up
    /// again to obtain the IPs (or trigger a rewrite when absent).
    Alias(&'a str),
    Miss,
}

pub struct HostsTrie {
    trie: DomainSuffixTrie,
    ips: Vec<Vec<IpAddr>>,
}

impl HostsTrie {
    /// Tags are either IP-list indices ("0", "1", …) or, for alias lines,
    /// the original domain name itself.  A numeric tag that has no matching
    /// IP list (should not happen after construction) is treated as a miss.
    pub fn lookup(&self, domain: &str) -> Lookup<'_> {
        match self.trie.lookup(domain) {
            Some(tag) => match tag.parse::<usize>() {
                Ok(idx) => self
                    .ips
                    .get(idx)
                    .map(|v| Lookup::Ips(v.as_slice()))
                    .unwrap_or(Lookup::Miss),
                Err(_) => Lookup::Alias(tag),
            },
            None => Lookup::Miss,
        }
    }
}

pub struct HostsTrieBuilder {
    builder: DomainSuffixTrieBuilder,
    ips: Vec<Vec<IpAddr>>,
    domain_to_idx: AHashMap<String, usize>,
}

impl HostsTrieBuilder {
    pub fn new() -> Self {
        Self {
            builder: DomainSuffixTrieBuilder::new(),
            ips: Vec::new(),
            domain_to_idx: AHashMap::new(),
        }
    }

    pub fn insert(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.trim_start_matches("*.");
        let idx = *self.domain_to_idx.entry(domain.to_string()).or_insert_with(|| {
            let idx = self.ips.len();
            self.ips.push(Vec::new());
            self.builder.insert(domain, &idx.to_string());
            idx
        });
        if let Some(entries) = self.ips.get_mut(idx) {
            entries.push(ip);
        }
    }

    /// Alias entry: `alias → original`.  The tag is the original domain
    /// (distinct from the numeric IP-list index tags).
    pub fn insert_alias(&mut self, alias: &str, original: &str) {
        self.builder.insert(alias, original);
    }

    pub fn build(self) -> HostsTrie {
        HostsTrie {
            trie: self.builder.build().expect("FST build failed"),
            ips: self.ips,
        }
    }
}

impl Default for HostsTrieBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 解析一行 hosts 条目。返回 `true` 表示该行已被消费（空行 / 注释 / IP 行）；
/// 返回 `false` 表示不是 IP 行，应交给 [`parse_alias_line`] 尝试别名解析。
fn parse_hosts_line(builder: &mut HostsTrieBuilder, line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return true;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }
    if let Ok(ip) = parts[0].parse::<IpAddr>() {
        for domain in &parts[1..] {
            builder.insert(domain, ip);
        }
        return true;
    }
    false
}

/// 解析一行别名：`original_domain alias1 alias2 ...`。
///
/// 首个 token 为原始域名，其余为代替域名（别名）。原域名是 IP 或纯数字串时
/// 跳过（IP 行交给 [`parse_hosts_line`]；纯数字串会与 IP 索引 tag 的 usize
/// 解析歧义）。自引用别名忽略。
fn parse_alias_line(builder: &mut HostsTrieBuilder, line: &str) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let original = parts[0];
    if original.parse::<IpAddr>().is_ok() || original.parse::<usize>().is_ok() {
        return;
    }
    for alias in &parts[1..] {
        if alias == &original {
            continue;
        }
        builder.insert_alias(alias, original);
    }
}

/// 从内联条目 + 文件内容构建 hosts trie。文件读取失败视为空内容。
fn build_hosts_trie(entries: &[String]) -> HostsTrie {
    let mut builder = HostsTrieBuilder::new();
    for entry in entries {
        if let Some(file_path) = entry.strip_prefix("file://").or_else(|| entry.strip_prefix("file:")) {
            match std::fs::read_to_string(file_path) {
                Ok(content) => {
                    for line in content.lines() {
                        parse_entry_line(&mut builder, line);
                    }
                    info!("Loaded hosts from {}", file_path);
                }
                Err(e) => error!("Failed to load hosts {}: {}", file_path, e),
            }
        } else {
            parse_entry_line(&mut builder, entry);
        }
    }
    builder.build()
}

/// 解析单行 hosts 内容：先试 IP 行，再试别名行。
fn parse_entry_line(builder: &mut HostsTrieBuilder, line: &str) {
    if !parse_hosts_line(builder, line) {
        parse_alias_line(builder, line);
    }
}

struct HostsMetrics {
    lookup_total: Counter,
    hit_total: Counter,
    entries: Gauge,
}

impl HostsMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: registry.counter("rsdns_hosts_lookup_total", "Hosts trie lookups", &[]),
            hit_total: registry.counter("rsdns_hosts_hit_total", "Hosts trie hits", &[]),
            entries: registry.gauge("rsdns_hosts_entries", "Loaded hosts entries", &[]),
        }
    }
}

/// The hosts stage.
pub struct Hosts {
    trie: Arc<RwLock<Arc<HostsTrie>>>,
    metrics: Arc<HostsMetrics>,
}

/// Builds the hosts stage from the `hosts:` config section (or none),
/// spawning a notify watcher per `file://` entry.
pub fn init(config: &Config, registry: &MetricsRegistry) -> Hosts {
    let raw = config.plugin_sections.get("hosts").cloned().unwrap_or_default();
    let entries: Vec<String> = if raw.is_null() {
        Vec::new()
    } else {
        serde_yaml::from_value(raw).unwrap_or_default()
    };
    let trie = Arc::new(build_hosts_trie(&entries));
    let metrics = Arc::new(HostsMetrics::new(registry));
    metrics.entries.set(trie.ips.len() as u64);
    let current = Arc::new(RwLock::new(trie));

    // 为每个 file 源 spawn notify watcher：变化时重建 trie 并原子替换。
    for entry in &entries {
        let file_path = entry.strip_prefix("file://").or_else(|| entry.strip_prefix("file:"));
        let Some(file_path) = file_path else { continue };
        let path = PathBuf::from(file_path);
        let cb_entries = entries.clone();
        let cb_current = current.clone();
        let cb_metrics = metrics.clone();
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !is_change_event(&event.kind) || event.flag().is_some() {
                return;
            }
            let new_trie = build_hosts_trie(&cb_entries);
            cb_metrics.entries.set(new_trie.ips.len() as u64);
            *cb_current.write() = Arc::new(new_trie);
        }) {
            Ok(mut watcher) => {
                if let Err(e) = watcher.watch(&path, RecursiveMode::NonRecursive) {
                    warn!("hosts: failed to watch {}: {}", path.display(), e);
                } else {
                    // 持有 watcher 直到进程退出，保持文件监控存活。
                    tokio::spawn(async move {
                        std::future::pending::<()>().await;
                        drop(watcher);
                    });
                }
            }
            Err(e) => {
                warn!("hosts: failed to watch {}: {}", path.display(), e);
            }
        }
    }

    Hosts { trie: current, metrics }
}

impl Hosts {
    /// Static mapping hit → `Respond`; miss → `Continue`.
    ///
    /// Alias lookup: when the original domain has an IP mapping, answer
    /// under the **queried** name with those IPs (`Respond`); otherwise
    /// rewrite the query target to the original domain and continue the
    /// pipeline (`Continue` — the server restores the queried name on the
    /// final answer).
    pub fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        self.metrics.lookup_total.inc();
        let name = ctx.name().to_string();
        match self.trie.read().lookup(&name) {
            Lookup::Miss => Step::Continue,
            Lookup::Ips(ips) => self.respond_data(ctx, &name, ips),
            Lookup::Alias(original) => match self.trie.read().lookup(original) {
                Lookup::Ips(ips) => self.respond_data(ctx, &name, ips),
                _ => {
                    // 原域名无 IP 映射（含原域名本身也是别名）：改写为原域名
                    // 继续走管线，最终应答由 server 按查询名呈现。
                    ctx.original_name = Some(name);
                    ctx.rewrite_name(original);
                    Step::Continue
                }
            },
        }
    }

    /// 按查询名构造 hosts A/AAAA 应答并短路（owner = 查询名，IP 来自原域名映射）。
    fn respond_data(&self, ctx: &mut QueryContext, name: &str, ips: &[IpAddr]) -> Step {
        self.metrics.hit_total.inc();
        match build_hosts_response(&ctx.msg, name, ctx.qtype(), ips) {
            Ok(resp) => {
                ctx.response = Some(resp);
                ctx.action = "hosts".into();
                Step::Respond
            }
            Err(e) => {
                log::warn!("hosts building response for {} failed: {}", name, e);
                ctx.response = Some(build_servfail(&ctx.msg));
                ctx.action = "hosts".into();
                Step::Respond
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::cache::CacheKey;
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, RecordType};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Instant;

    fn test_trie(entries: &[&str]) -> HostsTrie {
        let owned: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        build_hosts_trie(&owned)
    }

    fn query_ctx(name: &str, qtype: RecordType) -> QueryContext {
        let msg = make_query_msg(name, qtype).unwrap();
        QueryContext::new(
            msg,
            CacheKey::new(name, qtype),
            SocketAddr::from_str("127.0.0.1:5353").unwrap(),
            "udp",
            Instant::now(),
            0,
        )
    }

    fn hosts_stage(trie: HostsTrie) -> Hosts {
        Hosts {
            trie: Arc::new(RwLock::new(Arc::new(trie))),
            metrics: Arc::new(HostsMetrics::new(&MetricsRegistry::default())),
        }
    }

    #[test]
    fn test_parse_hosts_line_consumed() {
        let mut b = HostsTrieBuilder::new();
        // IP 行：已消费
        assert!(parse_hosts_line(&mut b, "10.0.0.1 a.com"));
        // 空行 / 注释：已消费
        assert!(parse_hosts_line(&mut b, ""));
        assert!(parse_hosts_line(&mut b, "   "));
        assert!(parse_hosts_line(&mut b, "# comment"));
        // 别名行（非 IP）：未消费，交给 parse_alias_line
        assert!(!parse_hosts_line(&mut b, "edge.com cdn.com"));
        // 单 token：未消费
        assert!(!parse_hosts_line(&mut b, "a.com"));
    }

    #[test]
    fn test_parse_alias_line_skips_invalid() {
        // 原域名是 IP / 纯数字 → 跳过；自引用 → 忽略
        let mut b = HostsTrieBuilder::new();
        parse_alias_line(&mut b, "10.0.0.1 cdn.com");
        parse_alias_line(&mut b, "123 cdn.com");
        parse_alias_line(&mut b, "edge.com edge.com");
        assert_eq!(b.build().lookup("cdn.com"), Lookup::Miss);

        // 正常别名行：alias → original
        let mut b = HostsTrieBuilder::new();
        parse_alias_line(&mut b, "edge.com cdn1.com cdn2.com");
        let t = b.build();
        assert_eq!(t.lookup("cdn1.com"), Lookup::Alias("edge.com"));
        assert_eq!(t.lookup("cdn2.com"), Lookup::Alias("edge.com"));
        // 原域名本身不是 IP 映射
        assert_eq!(t.lookup("edge.com"), Lookup::Miss);
    }

    #[test]
    fn test_lookup_ips_and_alias() {
        let t = test_trie(&["10.0.0.1 edge.com", "edge.com cdn1.com cdn2.com"]);
        // IP 映射（含子域后缀匹配）
        assert!(matches!(t.lookup("edge.com"), Lookup::Ips(_)));
        assert!(matches!(t.lookup("sub.edge.com"), Lookup::Ips(_)));
        // 别名
        assert_eq!(t.lookup("cdn1.com"), Lookup::Alias("edge.com"));
        assert_eq!(t.lookup("cdn2.com"), Lookup::Alias("edge.com"));
        assert_eq!(t.lookup("cdn3.com"), Lookup::Miss);
    }

    #[test]
    fn test_handle_alias_with_original_ip() {
        let h = hosts_stage(test_trie(&["edge.com cdn1.com", "10.0.0.1 edge.com"]));
        let mut ctx = query_ctx("cdn1.com", RecordType::A);
        let step = h.handle(&mut ctx);
        assert_eq!(step, Step::Respond);
        let resp = ctx.response.unwrap();
        // answer owner = 查询名，IP 来自原域名映射
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].name.to_utf8(), "cdn1.com");
        assert_eq!(resp.answers[0].data, RData::A(A(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(ctx.action, "hosts");
        // 无别名改写
        assert!(ctx.original_name.is_none());
    }

    #[test]
    fn test_handle_alias_without_original_ip_continues_rewritten() {
        let h = hosts_stage(test_trie(&["edge.com cdn1.com"]));
        let mut ctx = query_ctx("cdn1.com", RecordType::A);
        let step = h.handle(&mut ctx);
        assert_eq!(step, Step::Continue);
        assert_eq!(ctx.original_name.as_deref(), Some("cdn1.com"));
        // 解析目标改写为原域名：cache key 与 msg question 同步
        assert_eq!(ctx.key.name, "edge.com");
        assert_eq!(ctx.msg.queries.first().unwrap().name().to_utf8(), "edge.com");
        assert!(ctx.response.is_none());
    }

    #[test]
    fn test_handle_direct_original_unchanged() {
        let h = hosts_stage(test_trie(&["10.0.0.1 edge.com"]));
        let mut ctx = query_ctx("edge.com", RecordType::A);
        let step = h.handle(&mut ctx);
        assert_eq!(step, Step::Respond);
        let resp = ctx.response.unwrap();
        assert_eq!(resp.answers[0].name.to_utf8(), "edge.com");
        assert!(ctx.original_name.is_none());
    }
}
