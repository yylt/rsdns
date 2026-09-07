//! `balance` stage — reorders A/AAAA answers by configured CIDR preference,
//! an optional post-pass mode, and an optional answer-count cap.
//!
//! Pipeline position: after `rules` (the terminal stage), immediately before
//! the server's alias-restore / cache write-back.  It is a post-pass, never
//! a short-circuit.
//!
//! Behaviour (see `docs/design/2026-09-04-rsdns-balance.md`):
//!
//! - The stage is inert unless a `balance:` config section exists; a fresh
//!   cache hit also skips it (`ctx.skip_balance`).
//! - `prefers` is a flat CIDR list whose order is priority.  An answer IP
//!   matching an earlier CIDR is stably sorted ahead of one matching a later
//!   CIDR; IPs matching no CIDR keep their relative order at the end.  This
//!   is record-side only — every client sees the same order.
//! - `mode` (default `none`) controls the post-pass **only when all records
//!   of a family are equally ranked** (no CIDR preference, or all in one
//!   rank): `round_robin` rotates the family from a fresh random offset per
//!   query (stateless, no shared counter); `speed` latency-orders the family
//!   by TCP-connect RTT.  Once `prefers` has produced differing ranks the
//!   stable prefer-sort wins and no mode runs — a mode never overrides an
//!   established preference.
//! - `max_answers` (optional) truncates the whole answer list after the
//!   above; `0` or absent = no limit.
//! - A and AAAA records are handled as two independent families for the
//!   query types A / AAAA / ANY; IPv4 CIDRs only match A records, IPv6
//!   CIDRs only AAAA.  Non-target records (CNAME, HTTPS, …) keep their
//!   positions — only the relative order of each family's records changes.

use ahash::AHashMap;
use futures::future::join_all;
use log::warn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record, RecordType};

use crate::config::{parse_duration, BalanceConfig, BalanceMode, BalanceSpeedConfig, Config};
use crate::query::{QueryContext, Step};

// ---------------------------------------------------------------------------
// CIDR
// ---------------------------------------------------------------------------

/// A parsed IPv4 or IPv6 CIDR range (std-only integer comparison; no `ipnet`
/// crate).
#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { net: u32, prefix: u8 },
    V6 { net: u128, prefix: u8 },
}

impl Cidr {
    fn parse(spec: &str) -> Option<Cidr> {
        let (addr, prefix) = spec.trim().split_once('/')?;
        let prefix: u8 = prefix.parse().ok()?;
        if let Ok(v4) = addr.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return None;
            }
            return Some(Cidr::V4 {
                net: u32::from(v4),
                prefix,
            });
        }
        if let Ok(v6) = addr.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return None;
            }
            return Some(Cidr::V6 {
                net: u128::from(v6),
                prefix,
            });
        }
        None
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { net, prefix }, IpAddr::V4(ip)) => {
                let ip = u32::from(ip);
                let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
                (ip & mask) == (net & mask)
            }
            (Cidr::V6 { net, prefix }, IpAddr::V6(ip)) => {
                let ip = u128::from(ip);
                let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
                (ip & mask) == (net & mask)
            }
            // An IPv4 CIDR never matches an AAAA record and vice versa, so a
            // family stays within one address family.
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Latency sorting (mode: speed)
// ---------------------------------------------------------------------------

/// Measures TCP connect latency to each IP on `port`, concurrently.
///
/// Every IP is probed once with a `timeout`-bounded TCP handshake; the
/// socket is dropped immediately after connecting (no data exchanged).
/// Results are returned in the same order as `ips`; a failed probe carries
/// the underlying `io::Error` (or a `TimedOut` error).
pub async fn measure_tcp_latencies(
    ips: &[IpAddr],
    port: u16,
    timeout: Duration,
) -> Vec<(IpAddr, io::Result<Duration>)> {
    let futs = ips.iter().map(|&ip| async move {
        let start = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((ip, port))).await {
            Ok(Ok(_)) => (ip, Ok(start.elapsed())),
            Ok(Err(e)) => (ip, Err(e)),
            Err(_) => (ip, Err(io::Error::new(io::ErrorKind::TimedOut, "speed probe timed out"))),
        }
    });
    join_all(futs).await
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// Which record families this query participates in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Families {
    a: bool,
    aaaa: bool,
}

impl Families {
    fn is_empty(self) -> bool {
        !self.a && !self.aaaa
    }
}

/// The balance stage.
pub struct Balance {
    /// Whether a `balance:` config section exists (inert otherwise).
    enabled: bool,
    /// CIDR list in config order; index = priority rank (lower = earlier).
    cidrs: Vec<Cidr>,
    /// Post-pass mode (default `none`).
    mode: BalanceMode,
    /// Optional whole-answer cap after reordering.
    max_answers: Option<usize>,
    /// Parameters used by `mode: speed`.
    speed: BalanceSpeedConfig,
}

/// Builds the balance stage from the `balance:` config section.  When the
/// section is absent the stage is inert: no reordering, no rotation, no
/// truncation.
pub fn init(config: &Config) -> Balance {
    let Some(raw) = config.plugin_sections.get("balance") else {
        return Balance {
            enabled: false,
            cidrs: Vec::new(),
            mode: BalanceMode::None,
            max_answers: None,
            speed: BalanceSpeedConfig::default(),
        };
    };
    let cfg: BalanceConfig = match serde_yaml::from_value(raw.clone()) {
        Ok(c) => c,
        Err(e) => {
            warn!("balance: invalid config, disabled: {}", e);
            return Balance {
                enabled: false,
                cidrs: Vec::new(),
                mode: BalanceMode::None,
                max_answers: None,
                speed: BalanceSpeedConfig::default(),
            };
        }
    };
    let mode = BalanceMode::parse(&cfg.mode);
    let trimmed = cfg.mode.trim();
    if mode == BalanceMode::None && !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("none") {
        warn!("balance: unsupported mode {:?}, falling back to none", cfg.mode);
    }
    let cidrs = cfg
        .prefers
        .iter()
        .filter_map(|s| {
            let c = Cidr::parse(s);
            if c.is_none() {
                warn!("balance: invalid CIDR {:?}, skipped", s);
            }
            c
        })
        .collect();
    // Only `mode: speed` consumes the probe params; parse them then.
    let mut speed = cfg.speed.unwrap_or_default();
    if mode == BalanceMode::Speed && speed.r#type != "syn" {
        warn!("balance speed: unsupported type {:?}, falling back to syn", speed.r#type);
        speed.r#type = "syn".into();
    }
    Balance {
        enabled: true,
        cidrs,
        mode,
        max_answers: cfg.max_answers,
        speed,
    }
}

impl Balance {
    /// Reorders / rotates / truncates the response in place.  Returns
    /// `Step::Continue` — a post-pass, never a short-circuit.
    pub async fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        if !self.enabled || ctx.skip_balance {
            return Step::Continue;
        }
        // Only A / AAAA / ANY queries are balanced (and only those get the
        // whole-answer cap); anything else is passed through untouched.
        let Some(families) = families(ctx.qtype()) else {
            return Step::Continue;
        };
        if !families.is_empty() {
            let Some(response) = ctx.response.as_mut() else {
                return Step::Continue;
            };
            // prefers 先把每条记录按命中 rank 分组；当族内 rank 存在差异时，
            // 稳定偏好排序即为最终顺序（mode 不再执行，避免覆盖偏好）。仅当
            // 族内全部同 rank（无 prefers / 全部未命中 / 同一 CIDR）时，mode
            // 才在该族上执行（round_robin 轮转 / speed 按 RTT 排序）。
            self.balance_family(response, families.a).await;
            self.balance_family(response, families.aaaa).await;
        }
        if let Some(max) = self.max_answers {
            if let Some(response) = ctx.response.as_mut() {
                if max > 0 && response.answers.len() > max {
                    response.answers.truncate(max);
                }
            }
        }
        Step::Continue
    }

    /// Returns the priority rank (index into `cidrs`) of the first CIDR
    /// containing `ip`, or `None` when no CIDR matches.
    fn rank(&self, ip: IpAddr) -> Option<usize> {
        self.cidrs.iter().position(|c| c.contains(ip))
    }

    /// Reorders one family.  When its records have differing ranks the
    /// family is stably prefer-sorted; when they are all equally ranked the
    /// configured mode runs on the family (none → leave as-is, round_robin →
    /// rotate from a random start, speed → latency-order).  With fewer than
    /// two records nothing is done.
    async fn balance_family(&self, msg: &mut Message, is_a: bool) {
        let targets = collect_family(msg, is_a);
        if targets.len() < 2 {
            return;
        }
        let ranks: Vec<Option<usize>> = targets.iter().map(|&(_, ip)| self.rank(ip)).collect();
        if !self.cidrs.is_empty() {
            let uniform = ranks.iter().all(|r| *r == ranks[0]);
            if !uniform {
                // Mixed ranks: stable prefer-sort wins; no mode runs.
                let mut order: Vec<usize> = (0..targets.len()).collect();
                order.sort_by_key(|&k| ranks[k].unwrap_or(self.cidrs.len()));
                permute_family(msg, &targets, &order);
                return;
            }
        }
        match self.mode {
            BalanceMode::None => {}
            BalanceMode::RoundRobin => {
                let start = rand::random_range(0..targets.len());
                rotate_family(msg, &targets, start);
            }
            BalanceMode::Speed => sort_family_by_latency(msg, &targets, &self.speed).await,
        }
    }
}

/// Collects one family's answer slots `(index, ip)` in answer order.
fn collect_family(msg: &Message, is_a: bool) -> Vec<(usize, IpAddr)> {
    let mut targets = Vec::new();
    for (i, rec) in msg.answers.iter().enumerate() {
        match (&rec.data, is_a) {
            (RData::A(ip), true) => targets.push((i, IpAddr::V4(ip.0))),
            (RData::AAAA(ip), false) => targets.push((i, IpAddr::V6(ip.0))),
            _ => {}
        }
    }
    targets
}

/// Applies a permutation `order` (indices into `targets`) to the family's
/// records: slot `targets[k].0` receives the record that was at
/// `targets[order[k]].0`.  Non-target records keep their positions.  Returns
/// whether the order changed.
fn permute_family(msg: &mut Message, targets: &[(usize, IpAddr)], order: &[usize]) -> bool {
    if order.iter().enumerate().all(|(i, &k)| i == k) {
        return false;
    }
    let records: Vec<Record> = order.iter().map(|&k| msg.answers[targets[k].0].clone()).collect();
    for (k, &(slot, _)) in targets.iter().enumerate() {
        msg.answers[slot] = records[k].clone();
    }
    true
}

/// Circularly shifts the family's records so that the record `start`
/// positions into the family becomes first (`start == 0` → no-op).
fn rotate_family(msg: &mut Message, targets: &[(usize, IpAddr)], start: usize) {
    if start == 0 {
        return;
    }
    let n = targets.len();
    let order: Vec<usize> = (0..n).map(|k| (k + start) % n).collect();
    permute_family(msg, targets, &order);
}

/// Latency-orders one family's records (`mode: speed`): probes each unique
/// IP with a TCP handshake and stably sorts successful probes by RTT
/// ascending, failed probes last (ties keeping their original order).
async fn sort_family_by_latency(msg: &mut Message, targets: &[(usize, IpAddr)], speed: &BalanceSpeedConfig) {
    if targets.len() < 2 {
        return;
    }
    // Probe each unique IP exactly once.
    let mut ips: Vec<IpAddr> = targets.iter().map(|&(_, ip)| ip).collect();
    ips.sort_unstable();
    ips.dedup();
    let timeout = parse_duration(&speed.timeout).unwrap_or(Duration::from_secs(1));
    let rtt: AHashMap<IpAddr, io::Result<Duration>> = measure_tcp_latencies(&ips, speed.port, timeout)
        .await
        .into_iter()
        .collect();

    let mut order: Vec<usize> = (0..targets.len()).collect();
    order.sort_by(|&a, &b| {
        let a_res = rtt.get(&targets[a].1);
        let b_res = rtt.get(&targets[b].1);
        let a_fail = !matches!(a_res, Some(Ok(_)));
        let b_fail = !matches!(b_res, Some(Ok(_)));
        if a_fail != b_fail {
            return a_fail.cmp(&b_fail);
        }
        let a_d = a_res.and_then(|r| r.as_ref().ok().copied()).unwrap_or(Duration::MAX);
        let b_d = b_res.and_then(|r| r.as_ref().ok().copied()).unwrap_or(Duration::MAX);
        a_d.cmp(&b_d)
    });
    permute_family(msg, targets, &order);
}

/// The address families to process for a query type (A / AAAA / ANY);
/// anything else → `None`.
fn families(qtype: RecordType) -> Option<Families> {
    match qtype {
        RecordType::A => Some(Families { a: true, aaaa: false }),
        RecordType::AAAA => Some(Families { a: false, aaaa: true }),
        RecordType::ANY => Some(Families { a: true, aaaa: true }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::cache::CacheKey;
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::Name;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Instant;

    fn cfg_yaml(yaml: &str) -> Config {
        Config::from_yaml_str(yaml).expect("parse failed")
    }

    fn v4_rec(o: u8) -> Record {
        Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(10, 0, 0, o))),
        )
    }

    fn v6_rec(s: &str) -> Record {
        let ip: Ipv6Addr = s.parse().unwrap();
        Record::from_rdata(Name::from_utf8("example.com").unwrap(), 300, RData::AAAA(AAAA(ip)))
    }

    fn a_rec(ip: &str) -> Record {
        Record::from_rdata(Name::from_utf8("example.com").unwrap(), 300, RData::A(A(ip.parse().unwrap())))
    }

    fn ips_of(msg: &Message) -> Vec<String> {
        msg.answers
            .iter()
            .map(|r| match &r.data {
                RData::A(a) => a.0.to_string(),
                RData::AAAA(a) => a.0.to_string(),
                other => format!("{other:?}"),
            })
            .collect()
    }

    fn test_ctx(msg: hickory_proto::op::Message, qtype: RecordType) -> QueryContext {
        let mut ctx = QueryContext::new(
            make_query_msg("example.com", qtype).unwrap(),
            CacheKey::new("example.com", qtype),
            SocketAddr::from_str("127.0.0.1:5353").unwrap(),
            "udp",
            Instant::now(),
            0,
        );
        // balance is a post-pass on the final response; put the message in
        // `ctx.response` the way the server does before calling it.
        ctx.response = Some(msg);
        ctx
    }

    /// Runs the (async) balance handle on a fresh runtime.
    fn run_balance(b: &Balance, ctx: &mut QueryContext) {
        tokio::runtime::Runtime::new().unwrap().block_on(b.handle(ctx));
    }

    #[test]
    fn test_init_disabled_without_section() {
        let b = init(&cfg_yaml("upstreams: []\n"));
        assert!(!b.enabled);
        assert_eq!(b.mode, BalanceMode::None);
        assert!(b.cidrs.is_empty());
        assert!(b.max_answers.is_none());
    }

    #[test]
    fn test_mode_parsing() {
        assert_eq!(BalanceMode::parse("none"), BalanceMode::None);
        assert_eq!(BalanceMode::parse(""), BalanceMode::None);
        assert_eq!(BalanceMode::parse("NONE"), BalanceMode::None);
        assert_eq!(BalanceMode::parse("round_robin"), BalanceMode::RoundRobin);
        assert_eq!(BalanceMode::parse("round-robin"), BalanceMode::RoundRobin);
        assert_eq!(BalanceMode::parse("speed"), BalanceMode::Speed);
        assert_eq!(BalanceMode::parse("bogus"), BalanceMode::None);
    }

    #[test]
    fn test_default_mode_is_none() {
        // 未写 mode 时，除 prefers/max_answers 外不做任何事：两条记录保持原序。
        let cfg = cfg_yaml("balance:\n  max_answers: 5\nupstreams: []\n");
        let b = init(&cfg);
        assert_eq!(b.mode, BalanceMode::None);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(v4_rec(1));
        msg.answers.push(v4_rec(2));
        let mut ctx = test_ctx(msg, RecordType::A);
        run_balance(&b, &mut ctx);
        assert_eq!(ips_of(ctx.response.as_ref().unwrap()), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn test_cidr_parse_and_contains() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
        // v4 CIDR never matches a v6 IP
        assert!(!c.contains("2001:db8::1".parse().unwrap()));

        let c = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));

        let c = Cidr::parse("10.0.0.1/32").unwrap();
        assert!(c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!c.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        assert!(Cidr::parse("").is_none());
        assert!(Cidr::parse("10.0.0.1").is_none());
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("not-an-ip/8").is_none());
    }

    #[test]
    fn test_families_matching() {
        assert_eq!(families(RecordType::A), Some(Families { a: true, aaaa: false }));
        assert_eq!(families(RecordType::AAAA), Some(Families { a: false, aaaa: true }));
        assert_eq!(families(RecordType::ANY), Some(Families { a: true, aaaa: true }));
        assert!(families(RecordType::MX).is_none());
    }

    #[test]
    fn test_prefers_stable_sort_and_cap() {
        let cfg =
            cfg_yaml("balance:\n  prefers:\n    - 10.0.0.0/8\n    - 192.0.2.0/24\n  max_answers: 3\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("10.9.9.9"));
        msg.answers.push(a_rec("198.51.100.7"));
        msg.answers.push(a_rec("192.0.2.1"));
        msg.answers.push(a_rec("10.0.1.5"));
        let mut ctx = test_ctx(msg, RecordType::A);
        run_balance(&b, &mut ctx);
        let resp = ctx.response.as_ref().unwrap();
        // ranks: 10.9.9.9/10.0.1.5 = 0, 192.0.2.1 = 1, 198.51.100.7 = miss
        // stable prefer-sort: [10.9.9.9, 10.0.1.5, 192.0.2.1, 198.51.100.7]
        // then max_answers 3 truncates the whole list.
        assert_eq!(ips_of(resp), vec!["10.9.9.9", "10.0.1.5", "192.0.2.1"]);
    }

    #[test]
    fn test_prefers_keeps_unmatched_relative_order() {
        let cfg = cfg_yaml("balance:\n  prefers:\n    - 10.0.0.0/8\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("192.0.2.1"));
        msg.answers.push(a_rec("198.51.100.7"));
        msg.answers.push(a_rec("10.0.0.9"));
        let mut ctx = test_ctx(msg, RecordType::A);
        run_balance(&b, &mut ctx);
        assert_eq!(
            ips_of(ctx.response.as_ref().unwrap()),
            vec!["10.0.0.9", "192.0.2.1", "198.51.100.7"]
        );
    }

    #[test]
    fn test_round_robin_mode_rotates_uniform_family() {
        // mode round_robin, no prefers: two A records are one uniform family,
        // each query rotates from a random start.  With two records both
        // orders must appear across many queries.
        let cfg = cfg_yaml("balance:\n  mode: round_robin\nupstreams: []\n");
        let b = init(&cfg);
        assert_eq!(b.mode, BalanceMode::RoundRobin);
        let mut orders = std::collections::HashSet::new();
        for _ in 0..50 {
            let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
            msg.answers.push(v4_rec(1));
            msg.answers.push(v4_rec(2));
            let mut ctx = test_ctx(msg, RecordType::A);
            run_balance(&b, &mut ctx);
            orders.insert(ips_of(ctx.response.as_ref().unwrap()).join(","));
        }
        assert!(orders.contains("10.0.0.1,10.0.0.2"), "orders: {orders:?}");
        assert!(orders.contains("10.0.0.2,10.0.0.1"), "orders: {orders:?}");
    }

    #[test]
    fn test_mixed_rank_prefers_no_mode() {
        // prefers 产生不同 rank（一条命中 + 一条未命中）→ 稳定排序优先，
        // 即使 mode: round_robin 也不轮转；命中者恒在首位。
        let cfg = cfg_yaml("balance:\n  mode: round_robin\n  prefers:\n    - 10.0.0.0/8\nupstreams: []\n");
        let b = init(&cfg);
        assert_eq!(b.mode, BalanceMode::RoundRobin);
        for _ in 0..20 {
            let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
            msg.answers.push(a_rec("192.0.2.1"));
            msg.answers.push(a_rec("10.0.0.9"));
            let mut ctx = test_ctx(msg, RecordType::A);
            run_balance(&b, &mut ctx);
            assert_eq!(
                ips_of(ctx.response.as_ref().unwrap()),
                vec!["10.0.0.9", "192.0.2.1"],
                "mixed ranks must not rotate"
            );
        }
    }

    #[test]
    fn test_uniform_prefer_rank_still_round_robin() {
        // prefers 全部命中同一 CIDR（uniform rank）→ round_robin 仍执行。
        let cfg = cfg_yaml("balance:\n  mode: round_robin\n  prefers:\n    - 10.0.0.0/8\nupstreams: []\n");
        let b = init(&cfg);
        let mut orders = std::collections::HashSet::new();
        for _ in 0..50 {
            let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
            msg.answers.push(a_rec("10.0.0.9"));
            msg.answers.push(a_rec("10.0.0.1"));
            let mut ctx = test_ctx(msg, RecordType::A);
            run_balance(&b, &mut ctx);
            orders.insert(ips_of(ctx.response.as_ref().unwrap()).join(","));
        }
        assert!(orders.contains("10.0.0.9,10.0.0.1"), "orders: {orders:?}");
        assert!(orders.contains("10.0.0.1,10.0.0.9"), "orders: {orders:?}");
    }

    #[test]
    fn test_any_query_separates_families() {
        // ANY query: A records are never matched by an IPv6 CIDR; the AAAA
        // family rotates independently; CNAME positions are untouched.
        let cfg = cfg_yaml("balance:\n  mode: round_robin\n  prefers:\n    - 2001:db8::/32\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::ANY).unwrap();
        let cname = Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_utf8("target.example.com").unwrap())),
        );
        msg.answers.push(cname.clone());
        msg.answers.push(a_rec("192.0.2.1"));
        msg.answers.push(v6_rec("2001:db8::2"));
        msg.answers.push(v6_rec("2001:db8::1"));
        let mut ctx = test_ctx(msg, RecordType::ANY);
        run_balance(&b, &mut ctx);
        let resp = ctx.response.as_ref().unwrap();
        assert!(matches!(resp.answers[0].data, RData::CNAME(_)));
        assert!(matches!(resp.answers[1].data, RData::A(_)));
        let aaaa_count = resp.answers.iter().filter(|r| matches!(r.data, RData::AAAA(_))).count();
        assert_eq!(aaaa_count, 2);
    }

    #[test]
    fn test_non_address_queries_untouched() {
        // MX query: no family → pass through, and no whole-answer cap.
        let cfg = cfg_yaml("balance:\n  max_answers: 1\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::MX).unwrap();
        msg.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_utf8("mail.example.com").unwrap(),
            )),
        ));
        msg.answers.push(Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                20,
                Name::from_utf8("mail2.example.com").unwrap(),
            )),
        ));
        let mut ctx = test_ctx(msg, RecordType::MX);
        run_balance(&b, &mut ctx);
        assert_eq!(ctx.response.as_ref().unwrap().answers.len(), 2);
    }

    #[test]
    fn test_cap_zero_or_absent_no_limit() {
        let cfg = cfg_yaml("balance:\n  max_answers: 0\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        for i in 1..=8u8 {
            msg.answers.push(v4_rec(i));
        }
        let mut ctx = test_ctx(msg, RecordType::A);
        run_balance(&b, &mut ctx);
        assert_eq!(ctx.response.as_ref().unwrap().answers.len(), 8);
    }

    #[test]
    fn test_invalid_cidr_skipped() {
        let cfg = cfg_yaml("balance:\n  prefers:\n    - not-a-cidr\n    - 10.0.0.0/8\nupstreams: []\n");
        let b = init(&cfg);
        assert_eq!(b.cidrs.len(), 1);
    }

    #[test]
    fn test_skip_balance_flag_skips_everything() {
        // ctx.skip_balance = true → 即使配置了 prefers/max_answers 也原样放行。
        let cfg = cfg_yaml("balance:\n  prefers:\n    - 10.0.0.0/8\n  max_answers: 1\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("10.0.0.9"));
        msg.answers.push(a_rec("192.0.2.1"));
        let mut ctx = test_ctx(msg, RecordType::A);
        ctx.skip_balance = true;
        run_balance(&b, &mut ctx);
        assert_eq!(
            ips_of(ctx.response.as_ref().unwrap()),
            vec!["10.0.0.9", "192.0.2.1"],
            "skip_balance must bypass prefers and max_answers"
        );
    }

    #[test]
    fn test_speed_mode_reachable_first() {
        // mode: speed：两条 A 记录按 RTT 排序。本地监听端口必达应排最前，
        // TEST-NET 保留地址（探测失败）排最后。
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = format!(
            "balance:\n  mode: speed\n  speed:\n    type: syn\n    port: {port}\n    timeout: 100ms\nupstreams: []\n"
        );
        let b = init(&cfg_yaml(&cfg));
        assert_eq!(b.mode, BalanceMode::Speed);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("192.0.2.1"));
        msg.answers.push(a_rec("127.0.0.1"));
        let mut ctx = test_ctx(msg, RecordType::A);
        rt.block_on(b.handle(&mut ctx));
        let got = ips_of(ctx.response.as_ref().unwrap());
        assert_eq!(got.first().unwrap(), "127.0.0.1", "reachable should sort first, got {got:?}");
    }

    #[tokio::test]
    async fn test_speed_mode_single_untouched() {
        // 单条 A → 不探测、不改变。
        let cfg = cfg_yaml("balance:\n  mode: speed\nupstreams: []\n");
        let b = init(&cfg);
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("127.0.0.1"));
        let mut ctx = test_ctx(msg, RecordType::A);
        b.handle(&mut ctx).await;
        assert_eq!(ips_of(ctx.response.as_ref().unwrap()), vec!["127.0.0.1"]);
    }

    #[test]
    fn test_speed_config_defaults() {
        let sp = BalanceSpeedConfig::default();
        assert_eq!(sp.r#type, "syn");
        assert_eq!(sp.port, 443);
        assert_eq!(sp.timeout, "1s");
    }
}
