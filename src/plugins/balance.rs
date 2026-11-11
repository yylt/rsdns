//! `balance` stage — reorders A/AAAA answers by configured CIDR preference,
//! an optional post-pass mode, an optional answer-count cap, and optional
//! Cloudflare template substitution (ECH / A / AAAA).
//!
//! Pipeline position: after `rules` (the terminal stage), immediately before
//! the server's alias-restore / cache write-back.  It is a post-pass, never
//! a short-circuit.
//!
//! Behaviour (see `docs/design/2026-09-04-rsdns-balance.md` and
//! `docs/design/2026-11-10-rsdns-balance-cloudflare.md`):
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
//! - `cloudflare` (optional) substitutes answers that fall inside the
//!   built-in Cloudflare ranges with templates fetched through their configured
//!   upstreams: `ech` replaces HTTPS answers lacking `ech`, `a` replaces A
//!   answers, `aaaa` replaces AAAA answers.  Runs before `prefers`/`mode`/
//!   `max_answers`; skipped for DO/CD queries.
//! - A and AAAA records are handled as two independent families for the
//!   query types A / AAAA / ANY; IPv4 CIDRs only match A records, IPv6
//!   CIDRs only AAAA.  Non-target records (CNAME, HTTPS, …) keep their
//!   positions — only the relative order of each family's records changes.

use ahash::AHashMap;
use futures::future::join_all;
use log::warn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HTTPS, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::config::{parse_duration, BalanceCloudflareConfig, BalanceConfig, BalanceMode, BalanceSpeedConfig, Config};
use crate::plugins::cache::{CacheKey, CacheRecord, CacheResult, DnsCache};
use crate::plugins::util::{cache_upstream_response, make_query_msg, validate_domain};
use crate::query::{QueryContext, Step};
use crate::upstream::Upstreams;

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
// Cloudflare ranges / template substitution
// ---------------------------------------------------------------------------

/// Cloudflare IPv4 ranges from <https://www.cloudflare.com/ips-v4> (fetched
/// 2026-11-10).  Used to decide whether an answer belongs to Cloudflare and
/// is therefore a candidate for template substitution.
const CLOUDFLARE_IPV4_CIDRS: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Cloudflare IPv6 ranges from <https://www.cloudflare.com/ips-v6> (fetched
/// 2026-11-10).
const CLOUDFLARE_IPV6_CIDRS: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Parsed Cloudflare ranges (v4 + v6), initialized once.  Invalid built-in
/// constants panic at startup — they are data, not user configuration.
fn cloudflare_cidrs() -> &'static [Cidr] {
    static CIDRS: OnceLock<Vec<Cidr>> = OnceLock::new();
    CIDRS.get_or_init(|| {
        CLOUDFLARE_IPV4_CIDRS
            .iter()
            .chain(CLOUDFLARE_IPV6_CIDRS)
            .map(|s| Cidr::parse(s).unwrap_or_else(|| panic!("invalid Cloudflare CIDR {s:?}")))
            .collect()
    })
}

/// Whether `ip` falls inside any built-in Cloudflare range.
fn is_cloudflare_ip(ip: IpAddr) -> bool {
    cloudflare_cidrs().iter().any(|c| c.contains(ip))
}

/// One Cloudflare template domain (`balance.cloudflare.{ech,a,aaaa}`).
#[derive(Debug)]
struct CfTemplate {
    domain: String,
    upstream: String,
}

impl CfTemplate {
    fn cache_key(&self, rtype: RecordType) -> CacheKey {
        CacheKey::new(format!("{}@{}", self.domain, self.upstream), rtype)
    }
}

/// Resolved `balance.cloudflare` config.
#[derive(Debug)]
struct Cloudflare {
    /// HTTPS template domain for `ech` completion.
    ech: Option<CfTemplate>,
    /// A template domain.
    a: Option<CfTemplate>,
    /// AAAA template domain.
    aaaa: Option<CfTemplate>,
}

/// Invalid template specifications disable only the affected record type.
fn parse_cf_template(field: &str, spec: Option<&str>, config: &Config) -> Option<CfTemplate> {
    let spec = spec?.trim();
    let Some((domain, upstream)) = spec.split_once('@') else {
        warn!("balance cloudflare.{field}: expected domain@upstream, got {spec:?}, disabled");
        return None;
    };
    let Some(domain) = validate_domain(domain) else {
        warn!("balance cloudflare.{field}: invalid domain in {spec:?}, disabled");
        return None;
    };
    if !config
        .upstreams
        .iter()
        .any(|u| u.name == upstream && !upstream.is_empty())
    {
        warn!("balance cloudflare.{field}: unknown upstream {upstream:?}, disabled");
        return None;
    }
    Some(CfTemplate {
        domain,
        upstream: upstream.to_string(),
    })
}

/// Builds the Cloudflare substitution config if at least one template is usable.
fn build_cloudflare(cfg: &BalanceCloudflareConfig, config: &Config) -> Option<Cloudflare> {
    let ech = parse_cf_template("ech", cfg.ech.as_deref(), config);
    let a = parse_cf_template("a", cfg.a.as_deref(), config);
    let aaaa = parse_cf_template("aaaa", cfg.aaaa.as_deref(), config);
    if ech.is_none() && a.is_none() && aaaa.is_none() {
        return None;
    }
    Some(Cloudflare { ech, a, aaaa })
}

// ---------------------------------------------------------------------------
// Cloudflare template substitution helpers
// ---------------------------------------------------------------------------

/// Whether `name` equals `domain` (case/trailing-dot insensitive).
fn same_name(name: &Name, domain: &str) -> bool {
    name.to_utf8()
        .trim_end_matches('.')
        .eq_ignore_ascii_case(domain.trim_end_matches('.'))
}

/// Whether an HTTPS answer is a "CF range + no ech" substitution candidate:
/// an `ipv4hint`/`ipv6hint` inside the built-in ranges and no `ech` param.
fn cf_https_candidate(r: &Record) -> bool {
    let RData::HTTPS(svcb) = &r.data else {
        return false;
    };
    let mut in_cf = false;
    let mut has_ech = false;
    for (key, value) in &svcb.svc_params {
        match (key, value) {
            (SvcParamKey::EchConfigList, _) => has_ech = true,
            (SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(ips))) => {
                in_cf |= ips.iter().any(|ip| is_cloudflare_ip(IpAddr::V4(ip.0)));
            }
            (SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(ips))) => {
                in_cf |= ips.iter().any(|ip| is_cloudflare_ip(IpAddr::V6(ip.0)));
            }
            _ => {}
        }
    }
    in_cf && !has_ech
}

/// Whether `r` is an A/AAAA answer inside the built-in Cloudflare ranges.
fn cf_address_candidate(r: &Record, rtype: RecordType) -> bool {
    match (&r.data, rtype) {
        (RData::A(ip), RecordType::A) => is_cloudflare_ip(IpAddr::V4(ip.0)),
        (RData::AAAA(ip), RecordType::AAAA) => is_cloudflare_ip(IpAddr::V6(ip.0)),
        _ => false,
    }
}

/// Whether cached template records contain at least one record of `rtype`.
fn has_record_type(records: &[CacheRecord], rtype: RecordType) -> bool {
    records.iter().any(|r| {
        matches!(
            (rtype, r),
            (RecordType::A, CacheRecord::A(_))
                | (RecordType::AAAA, CacheRecord::Aaaa(_))
                | (RecordType::HTTPS, CacheRecord::Https(_))
        )
    })
}

/// First cached HTTPS SVCB carrying an `ech` param.
fn first_ech_https(records: &[CacheRecord]) -> Option<SVCB> {
    records.iter().find_map(|r| match r {
        CacheRecord::Https(svcb) if svcb_has_ech(svcb) => Some(svcb.clone()),
        _ => None,
    })
}

/// SVCB 是否含 `ech` SvcParam。
fn svcb_has_ech(svcb: &SVCB) -> bool {
    svcb.svc_params.iter().any(|(k, _)| *k == SvcParamKey::EchConfigList)
}

/// Extracts the A/AAAA IPs from cached template records.
fn address_ips(records: &[CacheRecord], rtype: RecordType) -> Vec<IpAddr> {
    records
        .iter()
        .filter_map(|r| match (rtype, r) {
            (RecordType::A, CacheRecord::A(ip)) => Some(IpAddr::V4(*ip)),
            (RecordType::AAAA, CacheRecord::Aaaa(ip)) => Some(IpAddr::V6(*ip)),
            _ => None,
        })
        .collect()
}

/// Replaces every CF candidate HTTPS answer with a record built from the
/// template SVCB; owner/TTL of the replaced record are preserved.
fn replace_https_answers(records: &[Record], template: &SVCB) -> Vec<Record> {
    records
        .iter()
        .map(|r| {
            if cf_https_candidate(r) {
                Record::from_rdata(r.name.clone(), r.ttl, RData::HTTPS(HTTPS(template.clone())))
            } else {
                r.clone()
            }
        })
        .collect()
}

/// Replaces the whole address family with template addresses: owner/TTL come
/// from the first replaced record, and the template records are spliced in at
/// that record's position.  Other records keep their relative order.
fn replace_address_answers(records: &[Record], rtype: RecordType, ips: &[IpAddr]) -> Vec<Record> {
    let Some(first) = records.iter().find(|r| r.record_type() == rtype) else {
        return records.to_vec();
    };
    let owner = first.name.clone();
    let ttl = first.ttl;
    let mut out = Vec::with_capacity(records.len() + ips.len());
    let mut inserted = false;
    for r in records {
        if r.record_type() == rtype {
            if !inserted {
                out.extend(
                    ips.iter()
                        .map(|ip| Record::from_rdata(owner.clone(), ttl, address_rdata(*ip, rtype))),
                );
                inserted = true;
            }
        } else {
            out.push(r.clone());
        }
    }
    out
}

/// Builds A/AAAA RDATA for a template IP of the same family as `rtype`.
fn address_rdata(ip: IpAddr, rtype: RecordType) -> RData {
    match (ip, rtype) {
        (IpAddr::V4(ip), RecordType::A) => RData::A(A(ip)),
        (IpAddr::V6(ip), RecordType::AAAA) => RData::AAAA(AAAA(ip)),
        _ => unreachable!("template address family must match the query family"),
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
    /// Cloudflare template substitution (`balance.cloudflare`), if enabled.
    cloudflare: Option<Cloudflare>,
    /// Small TTL cache for Cloudflare templates (created with `cloudflare`).
    template_cache: Option<Arc<DnsCache>>,
    /// Assembled upstreams (template queries), attached after
    /// `upstream::init`; `None` until then.
    upstreams: Option<Arc<Upstreams>>,
}

/// Builds the balance stage from the `balance:` config section.  When the
/// section is absent the stage is inert: no reordering, no rotation, no
/// truncation.
pub fn init(config: &Config) -> Balance {
    let Some(raw) = config.plugin_sections.get("balance") else {
        return Balance::disabled();
    };
    let cfg: BalanceConfig = match serde_yaml::from_value(raw.clone()) {
        Ok(c) => c,
        Err(e) => {
            warn!("balance: invalid config, disabled: {}", e);
            return Balance::disabled();
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
    let cloudflare = cfg.cloudflare.as_ref().and_then(|c| build_cloudflare(c, config));
    let template_cache = cloudflare
        .as_ref()
        .map(|_| Arc::new(DnsCache::new_metric(64, 60, 3600, false)));
    Balance {
        enabled: true,
        cidrs,
        mode,
        max_answers: cfg.max_answers,
        speed,
        cloudflare,
        template_cache,
        upstreams: None,
    }
}

impl Balance {
    fn disabled() -> Self {
        Self {
            enabled: false,
            cidrs: Vec::new(),
            mode: BalanceMode::None,
            max_answers: None,
            speed: BalanceSpeedConfig::default(),
            cloudflare: None,
            template_cache: None,
            upstreams: None,
        }
    }

    /// Injects the assembled upstream pools for template queries.  Must run
    /// after `upstream::init` (which borrows `Balance` for `rank_ips`).
    pub fn attach_upstreams(&mut self, upstreams: Arc<Upstreams>) {
        self.upstreams = Some(upstreams);
    }

    /// Reorders / rotates / truncates the response in place.  Returns
    /// `Step::Continue` — a post-pass, never a short-circuit.
    pub async fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        if !self.enabled || ctx.skip_balance {
            return Step::Continue;
        }
        // Cloudflare template substitution runs before reordering/truncation,
        // so the template records participate in `prefers`/`mode` and the
        // answer cap applies to the substituted set.
        if let Some(cf) = &self.cloudflare {
            self.apply_cloudflare(ctx, cf).await;
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

    /// 启动期上游域名解析用：把候选 IP 按本 stage 的 `prefers` CIDR 做**稳定
    /// 排序**——命中外层（索引更小）CIDR 的 IP 排在前；同排名内保持原有相对顺序
    /// （Rust `sort_by` 为稳定排序）。家族隔离由 `Cidr::contains` 保证（v4 CIDR
    /// 只匹配 v4 IP）。未启用（`enabled=false`）或 `cidrs` 为空时为无操作，原样
    /// 返回。
    pub fn rank_ips(&self, mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
        if !self.enabled || self.cidrs.is_empty() {
            return ips;
        }
        ips.sort_by_key(|ip| self.rank(*ip).unwrap_or(usize::MAX));
        ips
    }

    /// Applies `balance.cloudflare` template substitution to the final
    /// response.  Each configured template domain is independent:
    ///
    /// - `ech` replaces CF-range HTTPS answers lacking `ech`;
    /// - `a` replaces CF-range A answers;
    /// - `aaaa` replaces CF-range AAAA answers.
    ///
    /// Skipped for DNSSEC queries (DO/CD) because replacing answer sets
    /// would break RRSIG coverage, and for the template domains themselves.
    async fn apply_cloudflare(&self, ctx: &mut QueryContext, cf: &Cloudflare) {
        if ctx.msg.metadata.checking_disabled || ctx.msg.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok) {
            return;
        }
        let qtype = ctx.qtype();
        if !matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::ANY) {
            return;
        }
        let Some(qname) = ctx.msg.queries.first().map(|q| q.name().clone()) else {
            return;
        };
        let Some(resp) = ctx.response.as_ref() else {
            return;
        };
        let answers = &resp.answers;

        let ech = cf.ech.as_ref().filter(|t| !same_name(&qname, &t.domain));
        let a = cf.a.as_ref().filter(|t| !same_name(&qname, &t.domain));
        let aaaa = cf.aaaa.as_ref().filter(|t| !same_name(&qname, &t.domain));

        let want_https = ech.is_some()
            && matches!(qtype, RecordType::HTTPS | RecordType::ANY)
            && answers.iter().any(cf_https_candidate);
        let want_a = a.is_some()
            && matches!(qtype, RecordType::A | RecordType::ANY)
            && answers.iter().any(|r| cf_address_candidate(r, RecordType::A));
        let want_aaaa = aaaa.is_some()
            && matches!(qtype, RecordType::AAAA | RecordType::ANY)
            && answers.iter().any(|r| cf_address_candidate(r, RecordType::AAAA));
        if !(want_https || want_a || want_aaaa) {
            return;
        }

        // Fetch all needed templates before mutating the response.
        let https = if want_https {
            self.template_https(ech.expect("ech template")).await
        } else {
            None
        };
        let ips_a = if want_a {
            self.template_ips(a.expect("a template"), RecordType::A).await
        } else {
            None
        };
        let ips_aaaa = if want_aaaa {
            self.template_ips(aaaa.expect("aaaa template"), RecordType::AAAA).await
        } else {
            None
        };

        let Some(resp) = ctx.response.as_mut() else {
            return;
        };
        if let Some(template) = https {
            resp.answers = replace_https_answers(&resp.answers, &template);
        }
        if let Some(ips) = ips_a {
            resp.answers = replace_address_answers(&resp.answers, RecordType::A, &ips);
        }
        if let Some(ips) = ips_aaaa {
            resp.answers = replace_address_answers(&resp.answers, RecordType::AAAA, &ips);
        }
    }

    /// Fetches (and TTL-caches) the template records for `domain`/`rtype`.
    async fn template_records(&self, template: &CfTemplate, rtype: RecordType) -> Option<Arc<[CacheRecord]>> {
        let cache = self.template_cache.as_ref()?;
        let upstreams = self.upstreams.as_ref()?;
        let domain = &template.domain;
        let key = template.cache_key(rtype);
        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            return has_record_type(&entry.records, rtype).then(|| entry.records.clone());
        }
        let msg = match make_query_msg(domain, rtype) {
            Ok(m) => m,
            Err(e) => {
                warn!("balance cloudflare: invalid template domain {domain:?}: {e}");
                return None;
            }
        };
        let resp = match upstreams.query(&template.upstream, &msg).await {
            Ok(r) => r,
            Err(e) => {
                warn!("balance cloudflare: query {domain:?}/{rtype} failed: {e}, keep original response");
                return None;
            }
        };
        cache_upstream_response(cache, &key, &resp, None).await;
        match cache.get_cached(&key).await {
            CacheResult::Fresh(entry) => has_record_type(&entry.records, rtype).then(|| entry.records.clone()),
            CacheResult::Miss => None,
        }
    }

    /// First template HTTPS SVCB carrying `ech`.
    async fn template_https(&self, template: &CfTemplate) -> Option<SVCB> {
        let records = self.template_records(template, RecordType::HTTPS).await?;
        first_ech_https(&records)
    }

    /// Template A/AAAA addresses (empty → `None`, keep the original answer).
    async fn template_ips(&self, template: &CfTemplate, rtype: RecordType) -> Option<Vec<IpAddr>> {
        let records = self.template_records(template, rtype).await?;
        let ips = address_ips(&records, rtype);
        (!ips.is_empty()).then_some(ips)
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
    fn test_rank_ips_stable_prefers() {
        // rank_ips 与应答排序共享同一份 prefers 语义：命中外层 CIDR 的排在前，
        // 同排名保持输入顺序（稳定排序），家族隔离（v6 CIDR 不影响 v4 IP）。
        let cfg = cfg_yaml("balance:\n  prefers:\n    - 192.0.2.0/24\n    - 10.0.0.0/8\nupstreams: []\n");
        let b = init(&cfg);
        let ips = vec![
            IpAddr::from_str("10.0.0.9").unwrap(),
            IpAddr::from_str("198.51.100.7").unwrap(),
            IpAddr::from_str("192.0.2.1").unwrap(),
            IpAddr::from_str("10.1.2.3").unwrap(),
        ];
        let ranked = b.rank_ips(ips);
        // ranks: 192.0.2.1=0, 10.0.0.9/10.1.2.3=1, 198.51.100.7=miss；同 rank 稳定保持顺序。
        assert_eq!(
            ranked,
            vec![
                IpAddr::from_str("192.0.2.1").unwrap(),
                IpAddr::from_str("10.0.0.9").unwrap(),
                IpAddr::from_str("10.1.2.3").unwrap(),
                IpAddr::from_str("198.51.100.7").unwrap(),
            ]
        );
    }

    #[test]
    fn test_rank_ips_noop_without_prefers() {
        // 未配置 balance（enabled=false）或 prefers 为空 → 原样返回，不影响顺序。
        let none = init(&cfg_yaml("upstreams: []\n"));
        assert!(!none.enabled);
        let ips = vec![
            IpAddr::from_str("198.51.100.7").unwrap(),
            IpAddr::from_str("10.0.0.9").unwrap(),
        ];
        assert_eq!(none.rank_ips(ips.clone()), ips);

        let empty = init(&cfg_yaml("balance:\n  prefers: []\nupstreams: []\n"));
        assert!(empty.enabled && empty.cidrs.is_empty());
        assert_eq!(empty.rank_ips(ips.clone()), ips);
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

    // ---- balance.cloudflare ----

    fn https_rec(name: &str, ttl: u32, v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>, ech: bool) -> Record {
        let mut params = Vec::new();
        if let Some(ip) = v4 {
            params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(vec![A(ip)]))));
        }
        if let Some(ip) = v6 {
            params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(ip)]))));
        }
        if ech {
            params.push((
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(hickory_proto::rr::rdata::svcb::EchConfigList(vec![1, 2, 3])),
            ));
        }
        let svcb = SVCB::new(1, Name::root(), params);
        Record::from_rdata(Name::from_utf8(name).unwrap(), ttl, RData::HTTPS(HTTPS(svcb)))
    }

    #[test]
    fn test_is_cloudflare_ip_v4_v6() {
        assert!(is_cloudflare_ip("104.16.0.1".parse().unwrap()));
        assert!(is_cloudflare_ip("172.64.0.1".parse().unwrap()));
        assert!(is_cloudflare_ip("2606:4700::1".parse().unwrap()));
        assert!(is_cloudflare_ip("2a06:98c0::1".parse().unwrap()));
        assert!(!is_cloudflare_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_cloudflare_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_cf_https_candidate_v4_v6() {
        // CF v4 hint / CF v6 hint without ech → candidate.
        assert!(cf_https_candidate(&https_rec(
            "a.com",
            300,
            Some(Ipv4Addr::new(104, 16, 0, 1)),
            None,
            false
        )));
        assert!(cf_https_candidate(&https_rec(
            "a.com",
            300,
            None,
            Some("2606:4700::1".parse().unwrap()),
            false
        )));
        // Out-of-range hint / already has ech / no hint → not a candidate.
        assert!(!cf_https_candidate(&https_rec(
            "a.com",
            300,
            Some(Ipv4Addr::new(8, 8, 8, 8)),
            None,
            false
        )));
        assert!(!cf_https_candidate(&https_rec(
            "a.com",
            300,
            Some(Ipv4Addr::new(104, 16, 0, 1)),
            None,
            true
        )));
        assert!(!cf_https_candidate(&https_rec("a.com", 300, None, None, false)));
        // Non-HTTPS records are never candidates.
        assert!(!cf_https_candidate(&a_rec("104.16.0.1")));
    }

    #[test]
    fn test_replace_https_answers() {
        let template = SVCB::new(
            1,
            Name::root(),
            vec![(
                SvcParamKey::EchConfigList,
                SvcParamValue::EchConfigList(hickory_proto::rr::rdata::svcb::EchConfigList(vec![9, 9])),
            )],
        );
        let in_cf = https_rec("cf.example.com", 120, Some(Ipv4Addr::new(104, 16, 0, 1)), None, false);
        let outside = https_rec("out.example.com", 120, Some(Ipv4Addr::new(8, 8, 8, 8)), None, false);
        let has_ech = https_rec("ech.example.com", 120, Some(Ipv4Addr::new(104, 16, 0, 2)), None, true);
        let a = a_rec("1.2.3.4");
        let out = replace_https_answers(&[in_cf.clone(), outside.clone(), has_ech.clone(), a.clone()], &template);

        assert_eq!(out.len(), 4);
        // Replaced record keeps its owner/TTL and carries the template RDATA.
        assert_eq!(out[0].name, in_cf.name);
        assert_eq!(out[0].ttl, 120);
        let RData::HTTPS(svcb) = &out[0].data else {
            panic!("expected HTTPS");
        };
        assert!(svcb_has_ech(svcb));
        assert_eq!(svcb.target_name, Name::root());
        // Everything else is untouched.
        assert_eq!(out[1].data, outside.data);
        assert_eq!(out[2].data, has_ech.data);
        assert_eq!(out[3].data, a.data);
    }

    #[test]
    fn test_replace_address_answers() {
        use hickory_proto::rr::rdata::CNAME;
        let cname = Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::CNAME(CNAME(Name::from_utf8("cdn.example.com").unwrap())),
        );
        let a1 = a_rec("104.16.0.1");
        let a2 = a_rec("104.16.0.2");
        let aaaa = v6_rec("2001:db8::1");
        let records = vec![cname.clone(), a1.clone(), a2, aaaa.clone()];

        let ips: Vec<IpAddr> = vec!["104.17.0.1".parse().unwrap(), "104.17.0.2".parse().unwrap()];
        let out = replace_address_answers(&records, RecordType::A, &ips);
        // CNAME + two template A + AAAA (the two original A records collapse
        // into the template set at the first A's position).
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].data, cname.data);
        assert_eq!(out[1].data, RData::A(A("104.17.0.1".parse().unwrap())));
        assert_eq!(out[2].data, RData::A(A("104.17.0.2".parse().unwrap())));
        assert_eq!(out[3].data, aaaa.data);
        // Owner/TTL come from the first replaced record.
        assert_eq!(out[1].name, a1.name);
        assert_eq!(out[1].ttl, a1.ttl);
        assert_eq!(out[2].ttl, a1.ttl);
    }

    #[test]
    fn test_cloudflare_template_upstreams() {
        let cfg = cfg_yaml(
            "upstreams:\n  - name: first\n    servers: [{ address: 1.1.1.1 }]\n  - name: second\n    servers: [{ address: 8.8.8.8 }]\nbalance:\n  cloudflare:\n    ech: example.com@first\n    a: example.com@second\n    aaaa: example.com@first\n",
        );
        let cf = init(&cfg).cloudflare.unwrap();
        let ech = cf.ech.unwrap();
        let a = cf.a.unwrap();
        assert_eq!(ech.upstream, "first");
        assert_eq!(a.upstream, "second");
        assert_eq!(cf.aaaa.unwrap().upstream, "first");
        assert_ne!(ech.cache_key(RecordType::A), a.cache_key(RecordType::A));
        assert_ne!(ech.cache_key(RecordType::A), ech.cache_key(RecordType::HTTPS));

        for spec in [
            "example.com",
            "@first",
            "example.com@",
            "example.com@unknown",
            "example.com@first@second",
        ] {
            assert!(parse_cf_template("ech", Some(spec), &cfg).is_none(), "{spec}");
        }
    }

    #[tokio::test]
    async fn test_cloudflare_template_cache_isolated_by_upstream() {
        let cache = DnsCache::new_metric(64, 60, 3600, false);
        let first = CfTemplate {
            domain: "example.com".into(),
            upstream: "first".into(),
        };
        let second = CfTemplate {
            domain: "example.com".into(),
            upstream: "second".into(),
        };
        cache
            .put(
                first.cache_key(RecordType::A),
                vec![CacheRecord::A(Ipv4Addr::new(1, 1, 1, 1))],
                60,
            )
            .await;
        assert!(matches!(
            cache.get_cached(&first.cache_key(RecordType::A)).await,
            CacheResult::Fresh(_)
        ));
        assert!(matches!(
            cache.get_cached(&second.cache_key(RecordType::A)).await,
            CacheResult::Miss
        ));
    }

    #[test]
    fn test_cloudflare_domains_are_independent() {
        // An invalid `ech` only disables ech; `a` stays enabled and `aaaa`
        // is not implied.
        let cfg = cfg_yaml(
            "upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\nbalance:\n  cloudflare:\n    ech: \"bad domain.com@default\"\n    a: crypto.cloudflare.com@default\n",
        );
        let cf = init(&cfg).cloudflare.expect("a enabled");
        assert!(cf.ech.is_none());
        assert_eq!(cf.a.as_ref().unwrap().domain, "crypto.cloudflare.com");
        assert!(cf.aaaa.is_none());

        // All template domains invalid/empty → feature disabled.
        let cfg = cfg_yaml(
            "upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\nbalance:\n  cloudflare:\n    ech: \"\"\n",
        );
        assert!(init(&cfg).cloudflare.is_none());
    }

    #[tokio::test]
    async fn test_cloudflare_without_upstreams_keeps_answers() {
        // Before `attach_upstreams` the substitution is a no-op.
        let cfg = cfg_yaml(
            "upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\nbalance:\n  cloudflare:\n    a: crypto.cloudflare.com@default\n",
        );
        let b = init(&cfg);
        assert!(b.cloudflare.is_some());
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(a_rec("104.16.0.1"));
        let mut ctx = test_ctx(msg, RecordType::A);
        b.handle(&mut ctx).await;
        assert_eq!(ips_of(ctx.response.as_ref().unwrap()), vec!["104.16.0.1"]);
    }
}
