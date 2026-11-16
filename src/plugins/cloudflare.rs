//! Cloudflare template substitution, run on every final response before balance.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HTTPS, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use log::warn;

use super::balance::Cidr;
use crate::config::{CloudflareConfig, Config};
use crate::plugins::cache::{CacheKey, CacheRecord, CacheResult, DnsCache};
use crate::plugins::util::{cache_upstream_response, make_query_msg, validate_domain};
use crate::query::{QueryContext, Step};
use crate::upstream::Upstreams;

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

/// One Cloudflare template domain (`cloudflare.{ech,a,aaaa}`).
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

/// Resolved `cloudflare` config.
#[derive(Debug)]
struct Templates {
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
        warn!("cloudflare.{field}: expected domain@upstream, got {spec:?}, disabled");
        return None;
    };
    let Some(domain) = validate_domain(domain) else {
        warn!("cloudflare.{field}: invalid domain in {spec:?}, disabled");
        return None;
    };
    if !config
        .upstreams
        .iter()
        .any(|u| u.name == upstream && !upstream.is_empty())
    {
        warn!("cloudflare.{field}: unknown upstream {upstream:?}, disabled");
        return None;
    }
    Some(CfTemplate {
        domain,
        upstream: upstream.to_string(),
    })
}

/// Builds the Cloudflare substitution config if at least one template is usable.
fn build_cloudflare(cfg: &CloudflareConfig, config: &Config) -> Option<Templates> {
    let ech = parse_cf_template("ech", cfg.ech.as_deref(), config);
    let a = parse_cf_template("a", cfg.a.as_deref(), config);
    let aaaa = parse_cf_template("aaaa", cfg.aaaa.as_deref(), config);
    if ech.is_none() && a.is_none() && aaaa.is_none() {
        return None;
    }
    Some(Templates { ech, a, aaaa })
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

/// Independent post-pass with its own TTL cache and template upstreams.
pub struct Cloudflare {
    cloudflare: Option<Templates>,
    template_cache: Option<Arc<DnsCache>>,
    upstreams: Option<Arc<Upstreams>>,
}

pub fn init(config: &Config) -> Cloudflare {
    let cloudflare = config.plugin_sections.get("cloudflare").and_then(|raw| {
        match serde_yaml::from_value::<CloudflareConfig>(raw.clone()) {
            Ok(cfg) => build_cloudflare(&cfg, config),
            Err(e) => {
                warn!("cloudflare: invalid config, disabled: {e}");
                None
            }
        }
    });
    let template_cache = cloudflare
        .as_ref()
        .map(|_| Arc::new(DnsCache::new_metric(64, 60, 3600, false)));
    Cloudflare {
        cloudflare,
        template_cache,
        upstreams: None,
    }
}

impl Cloudflare {
    /// Attach the pools assembled at startup for template queries.
    pub fn attach_upstreams(&mut self, upstreams: Arc<Upstreams>) {
        self.upstreams = Some(upstreams);
    }

    /// Always called, independently of cache/group/balance bypass flags.
    pub async fn handle(&self, ctx: &mut QueryContext) -> Step {
        if let Some(cf) = &self.cloudflare {
            self.apply_cloudflare(ctx, cf).await;
        }
        Step::Continue
    }

    /// Applies `cloudflare` template substitution to the final
    /// response.  Each configured template domain is independent:
    ///
    /// - `ech` replaces CF-range HTTPS answers lacking `ech`;
    /// - `a` replaces CF-range A answers;
    /// - `aaaa` replaces CF-range AAAA answers.
    ///
    /// Skipped for DNSSEC queries (DO/CD) because replacing answer sets
    /// would break RRSIG coverage, and for the template domains themselves.
    async fn apply_cloudflare(&self, ctx: &mut QueryContext, cf: &Templates) {
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
                warn!("cloudflare: invalid template domain {domain:?}: {e}");
                return None;
            }
        };
        let resp = match upstreams.query(&template.upstream, &msg).await {
            Ok(r) => r,
            Err(e) => {
                warn!("cloudflare: query {domain:?}/{rtype} failed: {e}, keep original response");
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Instant;

    fn cfg_yaml(yaml: &str) -> Config {
        Config::from_yaml_str(yaml).expect("parse failed")
    }

    fn a_rec(ip: &str) -> Record {
        Record::from_rdata(Name::from_utf8("example.com").unwrap(), 300, RData::A(A(ip.parse().unwrap())))
    }

    fn v6_rec(s: &str) -> Record {
        let ip: Ipv6Addr = s.parse().unwrap();
        Record::from_rdata(Name::from_utf8("example.com").unwrap(), 300, RData::AAAA(AAAA(ip)))
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
            "upstreams:\n  - name: first\n    servers: [{ address: 1.1.1.1 }]\n  - name: second\n    servers: [{ address: 8.8.8.8 }]\ncloudflare:\n  ech: example.com@first\n  a: example.com@second\n  aaaa: example.com@first\n",
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
            "upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\ncloudflare:\n  ech: \"bad domain.com@default\"\n  a: crypto.cloudflare.com@default\n",
        );
        let cf = init(&cfg).cloudflare.expect("a enabled");
        assert!(cf.ech.is_none());
        assert_eq!(cf.a.as_ref().unwrap().domain, "crypto.cloudflare.com");
        assert!(cf.aaaa.is_none());

        // All template domains invalid/empty → feature disabled.
        let cfg =
            cfg_yaml("upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\ncloudflare:\n  ech: \"\"\n");
        assert!(init(&cfg).cloudflare.is_none());
    }

    #[tokio::test]
    async fn test_cloudflare_guards_and_bypass_flags() {
        let cfg = cfg_yaml("cloudflare:\n  a: template.example@local\n  aaaa: template.example@local\n  ech: template.example@local\nupstreams:\n  - name: local\n    servers: [{ address: '127.0.0.1:9' }]\n");
        let metrics = crate::metrics::MetricsRegistry::new();
        let hosts = crate::plugins::hosts::init(&cfg, &metrics);
        let balance = crate::plugins::balance::init(&cfg);
        let mut cf = init(&cfg);
        cf.attach_upstreams(crate::upstream::init(&cfg, &metrics, &hosts, &balance).await.unwrap());
        let cache = cf.template_cache.as_ref().unwrap();
        let template = cf.cloudflare.as_ref().unwrap().a.as_ref().unwrap();
        cache
            .put(
                template.cache_key(RecordType::A),
                vec![CacheRecord::A("192.0.2.1".parse().unwrap())],
                300,
            )
            .await;
        cache
            .put(
                template.cache_key(RecordType::AAAA),
                vec![CacheRecord::Aaaa("2001:db8::1".parse().unwrap())],
                300,
            )
            .await;
        let https = https_rec("template.example", 300, None, None, true);
        let RData::HTTPS(https) = https.data else {
            panic!("HTTPS template")
        };
        cache
            .put(template.cache_key(RecordType::HTTPS), vec![CacheRecord::Https(https.0)], 300)
            .await;

        for (rtype, original) in [
            (RecordType::A, a_rec("104.16.0.1")),
            (RecordType::AAAA, v6_rec("2606:4700::1")),
            (
                RecordType::HTTPS,
                https_rec("example.com", 300, Some("104.16.0.1".parse().unwrap()), None, false),
            ),
        ] {
            for guard in ["none", "cd", "do", "template"] {
                let mut msg = make_query_msg("example.com", rtype).unwrap();
                msg.answers.push(original.clone());
                let mut ctx = test_ctx(msg, rtype);
                ctx.skip_balance = true;
                ctx.skip_cache = true;
                match guard {
                    "cd" => ctx.msg.metadata.checking_disabled = true,
                    "do" => {
                        let mut edns = hickory_proto::op::Edns::new();
                        edns.set_dnssec_ok(true);
                        ctx.msg.edns = Some(edns);
                    }
                    "template" => {
                        ctx.msg.queries[0].set_name(Name::from_utf8("TEMPLATE.EXAMPLE.").unwrap());
                    }
                    _ => {}
                }
                cf.handle(&mut ctx).await;
                let answer = &ctx.response.as_ref().unwrap().answers[0];
                assert_eq!(answer.name, original.name);
                assert_eq!(answer.ttl, original.ttl);
                if guard == "none" {
                    assert_ne!(answer.data, original.data, "{rtype} should be substituted despite bypass flags");
                } else {
                    assert_eq!(answer.data, original.data, "{rtype} {guard} guard");
                }
            }
        }
    }

    #[tokio::test]
    async fn test_cloudflare_without_upstreams_keeps_answers() {
        // Before `attach_upstreams` the substitution is a no-op.
        let cfg = cfg_yaml(
            "upstreams:\n  - name: default\n    servers: [{ address: 8.8.8.8 }]\ncloudflare:\n  a: crypto.cloudflare.com@default\n",
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
