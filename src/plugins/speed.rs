//! `speed` stage — latency-ordered sorting of A/AAAA answers.
//!
//! Pipeline position: after `rules` (the terminal stage), before the
//! server's CNAME-to-last pass and cache write-back.  When enabled, it
//! measures TCP connect latency to each unique A/AAAA address in the final
//! response and stably re-orders those answers by RTT (fastest first,
//! failed probes last), so clients prefer the closest reachable node.
//!
//! The probe itself lives in the reusable free function
//! [`measure_tcp_latencies`], which other plugins can call without pulling
//! in this stage.
//!
//! See `docs/design/2026-08-21-rsdns-speed.md` for the full design.

use ahash::AHashMap;
use futures::future::join_all;
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use hickory_proto::rr::{Record, RecordType};
use log::warn;
use std::io;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::config::{parse_duration, Config, SpeedConfig};
use crate::query::{QueryContext, Step};

/// Address family whose answers the speed stage sorts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// Sort both A and AAAA answers (default).
    Any,
    /// Sort A answers only.
    A,
    /// Sort AAAA answers only.
    Aaaa,
}

fn parse_family(s: &str) -> Family {
    match s.trim().to_ascii_uppercase().as_str() {
        "A" => Family::A,
        "AAAA" => Family::Aaaa,
        _ => Family::Any, // "ANY" (default) and anything unknown
    }
}

/// Which record types participate in sorting for one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SortTypes {
    a: bool,
    aaaa: bool,
}

impl SortTypes {
    fn is_empty(self) -> bool {
        !self.a && !self.aaaa
    }
}

/// The speed stage.
pub struct Speed {
    enabled: bool,
    port: u16,
    family: Family,
    timeout: Duration,
}

/// Builds the speed stage from the `speed:` config section (or the default,
/// which is disabled).
pub fn init(config: &Config) -> Speed {
    let raw = config.plugin_sections.get("speed").cloned().unwrap_or_default();
    let cfg: SpeedConfig = serde_yaml::from_value(raw).unwrap_or_default();
    if cfg.r#type != "syn" {
        warn!("speed: unsupported type {:?}, falling back to syn", cfg.r#type);
    }
    let timeout = parse_duration(&cfg.timeout).unwrap_or(Duration::from_secs(1));
    Speed {
        enabled: cfg.enable,
        port: cfg.port,
        family: parse_family(&cfg.family),
        timeout,
    }
}

impl Speed {
    /// Sorts the response's A/AAAA answers by measured latency, in place.
    /// Returns `Step::Continue` — the response is already set by an earlier
    /// stage; this is a post-pass, never a short-circuit.
    pub async fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
        if !self.enabled || ctx.skip_speed {
            return Step::Continue;
        }
        let Some(types) = self.sort_types(ctx.qtype()) else {
            return Step::Continue;
        };
        let Some(response) = ctx.response.as_mut() else {
            return Step::Continue;
        };
        sort_addresses_by_latency(response, types, self.port, self.timeout).await;
        Step::Continue
    }

    /// Returns the record types to sort for this query type, or `None` when
    /// the query type does not match the configured `family`.
    fn sort_types(&self, qtype: RecordType) -> Option<SortTypes> {
        let query_set = match qtype {
            RecordType::A => SortTypes { a: true, aaaa: false },
            RecordType::AAAA => SortTypes { a: false, aaaa: true },
            RecordType::ANY => SortTypes { a: true, aaaa: true },
            _ => return None,
        };
        let family_set = match self.family {
            Family::Any => SortTypes { a: true, aaaa: true },
            Family::A => SortTypes { a: true, aaaa: false },
            Family::Aaaa => SortTypes { a: false, aaaa: true },
        };
        let merged = SortTypes {
            a: query_set.a && family_set.a,
            aaaa: query_set.aaaa && family_set.aaaa,
        };
        if merged.is_empty() {
            None
        } else {
            Some(merged)
        }
    }
}

/// Measures TCP connect latency to each IP on `port`, concurrently.
///
/// Generic helper — other plugins can reuse it without depending on this
/// stage.  Every IP is probed once with a `timeout`-bounded TCP handshake;
/// the socket is dropped immediately after connecting (no data exchanged).
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

/// Stably re-orders the A/AAAA answers in `msg` by measured RTT: successful
/// probes first (ascending RTT), failed probes last, ties keeping their
/// original order.  Non-target records (CNAME, HTTPS, …) keep their
/// positions.  No-op when fewer than two target answers are present.
async fn sort_addresses_by_latency(msg: &mut Message, types: SortTypes, port: u16, timeout: Duration) {
    // 1. Collect target answers: (index, ip).
    let mut targets: Vec<(usize, IpAddr)> = Vec::new();
    for (i, rec) in msg.answers.iter().enumerate() {
        match &rec.data {
            RData::A(ip) if types.a => targets.push((i, IpAddr::V4(ip.0))),
            RData::AAAA(ip) if types.aaaa => targets.push((i, IpAddr::V6(ip.0))),
            _ => {}
        }
    }
    if targets.len() < 2 {
        return;
    }

    // 2. Probe each unique IP exactly once.
    let mut ips: Vec<IpAddr> = targets.iter().map(|&(_, ip)| ip).collect();
    ips.sort_unstable();
    ips.dedup();
    let rtt: AHashMap<IpAddr, io::Result<Duration>> =
        measure_tcp_latencies(&ips, port, timeout).await.into_iter().collect();

    // 3. Stable sort by (failed, rtt); failures last, ties keep order.
    targets.sort_by(|&(_, a_ip), &(_, b_ip)| {
        let a_res = rtt.get(&a_ip);
        let b_res = rtt.get(&b_ip);
        let a_fail = !matches!(a_res, Some(Ok(_)));
        let b_fail = !matches!(b_res, Some(Ok(_)));
        if a_fail != b_fail {
            return a_fail.cmp(&b_fail);
        }
        let a_d = a_res.and_then(|r| r.as_ref().ok().copied()).unwrap_or(Duration::MAX);
        let b_d = b_res.and_then(|r| r.as_ref().ok().copied()).unwrap_or(Duration::MAX);
        a_d.cmp(&b_d)
    });

    // 4. Write the sorted records back into their answer slots.
    let sorted: Vec<Record> = targets.iter().map(|&(i, _)| msg.answers[i].clone()).collect();
    for (&(i, _), rec) in targets.iter().zip(sorted) {
        msg.answers[i] = rec;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::util::make_query_msg;
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::Name;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn cfg(enable: bool, family: &str) -> Speed {
        Speed {
            enabled: enable,
            port: 443,
            family: parse_family(family),
            timeout: Duration::from_secs(1),
        }
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

    #[test]
    fn test_parse_family() {
        assert_eq!(parse_family("ANY"), Family::Any);
        assert_eq!(parse_family("any"), Family::Any);
        assert_eq!(parse_family(""), Family::Any);
        assert_eq!(parse_family("A"), Family::A);
        assert_eq!(parse_family("AAAA"), Family::Aaaa);
        assert_eq!(parse_family("bogus"), Family::Any);
    }

    #[test]
    fn test_sort_types_matching() {
        // ANY family: A/AAAA/ANY queries all match.
        let s = cfg(true, "ANY");
        assert!(s.sort_types(RecordType::A).is_some());
        assert!(s.sort_types(RecordType::AAAA).is_some());
        assert!(s.sort_types(RecordType::ANY).is_some());
        assert!(s.sort_types(RecordType::MX).is_none());

        // A family: only A/ANY.
        let s = cfg(true, "A");
        assert!(s.sort_types(RecordType::A).is_some());
        assert!(s.sort_types(RecordType::ANY).is_some());
        assert!(s.sort_types(RecordType::AAAA).is_none());

        // AAAA family: only AAAA/ANY.
        let s = cfg(true, "AAAA");
        assert!(s.sort_types(RecordType::AAAA).is_some());
        assert!(s.sort_types(RecordType::ANY).is_some());
        assert!(s.sort_types(RecordType::A).is_none());
    }

    #[test]
    fn test_sort_types_record_selection() {
        // A query + ANY family sorts A only.
        let s = cfg(true, "ANY");
        assert_eq!(s.sort_types(RecordType::A), Some(SortTypes { a: true, aaaa: false }));
        assert_eq!(s.sort_types(RecordType::ANY), Some(SortTypes { a: true, aaaa: true }));
        // AAAA query + A family → no match.
        let s = cfg(true, "A");
        assert_eq!(s.sort_types(RecordType::AAAA), None);
        // ANY query + AAAA family sorts AAAA only.
        let s = cfg(true, "AAAA");
        assert_eq!(s.sort_types(RecordType::ANY), Some(SortTypes { a: false, aaaa: true }));
    }

    #[tokio::test]
    async fn test_sort_skips_single_answer() {
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        msg.answers.push(v4_rec(1));
        // One target → no sorting, unchanged.
        sort_addresses_by_latency(&mut msg, SortTypes { a: true, aaaa: false }, 443, Duration::from_millis(200)).await;
        assert_eq!(ips_of(&msg), vec!["10.0.0.1"]);
    }

    #[tokio::test]
    async fn test_sort_only_target_type() {
        // A query + a CNAME + two A: A sorted, CNAME untouched.
        let mut msg = make_query_msg("example.com", RecordType::A).unwrap();
        let cname = Record::from_rdata(
            Name::from_utf8("example.com").unwrap(),
            300,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(Name::from_utf8("target.example.com").unwrap())),
        );
        msg.answers.push(cname.clone());
        msg.answers.push(v4_rec(3));
        msg.answers.push(v4_rec(1));
        sort_addresses_by_latency(&mut msg, SortTypes { a: true, aaaa: false }, 443, Duration::from_millis(200)).await;
        // CNAME remains in position 0; the two A's swap to sorted order.
        assert!(matches!(msg.answers[0].data, RData::CNAME(_)));
        let a_ips: Vec<String> = msg.answers[1..].iter().map(|r| r.data.to_string()).collect();
        assert!(a_ips.contains(&"10.0.0.3".to_string()));
        assert!(a_ips.contains(&"10.0.0.1".to_string()));
    }

    #[tokio::test]
    async fn test_sort_preserves_other_types() {
        // ANY query + AAAA family: only AAAA sorted, A untouched.
        let mut msg = make_query_msg("example.com", RecordType::ANY).unwrap();
        msg.answers.push(v4_rec(1));
        msg.answers.push(v6_rec("2001:db8::2"));
        msg.answers.push(v6_rec("2001:db8::1"));
        sort_addresses_by_latency(&mut msg, SortTypes { a: false, aaaa: true }, 443, Duration::from_millis(200)).await;
        // A stays first.
        assert!(matches!(msg.answers[0].data, RData::A(_)));
        // AAAA answers are sorted (::1 before ::2) — may probe differently, so
        // only assert both are still present and the A is untouched.
        let aaaa_count = msg.answers.iter().filter(|r| matches!(r.data, RData::AAAA(_))).count();
        assert_eq!(aaaa_count, 2);
    }

    #[test]
    fn test_init_disabled_by_default() {
        let cfg = Config::default();
        let s = init(&cfg);
        assert!(!s.enabled);
        assert_eq!(s.port, 443);
        assert_eq!(s.family, Family::Any);
        assert_eq!(s.timeout, Duration::from_secs(1));
    }

    #[test]
    fn test_parse_duration_config() {
        use crate::config::parse_duration as pd;
        assert_eq!(pd("1s"), Some(Duration::from_secs(1)));
        assert_eq!(pd("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(pd("2"), Some(Duration::from_secs(2)));
        assert_eq!(pd("1m"), Some(Duration::from_secs(60)));
        assert_eq!(pd(""), None);
        assert_eq!(pd("0s"), None);
    }
}
