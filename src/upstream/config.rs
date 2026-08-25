//! Upstream connection & pool configuration types for rsdns.
//!
//! Owned by the `upstream/` module: the named upstream groups
//! ([`UpstreamGroupConfig`]), their servers ([`ServerConfig`]) and the
//! per-server connection-pool tuning ([`RawPoolConfig`] / [`PoolConfig`]).

use serde::Deserialize;
use std::time::Duration;

use super::pool::{PoolConfig, PreferFamily};

/// Parsed cooldown policy: `window:errors:cooldown`, e.g. `1m:10:10s`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CooldownConfig {
    /// Sliding error-count window length.
    pub window: Duration,
    /// Error count within `window` that triggers cooling.
    pub threshold: u32,
    /// How long a server is skipped once tripped.
    pub cooldown: Duration,
}

/// Parses a `<window>:<errors>:<cooldown>` spec into [`CooldownConfig`].
///
/// Durations accept a unit suffix (`s`/`m`/`h`); a bare number means
/// seconds.  `errors` must be ≥ 1.  Returns `None` for an empty input,
/// `Some(...)` on success.
pub fn parse_cooldown(s: &str) -> Result<Option<CooldownConfig>, String> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = s.split(':').map(str::trim).collect();
    if parts.len() != 3 {
        return Err(format!("invalid cooldown {s:?}: expected <window>:<errors>:<cooldown>"));
    }
    let window = parse_duration(parts[0]).ok_or_else(|| format!("invalid cooldown {s:?}: bad window duration"))?;
    let threshold: u32 = parts[1]
        .parse()
        .map_err(|_| format!("invalid cooldown {s:?}: errors must be a number"))?;
    if threshold == 0 {
        return Err(format!("invalid cooldown {s:?}: errors must be >= 1"));
    }
    let cooldown = parse_duration(parts[2]).ok_or_else(|| format!("invalid cooldown {s:?}: bad cooldown duration"))?;
    Ok(Some(CooldownConfig {
        window,
        threshold,
        cooldown,
    }))
}

/// Parses a duration with an optional unit suffix (`s`/`m`/`h`); a bare
/// number means seconds.  `0` is rejected.
fn parse_duration(s: &str) -> Option<Duration> {
    let (num, mult) = if let Some(n) = s.strip_suffix('h') {
        (n, 3600u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1u64)
    } else {
        (s, 1u64)
    };
    let n: u64 = num.parse().ok()?;
    if n == 0 {
        return None;
    }
    Some(Duration::from_secs(n.saturating_mul(mult)))
}

/// A single upstream server entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address with optional scheme: `"223.5.5.5"`, `"tls://dot.pub"`,
    /// `"https://doh.pub/dns-query"`, `"h3://..."`, `"quic://..."`.
    pub address: String,
    /// TLS server name (SNI / certificate name) used for DoT/DoH/DoH3/DoQ
    /// when the `address` host is a domain.  Defaults to the host from
    /// `address` when absent.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Optional connection-pool configuration (see [`RawPoolConfig`]).
    #[serde(default)]
    pub pool: Option<RawPoolConfig>,
}

/// A named upstream pool.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamGroupConfig {
    /// Pool name, referenced by `forward` rules.
    pub name: String,
    #[serde(default)]
    pub mode: QueryModeConfig,
    /// Circuit-breaker style per-server cooling, written as
    /// `<window>:<errors>:<cooldown>`, e.g. `1m:10:10s` = if a server
    /// fails 10 times within a 1-minute window, cool it down for 10
    /// seconds (skipped during queries).  Omitted → no cooling.
    #[serde(default)]
    pub cooldown: Option<String>,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QueryModeConfig {
    /// Race all servers concurrently; first success wins.
    Parallel,
    /// Try servers in config order; first success wins.
    #[default]
    Serial,
    /// Try servers in a random order; first success wins.
    Random,
    /// Try servers round-robin starting from a rotating cursor; first success wins.
    #[serde(alias = "round_robin")]
    RoundRobin,
}

/// User-facing pool configuration as parsed from YAML.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawPoolConfig {
    /// Seconds before an idle connection is dropped.
    pub idle_timeout: Option<u16>,
    /// Connect timeout in seconds.
    pub connect_timeout: Option<u16>,
    /// Per-request DNS timeout in seconds.
    pub dns_timeout: Option<u16>,
    /// Address family filter used when bootstrap-resolving a domain upstream:
    /// `"any"` (default), `"ipv4"`, or `"ipv6"`.
    pub prefer_family: Option<String>,
}

/// 将可选的秒数配置转换为 [`Duration`]，缺省时用 `default`。
fn opt_dur(secs: Option<u16>, default: Duration) -> Duration {
    secs.map(|s| Duration::from_secs(u64::from(s))).unwrap_or(default)
}

impl RawPoolConfig {
    /// Converts the raw YAML config into a runtime [`PoolConfig`].
    pub fn into_pool_config(self) -> PoolConfig {
        let defaults = PoolConfig::default();
        PoolConfig {
            idle_timeout: opt_dur(self.idle_timeout, defaults.idle_timeout),
            connect_timeout: opt_dur(self.connect_timeout, defaults.connect_timeout),
            dns_timeout: opt_dur(self.dns_timeout, defaults.dns_timeout),
        }
    }

    /// The address family preference for bootstrap resolution.
    pub fn prefer_family(&self) -> PreferFamily {
        match self.prefer_family.as_deref() {
            Some("ipv4") => PreferFamily::Ipv4,
            Some("ipv6") => PreferFamily::Ipv6,
            _ => PreferFamily::Any,
        }
    }
}
