//! Upstream connection & pool configuration types for rsdns.
//!
//! Owned by the `upstream/` module: the named upstream groups
//! ([`UpstreamGroupConfig`]), their servers ([`ServerConfig`]) and the
//! per-server connection-pool tuning ([`RawPoolConfig`] / [`PoolConfig`]).

use serde::Deserialize;
use std::time::Duration;

use super::pool::{PoolConfig, PreferFamily};

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
    /// Total query budget in seconds, including queueing, connections and fallback.
    #[serde(default = "default_query_timeout")]
    pub query_timeout: std::num::NonZeroU16,
    /// Per-server attempt budget in seconds, including queueing, connections and DNS.
    #[serde(default = "default_attempt_timeout")]
    pub attempt_timeout: std::num::NonZeroU16,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}

fn default_query_timeout() -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(5).expect("positive default query timeout")
}

fn default_attempt_timeout() -> std::num::NonZeroU16 {
    std::num::NonZeroU16::new(2).expect("positive default attempt timeout")
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
            dns_timeout: defaults.dns_timeout,
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
