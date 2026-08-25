//! Configuration types for rsdns.
//!
//! The top-level [`Config`] mirrors `rsdns.yaml`.  The structural sections
//! (`binds`, `groups`, `upstreams`) are arrays read directly by the server /
//! pipeline stages, while every other top-level key (`rules`, `cache`,
//! `log`, `hosts`, `metrics`, …) is captured verbatim in
//! [`Config::plugin_sections`] and consumed by the corresponding stage.
//!
//! The `upstreams` section is deserialized into [`Config::upstreams`] using
//! the types in `crate::upstream::config`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::upstream::config::UpstreamGroupConfig;

/// Root configuration, deserialised from rsdns.yaml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// Listen addresses: `"0.0.0.0:53"` for UDP, `"tcp://0.0.0.0:53"` for TCP.
    #[serde(default)]
    pub binds: Vec<BindConfig>,
    /// Domain groups (array, config order = match priority).
    #[serde(default)]
    pub groups: Vec<GroupConfig>,
    /// Upstream pools (array, each with a `name`).
    #[serde(default)]
    pub upstreams: Vec<UpstreamGroupConfig>,
    /// Every other top-level section, consumed by pipeline stages.
    #[serde(flatten)]
    pub plugin_sections: BTreeMap<String, serde_yaml::Value>,
}

/// A single listening address.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BindConfig {
    /// `"0.0.0.0:53"` (UDP) or `"tcp://0.0.0.0:53"` (TCP).
    pub address: String,
}

/// A domain group.
///
/// `domains` entries are inline domain names or `file://path` sources.
/// Data-layer code strips `*.` prefixes; each line of a source file
/// supports `#` comments and blank lines.  `file://` sources are watched
/// with the `notify` library and reloaded automatically on change.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupConfig {
    /// Group name, referenced by `match: group:{name}` rules.
    pub name: String,
    /// Inline domains and/or `file://` sources.
    #[serde(default)]
    pub domains: Vec<String>,
    /// When a queried name belongs to this group, bypass the cache
    /// (both lookup and write-back).
    #[serde(default)]
    pub skip_cache: bool,
    /// When a queried name belongs to this group, skip the speed plugin's
    /// latency-ordered sorting of A/AAAA answers.
    #[serde(default)]
    pub skip_speed: bool,
}

impl Config {
    /// Parses a YAML string into a [`Config`].
    pub fn from_yaml_str(content: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(content)
    }

    /// Reads a YAML file and parses it into a [`Config`].
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml_str(&content)?)
    }
}

/// Cache behaviour tuning.  All fields are optional; missing fields use
/// the defaults defined in `DnsCache::new()`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheConfig {
    /// LRU capacity (default 4096).
    #[serde(default)]
    pub size: Option<usize>,
    /// Minimum TTL to clamp responses to (seconds).
    #[serde(default)]
    pub min_ttl: Option<u32>,
    /// Maximum TTL to clamp responses to (seconds).
    #[serde(default)]
    pub max_ttl: Option<u32>,
    /// If `true`, preserve the upstream's original TTL (overrides `min_ttl`/`max_ttl`).
    #[serde(default)]
    pub keep_ttl: Option<bool>,
}

/// Speed plugin configuration (top-level `speed:` section).
///
/// Latency-measures A/AAAA answers and sorts them by RTT.  Disabled by
/// default; see the design doc `docs/design/2026-08-21-rsdns-speed.md`.
#[derive(Debug, Clone, Deserialize)]
pub struct SpeedConfig {
    /// Master switch; `false` (default) disables latency sorting entirely.
    #[serde(default)]
    pub enable: bool,
    /// Probe type; currently only `"syn"` (default).
    #[serde(default = "default_speed_type")]
    pub r#type: String,
    /// Probe destination port (default 443).
    #[serde(default = "default_speed_port")]
    pub port: u16,
    /// Address family to sort: `"ANY"` (default) / `"A"` / `"AAAA"`.
    #[serde(default = "default_speed_family")]
    pub family: String,
    /// Per-IP probe timeout: bare number = seconds, optional `ms`/`s`/`m`
    /// suffix (default `"1s"`).
    #[serde(default = "default_speed_timeout")]
    pub timeout: String,
}

fn default_speed_type() -> String {
    "syn".into()
}

fn default_speed_port() -> u16 {
    443
}

fn default_speed_family() -> String {
    "ANY".into()
}

fn default_speed_timeout() -> String {
    "1s".into()
}

impl Default for SpeedConfig {
    fn default() -> Self {
        Self {
            enable: false,
            r#type: default_speed_type(),
            port: default_speed_port(),
            family: default_speed_family(),
            timeout: default_speed_timeout(),
        }
    }
}

/// Parses a duration string (`"500ms"`, `"2s"`, `"1m"`, bare seconds) into
/// [`std::time::Duration`].  Used by the speed plugin's `timeout`.
pub fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1_000_000u64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000_000_000u64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000_000_000u64)
    } else {
        (s, 1_000_000_000u64)
    };
    let n: u64 = num.trim().parse().ok()?;
    if n == 0 {
        return None;
    }
    Some(std::time::Duration::from_nanos(n.saturating_mul(mult)))
}

/// A single DNS routing rule.
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    /// Match target: empty/missing/`*` = match all, `group:{name}`,
    /// `{a.com,b.com}` (inline set), or a `{N}.{domain}` placeholder
    /// template (e.g. `{1}.example.com`; `{N}` captures a query label and
    /// can be reused in actions like `cname.target`).
    /// Parsed at build time into a `MatchTarget`; invalid syntax is a config error.
    #[serde(default, alias = "r#match")]
    pub r#match: Option<String>,
    /// Optional query-type filter (`"A"`, `"AAAA"`, `"ANY"`, …).
    #[serde(default)]
    pub qtype: Option<String>,
    /// Action to take when this rule matches.
    pub action: RuleActionConfig,
}

/// What happens when a rule matches.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RuleActionConfig {
    /// Return NXDomain or a poison record (0.0.0.0 / ::).
    #[serde(rename = "block")]
    Block {
        #[serde(default = "default_block_response")]
        response: BlockResponse,
    },
    /// Rewrite the query to a CNAME target, recursively resolve, return the
    /// target's IP along with a synthetic CNAME record.
    #[serde(rename = "cname")]
    Cname {
        /// Canonical name target.
        target: String,
        /// Optional TTL override for the CNAME and resolved records.
        ttl: Option<u32>,
        /// Upstream pool name to resolve the target.
        upstream: String,
        /// Refuse these query types before resolving (e.g. ["A", "AAAA"]).
        #[serde(default)]
        deny_qtypes: Vec<String>,
    },
    /// Forward the query to a named upstream pool.
    ///
    /// Cache policy is no longer expressed here — it lives on the groups
    /// plugin (`skip_cache`) and the chain context (`ctx.skip_cache`).
    #[serde(rename = "forward")]
    Forward {
        /// `upstream` pool name (must exist in `[upstreams]`).
        #[serde(default)]
        upstream: String,
        /// If set, rewrite the response TTL to this value.
        ttl: Option<u32>,
        /// Cap the number of answer records returned to the client
        /// (default 5; `0` = no limit).  Truncation happens on the final
        /// response and the cached copy.
        #[serde(default)]
        max_answers: Option<usize>,
        /// Refuse these query types before forwarding upstream (e.g. ["A", "AAAA"]).
        #[serde(default)]
        deny_qtypes: Vec<String>,
        /// When the upstream response's first answer is a CNAME, actively
        /// resolve its target (same upstream, same qtype).  An A/AAAA result
        /// replaces the CNAME (owner rewritten to the queried name); an empty
        /// result drops it and continues with the next answer; a CNAME result
        /// keeps the original response untouched (no further chaining).
        #[serde(default)]
        resolve_cname: bool,
    },
    /// Rewrite the query with a synthesized IPv4 A answer (no upstream
    /// query).  `target` is a dotted-quad IPv4 (`10.10.0.0`) or a
    /// placeholder template (`{1}.32.0.2`): each `{N}` is filled from the
    /// matched rule's capture, so a query like `foo.32.0.2.example.com`
    /// (match `{1}.{2}.example.com`) yields A `foo.32.0.2`.
    #[serde(rename = "rewrite")]
    Rewrite {
        /// IPv4 template: literal dotted-quad, or `{N}` placeholders
        /// substituted from the match captures (each capture becomes one
        /// dotted-quad octet).  Invalid after substitution → SERVFAIL.
        target: String,
        /// Optional TTL override for the synthesized A record (default 300).
        ttl: Option<u32>,
    },
}

/// Block response variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    Nxdomain,
    Poison,
}

fn default_block_response() -> BlockResponse {
    BlockResponse::Nxdomain
}

/// Query log configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// Format template with placeholders: `{type}`, `{name}`, `{proto}`, `{remote}`,
    /// `{action}`, `{port}`, `{size}`, `{duration}`, `{rcode}`.
    /// Default: `"{remote}:{port} {name} [{type}] {rcode} {duration}"`
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "{remote} {name} \"{type}\" [{answers}] \"{action}\" {duration}s".into()
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            format: default_format(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_array_config() {
        let yaml = r#"
binds:
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"
groups:
  - name: ad
    domains:
      - file:///etc/rsdns/ad.txt
      - doubleclick.net
    skip_cache: true
  - name: intranet
    domains: [corp.internal, lan]
upstreams:
  - name: default
    mode: serial
    servers:
      - address: 223.5.5.5
      - address: tls://dot.pub
        server_name: dns.alidns.com
        pool:
          idle_timeout: 30
          dns_timeout: 3
          prefer_family: ipv4
  - name: overseas
    mode: parallel
    servers:
      - address: tls://8.8.8.8
  - name: cdn
    mode: round_robin
    cooldown: "1m:10:10s"
    servers:
      - address: 223.5.5.5
cache:
  size: 4096
hosts:
  - "127.0.0.1 localhost"
rules:
  - match: ""
    action: { type: forward, upstream: default }
metrics:
  bind: "0.0.0.0:9153"
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.binds.len(), 2);
        assert_eq!(config.binds[0].address, "0.0.0.0:53");
        assert_eq!(config.binds[1].address, "tcp://0.0.0.0:53");
        assert_eq!(config.groups.len(), 2);
        assert_eq!(config.groups[0].name, "ad");
        assert!(config.groups[0].skip_cache);
        assert_eq!(config.groups[1].name, "intranet");
        assert_eq!(config.upstreams.len(), 3);
        assert_eq!(config.upstreams[0].name, "default");
        assert_eq!(config.upstreams[0].mode, crate::upstream::config::QueryModeConfig::Serial);
        assert_eq!(config.upstreams[1].mode, crate::upstream::config::QueryModeConfig::Parallel);
        assert_eq!(config.upstreams[2].mode, crate::upstream::config::QueryModeConfig::RoundRobin);
        assert_eq!(config.upstreams[2].cooldown.as_deref(), Some("1m:10:10s"),);
        assert_eq!(config.upstreams[0].servers.len(), 2);
        // Plugin sections land in plugin_sections
        assert!(config.plugin_sections.contains_key("cache"));
        assert!(config.plugin_sections.contains_key("hosts"));
        assert!(config.plugin_sections.contains_key("rules"));
        assert!(config.plugin_sections.contains_key("metrics"));
    }

    #[test]
    fn test_forward_resolve_cname_parse() {
        let yaml = r#"
rules:
  - match: ""
    action: { type: forward, upstream: default, resolve_cname: true }
  - match: ""
    action: { type: forward, upstream: default }
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        let raw = config.plugin_sections.get("rules").cloned().unwrap();
        let configs: Vec<RuleConfig> = serde_yaml::from_value(raw).unwrap();
        assert_eq!(configs.len(), 2);
        match &configs[0].action {
            RuleActionConfig::Forward { resolve_cname, .. } => assert!(*resolve_cname),
            other => panic!("expected Forward, got {other:?}"),
        }
        match &configs[1].action {
            RuleActionConfig::Forward { resolve_cname, .. } => assert!(!*resolve_cname, "default must be false"),
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn test_unknown_top_level_keys_go_to_plugin_sections() {
        let yaml = r#"
binds:
  - address: "0.0.0.0:53"
groups:
  - name: ad
    domains: [doubleclick.net]
upstreams:
  - name: default
    servers: [{ address: 223.5.5.5 }]
some_future_plugin:
  foo: bar
"#;
        let config = Config::from_yaml_str(yaml).expect("parse failed");
        assert_eq!(config.binds.len(), 1);
        assert_eq!(config.plugin_sections.len(), 1);
        assert!(config.plugin_sections.contains_key("some_future_plugin"));
    }

    #[test]
    fn test_pool_config_parse() {
        use crate::upstream::config::RawPoolConfig;
        use crate::upstream::pool::PreferFamily;

        let pc = RawPoolConfig {
            idle_timeout: Some(8),
            connect_timeout: Some(4),
            dns_timeout: Some(3),
            prefer_family: Some("ipv4".into()),
        };
        assert_eq!(pc.prefer_family(), PreferFamily::Ipv4);
        let pool = pc.into_pool_config();
        assert_eq!(pool.idle_timeout, std::time::Duration::from_secs(8));
        assert_eq!(pool.connect_timeout, std::time::Duration::from_secs(4));
        assert_eq!(pool.dns_timeout, std::time::Duration::from_secs(3));
        assert_eq!(RawPoolConfig::default().prefer_family(), PreferFamily::Any);
    }

    #[test]
    fn test_pool_config_defaults() {
        use crate::upstream::config::RawPoolConfig;

        let pool = RawPoolConfig::default().into_pool_config();
        let defaults = crate::upstream::pool::PoolConfig::default();
        assert_eq!(pool.idle_timeout, defaults.idle_timeout);
        assert_eq!(pool.connect_timeout, defaults.connect_timeout);
        assert_eq!(pool.dns_timeout, defaults.dns_timeout);
    }
}
