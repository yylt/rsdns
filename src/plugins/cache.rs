//! `cache` stage — cache-first query cache (core `DnsCache` + pipeline
//! stage).
//!
//! Pipeline position: after `groups`, before `rules`.  The stage splits
//! into two calls driven by the server:
//!
//! - [`Cache::lookup`]: `ctx.skip_cache` → `Continue`; fresh hit → build
//!   response and `Respond` (short-circuits before rules); miss →
//!   `Continue`.  Expiry is handled by moka's per-entry TTL: expired
//!   entries are excluded on read and evicted in the background, so a hit
//!   is always fresh — there is no stale serving.
//! - [`Cache::write_back`]: after the rules stage fills `ctx.response`, if
//!   the response came from upstream (`ctx.action` starts with "forward")
//!   and `!ctx.skip_cache`, it is written to cache.

use ahash::RandomState;
use hickory_proto::rr::rdata::svcb::SVCB;
use hickory_proto::rr::RecordType;
use log::warn;
use moka::future::Cache as MokaCache;
use moka::Expiry;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{CacheConfig, Config};
use crate::metrics::{Counter, Gauge, MetricsRegistry};
use crate::plugins::util::{build_response_from_cache, build_servfail, cache_upstream_response};
use crate::query::{QueryContext, Step};

// ---------------------------------------------------------------------------
// Cache core
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub name: String,
    pub qtype: RecordType,
}

impl CacheKey {
    pub fn new(name: impl Into<String>, qtype: RecordType) -> Self {
        Self {
            name: name.into(),
            qtype,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CacheRecord {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Https(SVCB),
    NxDomain,
    /// Empty NOERROR answer for a query type that has no records (NoData).
    NoData,
}

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Arc<[CacheRecord]>,
    /// Insertion time; `expires_at = created_at + entry TTL`.  Used only to
    /// compute the remaining TTL for responses — expiry/eviction is owned
    /// by moka's per-entry TTL.
    pub created_at: Instant,
    pub ttl: u32,
}

impl CacheEntry {
    pub fn action_name(&self) -> &'static str {
        if self.records.is_empty() {
            return "forward-cache-fail";
        }
        match &self.records[0] {
            CacheRecord::NxDomain => "forward-cache-nxdomain",
            CacheRecord::NoData => "forward-cache-nodata",
            _ => "forward-cache",
        }
    }

    pub fn remaining_ttl(&self, keep_ttl: bool) -> u32 {
        if keep_ttl {
            return self.ttl;
        }
        let expires_at = self.created_at + Duration::from_secs(self.ttl as u64);
        let now = Instant::now();
        if now >= expires_at {
            return 0;
        }
        (expires_at - now).as_secs() as u32
    }
}

/// Per-entry TTL policy for moka.  Computes each entry's lifetime from its
/// `CacheEntry.ttl` (clamped by `min_ttl`/`max_ttl` unless `keep_ttl`).
/// `expire_after_update` is overridden so a re-insert restarts the full TTL
/// (the trait default keeps the previous remaining duration instead).
struct TtlExpiry {
    min_ttl: Duration,
    max_ttl: Duration,
    keep_ttl: bool,
}

impl TtlExpiry {
    fn duration_for(&self, value: &CacheEntry) -> Duration {
        if self.keep_ttl {
            Duration::from_secs(value.ttl as u64)
        } else {
            Duration::from_secs(value.ttl as u64).clamp(self.min_ttl, self.max_ttl)
        }
    }
}

impl Expiry<CacheKey, CacheEntry> for TtlExpiry {
    fn expire_after_create(&self, _key: &CacheKey, value: &CacheEntry, _created_at: Instant) -> Option<Duration> {
        Some(self.duration_for(value))
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &CacheEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(self.duration_for(value))
    }
}

pub enum CacheResult {
    Fresh(CacheEntry),
    Miss,
}

/// Per-operation cache metrics.  Created by the cache stage; attached to
/// the [`DnsCache`] via [`DnsCache::attach_metrics`].
#[derive(Clone, Default)]
pub struct CacheMetrics {
    pub lookup_total: Option<Counter>,
    pub entries: Option<Gauge>,
}

impl CacheMetrics {
    /// Registers all cache metrics on `registry`.
    pub fn register(registry: &MetricsRegistry) -> Self {
        Self {
            lookup_total: Some(registry.counter("rsdns_cache_lookup_total", "Cache lookups", &["result"])),
            entries: Some(registry.gauge("rsdns_cache_entries", "Current cache entries", &[])),
        }
    }
}

#[derive(Clone)]
pub struct DnsCache {
    inner: MokaCache<CacheKey, CacheEntry, RandomState>,
    pub keep_ttl: bool,
    metrics: Arc<std::sync::OnceLock<CacheMetrics>>,
}

impl DnsCache {
    /// Builds a cache with a shared metrics slot (filled in by the cache
    /// stage's `register_metrics`).
    pub fn new_metric(size: usize, min_ttl: u32, max_ttl: u32, keep_ttl: bool) -> Self {
        let metrics: Arc<std::sync::OnceLock<CacheMetrics>> = Arc::new(std::sync::OnceLock::new());
        let min_ttl = Duration::from_secs(min_ttl as u64);
        let max_ttl = Duration::from_secs(max_ttl as u64);
        let cache = MokaCache::builder()
            .max_capacity(size as u64)
            .expire_after(TtlExpiry {
                min_ttl,
                max_ttl,
                keep_ttl,
            })
            .build_with_hasher(RandomState::new());
        Self {
            inner: cache,
            keep_ttl,
            metrics,
        }
    }

    /// Attaches the metrics collected by the cache stage.
    pub fn attach_metrics(&self, metrics: CacheMetrics) {
        let _ = self.metrics.set(metrics);
        if let Some(m) = self.metrics.get() {
            if let Some(g) = &m.entries {
                g.set(self.inner.entry_count());
            }
        }
    }

    pub async fn get_cached(&self, key: &CacheKey) -> CacheResult {
        // moka excludes expired entries on read, so a hit is always fresh.
        let result = if let Some(entry) = self.inner.get(key).await {
            CacheResult::Fresh(entry)
        } else {
            CacheResult::Miss
        };

        if let Some(m) = self.metrics.get() {
            let label = match &result {
                CacheResult::Fresh(_) => "fresh",
                CacheResult::Miss => "miss",
            };
            if let Some(c) = &m.lookup_total {
                c.with_label_values(&[label]).inc();
            }
        }
        result
    }

    pub async fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32) {
        let entry = CacheEntry {
            records: records.into(),
            created_at: Instant::now(),
            ttl,
        };
        self.inner.insert(key, entry).await;
        if let Some(m) = self.metrics.get() {
            if let Some(g) = &m.entries {
                g.set(self.inner.entry_count());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// Builds the cache stage from the `cache:` config section (or the default).
pub fn init(config: &Config, registry: &MetricsRegistry) -> Cache {
    let raw = config.plugin_sections.get("cache").cloned().unwrap_or_default();
    let cfg: CacheConfig = serde_yaml::from_value(raw).unwrap_or_default();
    let cache = DnsCache::new_metric(
        cfg.size.unwrap_or(4096),
        cfg.min_ttl.unwrap_or(60),
        cfg.max_ttl.unwrap_or(3600),
        cfg.keep_ttl.unwrap_or(false),
    );
    let metrics = CacheMetrics::register(registry);
    cache.attach_metrics(metrics);
    Cache { cache }
}

/// The cache stage.
pub struct Cache {
    cache: DnsCache,
}

impl Cache {
    /// Cache-first lookup.  Returns `Respond` when a fresh cached entry
    /// answers; `Continue` on miss.  Expired entries are excluded by moka
    /// on read, so there is no stale serving.
    pub async fn lookup(&self, ctx: &mut QueryContext) -> Step {
        if ctx.skip_cache {
            return Step::Continue;
        }

        match self.cache.get_cached(&ctx.key).await {
            CacheResult::Fresh(entry) => {
                // 缓存命中：答案已在写回前按测速排序，跳过 speed 阶段重复探测。
                ctx.skip_speed = true;
                let action = entry.action_name();
                match build_response_from_cache(&ctx.msg, &entry, self.cache.keep_ttl) {
                    Ok(resp) => {
                        ctx.response = Some(resp);
                        ctx.action = action.into();
                        Step::Respond
                    }
                    Err(e) => {
                        warn!("building cache response for {} failed: {}", ctx.name(), e);
                        ctx.response = Some(build_servfail(&ctx.msg));
                        ctx.action = action.into();
                        Step::Respond
                    }
                }
            }
            CacheResult::Miss => Step::Continue,
        }
    }

    /// Writes an upstream response back into the cache (positive records +
    /// NXDOMAIN negative), unless `ctx.skip_cache` was set or the response
    /// did not come from upstream.
    pub async fn write_back(&self, ctx: &QueryContext) {
        if ctx.skip_cache {
            return;
        }
        if let Some(response) = ctx.response.as_ref() {
            if ctx.action.starts_with("forward") {
                // rules 的 ttl 覆盖已应用在 response 上。
                let rewrite_ttl = None;
                cache_upstream_response(&self.cache, &ctx.key, response, rewrite_ttl).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_fresh() {
        let cache = DnsCache::new_metric(10, 60, 3600, false);
        let key = CacheKey::new("example.com", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records.clone(), 300).await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_auto_expire() {
        // 每条目 TTL 由 moka 自动过期：短 TTL 写入后，超过 TTL 即 miss。
        let cache = DnsCache::new_metric(10, 0, 1, false);
        let key = CacheKey::new("expire.com", RecordType::A);
        cache
            .put(key.clone(), vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))], 1)
            .await;

        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_put_resets_ttl() {
        // 同 key 重新 put 后 TTL 从新值重新计时（expire_after_update 覆盖生效）。
        let cache = DnsCache::new_metric(10, 0, 3600, false);
        let key = CacheKey::new("refresh.com", RecordType::A);
        cache
            .put(key.clone(), vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))], 1)
            .await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        cache
            .put(key.clone(), vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))], 1)
            .await;
        // 重新插入后仍应命中，且剩余 TTL 接近 1s（而非只剩 0.5s）。
        tokio::time::sleep(Duration::from_millis(600)).await;
        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            assert_eq!(entry.remaining_ttl(false), 0, "remaining TTL after 600ms of 1s TTL");
        } else {
            panic!("expected Fresh after re-insert");
        }
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::new_metric(10, 60, 3600, false);
        let key = CacheKey::new("miss.com", RecordType::A);
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_cache_empty_entry() {
        let cache = DnsCache::new_metric(10, 60, 3600, false);
        let key = CacheKey::new("block.test", RecordType::A);
        cache.put(key.clone(), vec![], 300).await;
        let result = cache.get_cached(&key).await;
        assert!(matches!(result, CacheResult::Fresh(_)));
    }

    #[tokio::test]
    async fn test_cache_nodata_action_name() {
        let cache = DnsCache::new_metric(10, 60, 3600, false);
        let key = CacheKey::new("nodata.test", RecordType::A);
        cache.put(key.clone(), vec![CacheRecord::NoData], 300).await;
        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            assert_eq!(entry.action_name(), "forward-cache-nodata");
        } else {
            panic!("expected Fresh");
        }
    }

    #[tokio::test]
    async fn test_remaining_ttl_decrement() {
        let cache = DnsCache::new_metric(10, 0, 3600, false);
        let key = CacheKey::new("ttl.test", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records, 5).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            let remaining = entry.remaining_ttl(false);
            assert!(remaining < 5, "remaining_ttl should decrement: {}", remaining);
        } else {
            panic!("expected Fresh");
        }
    }

    #[tokio::test]
    async fn test_remaining_ttl_keepttl() {
        let cache = DnsCache::new_metric(10, 0, 3600, true);
        let key = CacheKey::new("keepttl.test", RecordType::A);
        let records = vec![CacheRecord::A(Ipv4Addr::new(1, 2, 3, 4))];
        cache.put(key.clone(), records, 5).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;

        if let CacheResult::Fresh(entry) = cache.get_cached(&key).await {
            let remaining = entry.remaining_ttl(true);
            assert_eq!(remaining, 5, "keep_ttl should return original TTL");
        } else {
            panic!("expected Fresh");
        }
    }
}
