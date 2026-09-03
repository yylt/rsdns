//! jemalloc memory statistics, read via `mallctl`.
//!
//! Exposes the jemalloc `stats.*` counters (allocated / active / resident /
//! mapped, in bytes) as Prometheus gauges.  Compiled and registered only
//! under the `jemalloc` feature; with `mimalloc` or no allocator feature
//! these metrics are absent.
//!
//! `mallctl` is a thread-safe, non-allocating control interface: reads are
//! safe from any thread and never touch the Rust allocation path, so the
//! refresh loop cannot recurse back into the allocator.

#![cfg(feature = "jemalloc")]

use log::warn;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::metrics::{Gauge, MetricsRegistry};

/// A single jemalloc `stats.*` counter, cached as an `AtomicU64`.
///
/// `mallctl` reads must write into a correctly-sized buffer and read the
/// result back through the same (possibly shortened) length, which is not
/// expressible with stable-safe references to `AtomicU64`; the `u64` is
/// therefore accessed through raw pointers.  The caller owns the only
/// reference, so the access is race-free.
struct Stat {
    value: AtomicU64,
}

impl Stat {
    fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// Reads the jemalloc `stats.<name>` counter (bytes) into `value`.
fn read_stat(name: &str, value: &Stat) {
    let name = match CString::new(name) {
        Ok(n) => n,
        Err(_) => return,
    };
    let raw = value.value.as_ptr() as *mut u8;
    let mut len: usize = std::mem::size_of::<u64>();
    // SAFETY: `mallctl` is thread-safe; `raw` points to a valid `u64` sized
    // buffer owned by this process.  On success the counter is stored and
    // published through the atomic.  On failure nothing is written and the
    // previous value is retained.
    let ret = unsafe { tikv_jemalloc_sys::mallctl(name.as_ptr(), raw as *mut _, &mut len, std::ptr::null_mut(), 0) };
    if ret != 0 {
        warn!("mallctl({name:?}) failed: {ret}");
    }
}

/// jemalloc memory gauges, refreshed on a fixed interval.
pub struct JemallocMetrics {
    allocated: Stat,
    active: Stat,
    resident: Stat,
    mapped: Stat,
}

impl JemallocMetrics {
    /// Reads the current `stats.*` values and writes them to the gauges.
    pub fn refresh(&self, g: &JemallocGauges) {
        read_stat("stats.allocated", &self.allocated);
        read_stat("stats.active", &self.active);
        read_stat("stats.resident", &self.resident);
        read_stat("stats.mapped", &self.mapped);
        g.allocated.set(self.allocated.get());
        g.active.set(self.active.get());
        g.resident.set(self.resident.get());
        g.mapped.set(self.mapped.get());
    }
}

/// Gauge handles for the jemalloc metrics.
pub struct JemallocGauges {
    allocated: Gauge,
    active: Gauge,
    resident: Gauge,
    mapped: Gauge,
}

/// Registers the jemalloc memory gauges on `registry`.
pub fn register_metrics(registry: &MetricsRegistry) -> JemallocGauges {
    JemallocGauges {
        allocated: registry.gauge(
            "rsdns_jemalloc_allocated_bytes",
            "Bytes currently allocated by jemalloc (stats.allocated)",
            &[],
        ),
        active: registry.gauge(
            "rsdns_jemalloc_active_bytes",
            "Bytes in active pages managed by jemalloc (stats.active)",
            &[],
        ),
        resident: registry.gauge(
            "rsdns_jemalloc_resident_bytes",
            "Bytes of resident memory mapped by jemalloc (stats.resident)",
            &[],
        ),
        mapped: registry.gauge(
            "rsdns_jemalloc_mapped_bytes",
            "Bytes of virtual address space mapped by jemalloc (stats.mapped)",
            &[],
        ),
    }
}

/// Spawns a task refreshing the jemalloc gauges every `interval`.
pub fn spawn_refresh(registry: MetricsRegistry, interval: Duration) {
    tokio::spawn(async move {
        let gauges = register_metrics(&registry);
        let metrics = JemallocMetrics {
            allocated: Stat::new(),
            active: Stat::new(),
            resident: Stat::new(),
            mapped: Stat::new(),
        };
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            metrics.refresh(&gauges);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_refresh() {
        let registry = MetricsRegistry::default();
        let gauges = register_metrics(&registry);
        let metrics = JemallocMetrics {
            allocated: Stat::new(),
            active: Stat::new(),
            resident: Stat::new(),
            mapped: Stat::new(),
        };
        // 首次 refresh：读一次真实 jemalloc 统计，gauge 应被更新。
        metrics.refresh(&gauges);
        let text = registry.encode_text();
        for name in [
            "rsdns_jemalloc_allocated_bytes",
            "rsdns_jemalloc_active_bytes",
            "rsdns_jemalloc_resident_bytes",
            "rsdns_jemalloc_mapped_bytes",
        ] {
            assert!(text.contains(&format!("# TYPE {name} gauge")), "missing {name}");
            // gauge 行: "<name> <value>"
            let marker = format!("{name} ");
            assert!(text.contains(&marker), "gauge {name} has no value:\n{text}");
        }
    }
}
