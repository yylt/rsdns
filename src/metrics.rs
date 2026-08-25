//! Lightweight Prometheus text-format metrics registry.
//!
//! Chosen over the `prometheus` crate to keep the dependency tree minimal
//! (the crate is not vendored in the offline registry).  The surface is
//! intentionally small — counters and gauges with optional label vectors —
//! and renders the standard Prometheus text exposition format
//! (https://prometheus.io/docs/instrumenting/exposition_formats/).
//!
//! All metric names are expected to follow `rsdns_<plugin>_<name>`.

use ahash::AHashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn fmt_labels(names: &[String], values: &[String]) -> String {
    let mut out = String::new();
    for (i, (n, v)) in names.iter().zip(values).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{}=\"{}\"", n, escape_label_value(v));
    }
    out
}

fn validate_metric_name(name: &str) {
    assert!(
        !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "invalid metric name: {name:?}"
    );
}

/// A labeled counter (monotonic, increment-only).
///
/// `with_label_values` returns a handle that carries its label values, so
/// `inc()` writes to the correct time series.
#[derive(Clone)]
pub struct Counter {
    series: Arc<Mutex<Series>>,
    labels: Vec<String>,
}

impl Counter {
    fn new(series: Arc<Mutex<Series>>, labels: Vec<String>) -> Self {
        Self { series, labels }
    }

    pub fn inc(&self) {
        self.inc_by(1);
    }

    pub fn inc_by(&self, v: u64) {
        let mut series = self.series.lock().unwrap();
        series.update(&self.labels, v as i64);
    }

    pub fn with_label_values(&self, values: &[&str]) -> Counter {
        Counter::new(self.series.clone(), values.iter().map(|s| s.to_string()).collect())
    }
}

/// A labeled gauge (settable up/down).
#[derive(Clone)]
pub struct Gauge {
    series: Arc<Mutex<Series>>,
    labels: Vec<String>,
}

impl Gauge {
    fn new(series: Arc<Mutex<Series>>, labels: Vec<String>) -> Self {
        Self { series, labels }
    }

    pub fn set(&self, v: u64) {
        let mut series = self.series.lock().unwrap();
        series.set(&self.labels, v);
    }

    pub fn with_label_values(&self, values: &[&str]) -> Gauge {
        Gauge::new(self.series.clone(), values.iter().map(|s| s.to_string()).collect())
    }
}

/// One metric family's label-name list plus its per-label-combination values.
#[derive(Default)]
struct Series {
    label_names: Vec<String>,
    values: AHashMap<Vec<String>, u64>,
}

impl Series {
    fn update(&mut self, labels: &[String], delta: i64) {
        let entry = self.values.entry(labels.to_vec()).or_insert(0);
        if delta < 0 {
            *entry = entry.saturating_sub(delta.unsigned_abs());
        } else {
            *entry = entry.saturating_add(delta as u64);
        }
    }

    /// Overwrites the value for `labels` (gauge semantics).
    fn set(&mut self, labels: &[String], value: u64) {
        self.values.insert(labels.to_vec(), value);
    }
}

/// A metric family entry: (name, help, series).
type CounterFamily = (String, String, Arc<Mutex<Series>>);
type GaugeFamily = (String, String, Arc<Mutex<Series>>);

/// The metric registry: owns all registered metric families and renders
/// them on demand.  Cheap to clone (all state is behind `Arc`), so plugins
/// can hold a copy for their hot path.
#[derive(Clone, Default)]
pub struct MetricsRegistry {
    counters: Arc<Mutex<Vec<CounterFamily>>>, // (name, help, series)
    gauges: Arc<Mutex<Vec<GaugeFamily>>>,
}

fn assert_unique<T>(list: &Mutex<Vec<T>>, name: &str, get_name: impl Fn(&T) -> &str) {
    let list = list.lock().unwrap();
    for item in list.iter() {
        assert_ne!(get_name(item), name, "metric already registered: {name}");
    }
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a counter family.  `label_names` is empty for a plain counter.
    pub fn counter(&self, name: &str, help: &str, label_names: &[&str]) -> Counter {
        validate_metric_name(name);
        assert_unique(&self.counters, name, |(n, _, _)| n);
        let series = Arc::new(Mutex::new(Series {
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            values: AHashMap::new(),
        }));
        self.counters
            .lock()
            .unwrap()
            .push((name.to_string(), help.to_string(), series.clone()));
        Counter::new(series, Vec::new())
    }

    /// Registers a gauge family.
    pub fn gauge(&self, name: &str, help: &str, label_names: &[&str]) -> Gauge {
        validate_metric_name(name);
        assert_unique(&self.gauges, name, |(n, _, _)| n);
        let series = Arc::new(Mutex::new(Series {
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            values: AHashMap::new(),
        }));
        self.gauges
            .lock()
            .unwrap()
            .push((name.to_string(), help.to_string(), series.clone()));
        Gauge::new(series, Vec::new())
    }

    /// Renders the whole registry in Prometheus text format.
    pub fn encode_text(&self) -> String {
        let mut out = String::new();
        {
            let counters = self.counters.lock().unwrap();
            for (name, help, series) in counters.iter() {
                let _ = writeln!(out, "# HELP {} {}", name, help);
                let _ = writeln!(out, "# TYPE {} counter", name);
                let series = series.lock().unwrap();
                for (labels, value) in series.values.iter() {
                    emit_series(&mut out, name, &series.label_names, labels, *value);
                }
            }
        }
        {
            let gauges = self.gauges.lock().unwrap();
            for (name, help, series) in gauges.iter() {
                let _ = writeln!(out, "# HELP {} {}", name, help);
                let _ = writeln!(out, "# TYPE {} gauge", name);
                let series = series.lock().unwrap();
                for (labels, value) in series.values.iter() {
                    emit_series(&mut out, name, &series.label_names, labels, *value);
                }
            }
        }
        out
    }
}

fn emit_series(out: &mut String, name: &str, label_names: &[String], labels: &[String], value: u64) {
    if label_names.is_empty() {
        let _ = writeln!(out, "{} {}", name, value);
    } else {
        let _ = writeln!(out, "{}{{{}}} {}", name, fmt_labels(label_names, labels), value);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_plain() {
        let r = MetricsRegistry::default();
        let c = r.counter("rsdns_test_queries_total", "queries", &[]);
        c.inc();
        c.inc_by(2);
        let text = r.encode_text();
        assert!(text.contains("# TYPE rsdns_test_queries_total counter"));
        assert!(text.contains("rsdns_test_queries_total 3\n"), "got:\n{text}");
    }

    #[test]
    fn test_counter_labeled() {
        let r = MetricsRegistry::default();
        let c = r.counter("rsdns_test_rcode_total", "rcodes", &["rcode"]);
        c.with_label_values(&["NOERROR"]).inc();
        c.with_label_values(&["NOERROR"]).inc();
        c.with_label_values(&["NXDOMAIN"]).inc();
        let text = r.encode_text();
        assert!(text.contains("rsdns_test_rcode_total{rcode=\"NOERROR\"} 2\n"), "got:\n{text}");
        assert!(text.contains("rsdns_test_rcode_total{rcode=\"NXDOMAIN\"} 1\n"), "got:\n{text}");
    }

    #[test]
    fn test_gauge_set_and_add() {
        let r = MetricsRegistry::default();
        let g = r.gauge("rsdns_test_entries", "entries", &["group"]);
        g.with_label_values(&["ad"]).set(5);
        g.with_label_values(&["ad"]).set(4);
        let text = r.encode_text();
        assert!(text.contains("rsdns_test_entries{group=\"ad\"} 4\n"), "got:\n{text}");
    }

    #[test]
    fn test_label_value_escaping() {
        let r = MetricsRegistry::default();
        let c = r.counter("rsdns_test_esc_total", "esc", &["proto"]);
        c.with_label_values(&["udp\"tcp"]).inc();
        let text = r.encode_text();
        assert!(text.contains("rsdns_test_esc_total{proto=\"udp\\\"tcp\"} 1\n"), "got:\n{text}");
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn test_duplicate_name_panics() {
        let r = MetricsRegistry::default();
        r.counter("rsdns_test_dup_total", "a", &[]);
        r.counter("rsdns_test_dup_total", "b", &[]);
    }
}
