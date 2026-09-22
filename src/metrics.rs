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

/// DNS response code short names, used as metric label values.  hickory's
/// `ResponseCode` `Display`/`to_str` yields verbose phrases ("No Error",
/// "Server Failure"); Prometheus label values are better kept terse.
pub fn rcode_label(code: u16) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        16 => "BADVERS",
        17 => "BADKEY",
        18 => "BADTIME",
        19 => "BADMODE",
        20 => "BADNAME",
        21 => "BADALG",
        22 => "BADTRUNC",
        23 => "BADCOOKIE",
        _ => "OTHER",
    }
}

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

/// Default histogram bucket boundaries (seconds), tuned for DNS latency.
pub const DEFAULT_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

/// A labeled histogram (observations bucketed by cumulative count + sum).
#[derive(Clone)]
pub struct Histogram {
    series: Arc<Mutex<HistogramSeries>>,
    labels: Vec<String>,
}

impl Histogram {
    fn new(series: Arc<Mutex<HistogramSeries>>, labels: Vec<String>) -> Self {
        Self { series, labels }
    }

    /// Records an observation (e.g. a latency in seconds).
    pub fn observe(&self, value: f64) {
        let mut series = self.series.lock().unwrap();
        series.observe(&self.labels, value);
    }

    pub fn with_label_values(&self, values: &[&str]) -> Histogram {
        Histogram::new(self.series.clone(), values.iter().map(|s| s.to_string()).collect())
    }
}

/// Per-label-combination histogram state: sum, total count, and per-bucket counts.
#[derive(Default)]
struct HistogramSeries {
    label_names: Vec<String>,
    buckets: Vec<f64>,
    values: AHashMap<Vec<String>, HistogramValue>,
}

#[derive(Default, Clone)]
struct HistogramValue {
    sum: f64,
    count: u64,
    /// One entry per `buckets` boundary (cumulative count), plus the implicit
    /// `+Inf` bucket which equals `count`.
    bucket_counts: Vec<u64>,
}

impl HistogramSeries {
    fn observe(&mut self, labels: &[String], value: f64) {
        let v = self.values.entry(labels.to_vec()).or_insert_with(|| HistogramValue {
            bucket_counts: vec![0; self.buckets.len()],
            ..Default::default()
        });
        v.sum += value;
        v.count += 1;
        for (i, upper) in self.buckets.iter().enumerate() {
            if value <= *upper {
                v.bucket_counts[i] += 1;
            }
        }
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
type HistogramFamily = (String, String, Arc<Mutex<HistogramSeries>>);

/// The metric registry: owns all registered metric families and renders
/// them on demand.  Cheap to clone (all state is behind `Arc`), so plugins
/// can hold a copy for their hot path.
#[derive(Clone, Default)]
pub struct MetricsRegistry {
    counters: Arc<Mutex<Vec<CounterFamily>>>, // (name, help, series)
    gauges: Arc<Mutex<Vec<GaugeFamily>>>,
    histograms: Arc<Mutex<Vec<HistogramFamily>>>,
}

fn assert_unique(name: &str) {
    let exists = REGISTERED_NAMES.with(|set| set.borrow().contains(name));
    assert!(!exists, "metric already registered: {name}");
}

thread_local! {
    static REGISTERED_NAMES: std::cell::RefCell<std::collections::HashSet<String>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a counter family.  `label_names` is empty for a plain counter.
    pub fn counter(&self, name: &str, help: &str, label_names: &[&str]) -> Counter {
        validate_metric_name(name);
        assert_unique(name);
        let series = Arc::new(Mutex::new(Series {
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            values: AHashMap::new(),
        }));
        REGISTERED_NAMES.with(|set| set.borrow_mut().insert(name.to_string()));
        self.counters
            .lock()
            .unwrap()
            .push((name.to_string(), help.to_string(), series.clone()));
        Counter::new(series, Vec::new())
    }

    /// Registers a gauge family.
    pub fn gauge(&self, name: &str, help: &str, label_names: &[&str]) -> Gauge {
        validate_metric_name(name);
        assert_unique(name);
        let series = Arc::new(Mutex::new(Series {
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            values: AHashMap::new(),
        }));
        REGISTERED_NAMES.with(|set| set.borrow_mut().insert(name.to_string()));
        self.gauges
            .lock()
            .unwrap()
            .push((name.to_string(), help.to_string(), series.clone()));
        Gauge::new(series, Vec::new())
    }

    /// Registers a histogram family with explicit bucket boundaries.
    pub fn histogram(&self, name: &str, help: &str, label_names: &[&str], buckets: &[f64]) -> Histogram {
        validate_metric_name(name);
        assert_unique(name);
        let mut sorted = buckets.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let series = Arc::new(Mutex::new(HistogramSeries {
            label_names: label_names.iter().map(|s| s.to_string()).collect(),
            buckets: sorted,
            values: AHashMap::new(),
        }));
        REGISTERED_NAMES.with(|set| set.borrow_mut().insert(name.to_string()));
        self.histograms
            .lock()
            .unwrap()
            .push((name.to_string(), help.to_string(), series.clone()));
        Histogram::new(series, Vec::new())
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
        {
            let histograms = self.histograms.lock().unwrap();
            for (name, help, series) in histograms.iter() {
                let _ = writeln!(out, "# HELP {} {}", name, help);
                let _ = writeln!(out, "# TYPE {} histogram", name);
                let series = series.lock().unwrap();
                for (labels, value) in series.values.iter() {
                    emit_histogram(&mut out, name, &series.label_names, labels, value, &series.buckets);
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

fn emit_histogram(
    out: &mut String,
    name: &str,
    label_names: &[String],
    labels: &[String],
    value: &HistogramValue,
    buckets: &[f64],
) {
    // `_bucket` lines: one per explicit boundary (cumulative, le="X"), plus the
    // implicit +Inf bucket carrying the total count.
    for (i, upper) in buckets.iter().enumerate() {
        let le = format!("{upper}");
        let bucket_labels = append_label(label_names, labels, "le", &le);
        let _ = writeln!(out, "{}_bucket{{{}}} {}", name, bucket_labels, value.bucket_counts[i]);
    }
    let inf_labels = append_label(label_names, labels, "le", "+Inf");
    let _ = writeln!(out, "{}_bucket{{{}}} {}", name, inf_labels, value.count);
    let sum_labels = fmt_labels(label_names, labels);
    if label_names.is_empty() {
        let _ = writeln!(out, "{}_sum {}", name, value.sum);
        let _ = writeln!(out, "{}_count {}", name, value.count);
    } else {
        let _ = writeln!(out, "{}_sum{{{}}} {}", name, sum_labels, value.sum);
        let _ = writeln!(out, "{}_count{{{}}} {}", name, sum_labels, value.count);
    }
}

/// Appends a single `k="v"` label to an existing label list, returning the
/// full `k1="v1",k2="v2",k="v"` string.
fn append_label(names: &[String], values: &[String], extra_name: &str, extra_value: &str) -> String {
    let mut out = String::new();
    for (i, (n, v)) in names.iter().zip(values).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{}=\"{}\"", n, escape_label_value(v));
    }
    if !out.is_empty() {
        out.push(',');
    }
    let _ = write!(out, "{}=\"{}\"", extra_name, escape_label_value(extra_value));
    out
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

    #[test]
    fn test_histogram_observes_buckets() {
        let r = MetricsRegistry::default();
        let h = r.histogram("rsdns_test_latency_seconds", "latency", &["proto"], &[0.01, 0.1, 1.0]);
        // 0.005s -> le=0.01 only; 0.05s -> le=0.01 + le=0.1; 2.0s -> all + Inf.
        h.with_label_values(&["udp"]).observe(0.005);
        h.with_label_values(&["udp"]).observe(0.05);
        h.with_label_values(&["udp"]).observe(2.0);
        let text = r.encode_text();
        assert!(text.contains("# TYPE rsdns_test_latency_seconds histogram"));
        // Cumulative bucket counts: le=0.01=1, le=0.1=2, le=+Inf=3.
        assert!(
            text.contains("rsdns_test_latency_seconds_bucket{proto=\"udp\",le=\"0.01\"} 1\n"),
            "got:\n{text}"
        );
        assert!(
            text.contains("rsdns_test_latency_seconds_bucket{proto=\"udp\",le=\"0.1\"} 2\n"),
            "got:\n{text}"
        );
        assert!(
            text.contains("rsdns_test_latency_seconds_bucket{proto=\"udp\",le=\"+Inf\"} 3\n"),
            "got:\n{text}"
        );
        assert!(
            text.contains("rsdns_test_latency_seconds_sum{proto=\"udp\"} 2.0"), // 0.005+0.05+2.0 ≈ 2.055
            "got:\n{text}"
        );
        assert!(
            text.contains("rsdns_test_latency_seconds_count{proto=\"udp\"} 3\n"),
            "got:\n{text}"
        );
    }

    #[test]
    #[should_panic(expected = "already registered")]
    fn test_cross_type_duplicate_name_panics() {
        let r = MetricsRegistry::default();
        r.counter("rsdns_test_cross_total", "a", &[]);
        r.gauge("rsdns_test_cross_total", "b", &[]);
    }
}
