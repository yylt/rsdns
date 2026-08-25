//! `logs` stage — outermost query logger.
//!
//! Wraps the whole pipeline: records the query, runs the rest of the
//! pipeline, then renders and writes a log line on unwind unless
//! `ctx.skip_log` was set by a downstream stage.
//!
//! Lines are written directly to stdout with `tokio::io::AsyncWriteExt`
//! (buffered as `bytes::Bytes`); there is no file output and no periodic
//! flush timer.

use bytes::{BufMut, Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

use crate::config::{Config, LogConfig};
use crate::metrics::{Counter, MetricsRegistry};
use crate::query::QueryContext;

/// 查询日志模板中的一个占位符字段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Duration,
    Proto,
    Rcode,
    Name,
    QType,
    Port,
    Size,
    Action,
    Remote,
    Answers,
}

impl Field {
    /// 占位符名 → 字段；未识别的名字返回 `None`，原样保留为字面量。
    fn parse(key: &str) -> Option<Self> {
        Some(match key {
            "duration" => Self::Duration,
            "proto" => Self::Proto,
            "rcode" => Self::Rcode,
            "name" => Self::Name,
            "type" => Self::QType,
            "port" => Self::Port,
            "size" => Self::Size,
            "action" => Self::Action,
            "remote" => Self::Remote,
            "answers" => Self::Answers,
            _ => return None,
        })
    }
}

/// 预编译的模板：字面量段落与字段占位符交替。
#[derive(Debug, Clone)]
pub(crate) struct CompiledTemplate {
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Text(String),
    Field(Field),
}

/// 将用户模板预编译为段落序列，替代每次查询时的模板解析。
fn compile_template(template: &str) -> CompiledTemplate {
    let mut segments = Vec::new();
    let mut rest = template;
    let mut text = String::new();
    loop {
        let Some(start) = rest.find('{') else {
            text.push_str(rest);
            break;
        };
        text.push_str(&rest[..start]);
        rest = &rest[start + 1..];
        if let Some(end) = rest.find('}') {
            match Field::parse(&rest[..end]) {
                Some(field) => {
                    if !text.is_empty() {
                        segments.push(Segment::Text(std::mem::take(&mut text)));
                    }
                    segments.push(Segment::Field(field));
                }
                None => text.push_str(&format!("{{{}}}", &rest[..end])),
            }
            rest = &rest[end + 1..];
        } else {
            text.push('{');
            text.push_str(rest);
            break;
        }
    }
    if !text.is_empty() {
        segments.push(Segment::Text(text));
    }
    CompiledTemplate { segments }
}

/// 一条查询日志（渲染前的数据载体）。
pub struct QueryLog<'a> {
    pub qtype: RecordType,
    pub name: String,
    pub proto: &'static str,
    pub remote: IpAddr,
    pub port: u16,
    pub size: usize,
    pub duration: Duration,
    pub rcode: ResponseCode,
    pub action: String,
    pub answers: &'a str,
}

impl QueryLog<'_> {
    /// 按预编译模板渲染日志行（含换行），返回不可变 `Bytes` 供异步写出。
    fn format(&self, template: &CompiledTemplate) -> Bytes {
        let mut out = BytesMut::with_capacity(160);
        self.format_into(template, &mut out);
        out.put_u8(b'\n');
        out.freeze()
    }

    /// 按预编译模板将字段填充进 `out`（先清空）。仅做段遍历与值写入，无模板解析。
    fn format_into(&self, template: &CompiledTemplate, out: &mut BytesMut) {
        out.clear();
        for segment in &template.segments {
            match segment {
                Segment::Text(t) => out.extend_from_slice(t.as_bytes()),
                Segment::Field(field) => match field {
                    Field::Duration => {
                        let _ = write!(out, "{:.5}", self.duration.as_secs_f64());
                    }
                    Field::Proto => out.extend_from_slice(self.proto.as_bytes()),
                    Field::Rcode => out.extend_from_slice(format_rcode(self.rcode).as_bytes()),
                    Field::Name => out.extend_from_slice(self.name.as_bytes()),
                    Field::QType => {
                        let _ = write!(out, "{}", self.qtype);
                    }
                    Field::Port => {
                        let _ = write!(out, "{}", self.port);
                    }
                    Field::Size => {
                        let _ = write!(out, "{}", self.size);
                    }
                    Field::Action => out.extend_from_slice(self.action.as_bytes()),
                    Field::Remote => match &self.remote {
                        IpAddr::V4(v4) => {
                            let _ = write!(out, "{}", v4);
                        }
                        IpAddr::V6(v6) => {
                            let _ = write!(out, "[{}]", v6);
                        }
                    },
                    Field::Answers => out.extend_from_slice(self.answers.as_bytes()),
                },
            }
        }
    }
}

fn format_rcode(rcode: ResponseCode) -> &'static str {
    match rcode {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::FormErr => "FORMERR",
        _ => "UNKNOWN",
    }
}

/// 查询日志：预编译模板 + 异步写入 stdout。
///
/// 每次查询渲染一行 `Bytes` 后 `await` 写出。
pub(crate) struct QueryLogger {
    template: CompiledTemplate,
}

impl QueryLogger {
    pub fn new(cfg: &LogConfig) -> Arc<Self> {
        Arc::new(Self {
            template: compile_template(&cfg.format),
        })
    }

    pub async fn write(&self, qlog: &QueryLog<'_>) {
        let line = qlog.format(&self.template);
        let mut stdout = tokio::io::stdout();
        if let Err(e) = stdout.write_all(&line).await {
            log::warn!("query log write failed: {}", e);
        }
    }
}

/// 将应答中的记录类型列表写入 `out`（逗号分隔），空应答写 `-`。
fn format_answer_types(msg: &Message, out: &mut String) {
    out.clear();
    for r in &msg.answers {
        if !out.is_empty() {
            out.push(',');
        }
        out.push_str(&r.record_type().to_string());
    }
    if out.is_empty() {
        out.push('-');
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

struct LogsMetrics {
    queries_total: Counter,
    skipped_total: Counter,
}

impl LogsMetrics {
    fn new(registry: &MetricsRegistry) -> Self {
        Self {
            queries_total: registry.counter("rsdns_logs_queries_total", "Logged DNS queries", &["proto"]),
            skipped_total: registry.counter("rsdns_logs_skipped_total", "Queries skipped due to skip_log", &[]),
        }
    }
}

/// The query logger stage.
pub struct Logs {
    logger: Arc<QueryLogger>,
    metrics: OnceLock<LogsMetrics>,
}

/// Builds the logs stage from the `log:` config section (or the default).
pub fn init(config: &Config, registry: &MetricsRegistry) -> Logs {
    let raw = config.plugin_sections.get("log").cloned().unwrap_or_default();
    let cfg: LogConfig = serde_yaml::from_value(raw).unwrap_or_default();
    let logger = QueryLogger::new(&cfg);
    let metrics = LogsMetrics::new(registry);
    Logs {
        logger,
        metrics: OnceLock::from(metrics),
    }
}

impl Logs {
    /// No-op retained for API stability: lines are written immediately.
    pub async fn flush(&self) {}

    /// Writes the query log line after the pipeline completed, unless
    /// `ctx.skip_log` was set by a downstream stage.
    pub async fn log_query(&self, ctx: &QueryContext) {
        let response = ctx.response.as_ref();
        let rcode = response
            .map(|r| r.metadata.response_code)
            .unwrap_or(ResponseCode::ServFail);

        if ctx.skip_log {
            if let Some(m) = self.metrics.get() {
                m.skipped_total.inc();
            }
            return;
        }

        let mut answers = String::new();
        if let Some(response) = response {
            format_answer_types(response, &mut answers);
        } else {
            answers.push('-');
        }

        let qlog = QueryLog {
            qtype: ctx.qtype(),
            name: ctx.name().to_string(),
            proto: ctx.proto,
            remote: ctx.client.ip(),
            port: ctx.client.port(),
            size: ctx.size,
            duration: ctx.start.elapsed(),
            rcode,
            action: ctx.action.clone(),
            answers: &answers,
        };

        self.logger.write(&qlog).await;
        if let Some(m) = self.metrics.get() {
            m.queries_total.with_label_values(&[ctx.proto]).inc();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_template() -> CompiledTemplate {
        compile_template(r#"{remote} {name} "{type}" [{answers}] "{action}" {duration}s"#)
    }

    fn sample_qlog<'a>(answers: &'a str) -> QueryLog<'a> {
        QueryLog {
            qtype: RecordType::A,
            name: "www.example.com".into(),
            proto: "udp",
            remote: IpAddr::V4("192.168.1.100".parse().unwrap()),
            port: 5353,
            size: 29,
            duration: Duration::from_micros(1250),
            rcode: ResponseCode::NoError,
            action: "forward(default)".into(),
            answers,
        }
    }

    fn render(qlog: &QueryLog, template: &CompiledTemplate) -> String {
        let mut out = BytesMut::new();
        qlog.format_into(template, &mut out);
        String::from_utf8(out.to_vec()).unwrap()
    }

    #[test]
    fn test_compile_template_parses_placeholders() {
        let t = compile_template("{name} {type} {port} {size} {duration} {rcode} {remote} {action} {proto} {answers}");
        assert_eq!(
            t.segments,
            vec![
                Segment::Field(Field::Name),
                Segment::Text(" ".into()),
                Segment::Field(Field::QType),
                Segment::Text(" ".into()),
                Segment::Field(Field::Port),
                Segment::Text(" ".into()),
                Segment::Field(Field::Size),
                Segment::Text(" ".into()),
                Segment::Field(Field::Duration),
                Segment::Text(" ".into()),
                Segment::Field(Field::Rcode),
                Segment::Text(" ".into()),
                Segment::Field(Field::Remote),
                Segment::Text(" ".into()),
                Segment::Field(Field::Action),
                Segment::Text(" ".into()),
                Segment::Field(Field::Proto),
                Segment::Text(" ".into()),
                Segment::Field(Field::Answers),
            ]
        );
    }

    #[test]
    fn test_unknown_and_unclosed_placeholders_kept_as_literal() {
        let t = compile_template("a{unknown}b{");
        assert_eq!(t.segments, vec![Segment::Text("a{unknown}b{".into())]);
        let t = compile_template("{name} {bogus} {");
        assert_eq!(
            t.segments,
            vec![Segment::Field(Field::Name), Segment::Text(" {bogus} {".into()),]
        );
    }

    #[test]
    fn test_render_default_template() {
        let t = test_template();
        let qlog = sample_qlog("A");
        let line = render(&qlog, &t);
        assert_eq!(line, r#"192.168.1.100 www.example.com "A" [A] "forward(default)" 0.00125s"#);
    }

    #[test]
    fn test_render_ipv6_brackets() {
        let t = compile_template("{remote}:{port}");
        let qlog = QueryLog {
            remote: IpAddr::V6("2001:db8::1".parse().unwrap()),
            port: 53,
            ..sample_qlog("A")
        };
        assert_eq!(render(&qlog, &t), "[2001:db8::1]:53");
    }

    #[test]
    fn test_render_unknown_rcode_and_no_answers() {
        let t = compile_template("{rcode} [{answers}]");
        let qlog = QueryLog {
            rcode: ResponseCode::BADVERS,
            answers: "-",
            ..sample_qlog("-")
        };
        assert_eq!(render(&qlog, &t), "UNKNOWN [-]");
    }
}
