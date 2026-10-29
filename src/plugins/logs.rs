//! `logs` stage — outermost query logger.
//!
//! Wraps the whole pipeline: records the query, runs the rest of the
//! pipeline, then renders and writes a log line on unwind unless
//! `ctx.skip_log` was set by a downstream stage.
//!
//! Lines go either to stdout (async, buffered as `bytes::Bytes`) or, when
//! `log.directory` is set (a plain directory path), appended to
//! `dir/query.log`.  rsdns never rotates or compresses that file itself:
//! rotation is owned by an external `logrotate` (see
//! `example/rsdns.logrotate`), which renames the file and then has the
//! process reopen it via `SIGHUP` (`systemctl reload rsdns` →
//! [`QueryLogger::reopen`]).  Directory-mode I/O runs through `tokio::fs`
//! (never blocking a worker).

use bytes::{BufMut, Bytes, BytesMut};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::fmt::Write as _;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::fs;
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
    Time,
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
            "time" => Self::Time,
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
    /// 请求发起时刻（wall-clock，与系统时间对齐）。
    pub time: SystemTime,
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
                    Field::Time => {
                        let _ = write!(out, "{}", format_time(self.time));
                    }
                },
            }
        }
    }
}

/// 本地时区偏移，首次使用时缓存（`current_local_offset` 每次都是系统调用）。
static LOCAL_OFFSET: OnceLock<time::UtcOffset> = OnceLock::new();

fn local_offset() -> time::UtcOffset {
    *LOCAL_OFFSET.get_or_init(|| time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC))
}

/// 渲染请求发起时刻（本地时区，`DD/MM/YYYY:HH:MM:SS +ZZZZ`，即
/// `27/08/2026:11:40:30 +0800` 式 CLF 风格；本地时区不可用时回退 UTC，
/// 偏移显示为 `+0000`）。失败时输出占位符原文，不阻塞日志。
fn format_time(t: SystemTime) -> String {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => {
            let secs = d.as_secs() as i64;
            let now = match time::OffsetDateTime::from_unix_timestamp(secs) {
                Ok(utc) => utc.to_offset(local_offset()),
                Err(_) => return "{time}".into(),
            };
            let off = now.offset();
            format!(
                "{:02}/{:02}/{:04}:{:02}:{:02}:{:02} {}{:02}{:02}",
                now.day(),
                u8::from(now.month()),
                now.year(),
                now.hour(),
                now.minute(),
                now.second(),
                if off.is_negative() { '-' } else { '+' },
                off.whole_hours().unsigned_abs(),
                off.minutes_past_hour().unsigned_abs(),
            )
        }
        Err(_) => "{time}".into(),
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

/// 查询日志：预编译模板 + 写出（stdout 或目录文件）。
///
/// 每次查询渲染一行 `Bytes` 后写出。目录模式行级写入 `tokio::fs` 写入器
/// （异步，不阻塞 worker），stdout 模式走 tokio 异步写出。
pub(crate) struct QueryLogger {
    template: CompiledTemplate,
    sink: LogSink,
}

impl QueryLogger {
    /// 构建 logger。目录模式下创建目录并打开（或创建）`dir/query.log`，
    /// 失败返回 Err（启动报错退出）。`directory` 必须是纯目录路径：内置
    /// 轮转已移除，旧的 `{dir}:{maxsize}:{numfile}` 形式直接报错。
    pub async fn new(cfg: &LogConfig) -> Result<Arc<Self>, io::Error> {
        let sink = match cfg.directory.as_deref() {
            Some(dir) => {
                if dir.contains(':') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "log.directory {dir:?} must be a plain directory path: built-in rotation was removed, \
                             use an external logrotate (see example/rsdns.logrotate) and set \
                             `directory: /var/log/rsdns`"
                        ),
                    ));
                }
                LogSink::Directory(DirectorySink::open(PathBuf::from(dir)).await?)
            }
            None => LogSink::Stdout(tokio::sync::Mutex::new(tokio::io::stdout())),
        };
        Ok(Arc::new(Self {
            template: compile_template(&cfg.format),
            sink,
        }))
    }

    pub async fn write(&self, qlog: &QueryLog<'_>) {
        let line = qlog.format(&self.template);
        match &self.sink {
            LogSink::Stdout(stdout) => {
                let mut stdout = stdout.lock().await;
                if let Err(e) = stdout.write_all(&line).await {
                    log::warn!("query log write failed: {}", e);
                }
            }
            LogSink::Directory(sink) => sink.write(&line).await,
        }
    }

    /// 重新打开目录模式下的 `query.log`（`SIGHUP` 触发）。stdout 模式为空操作。
    ///
    /// `logrotate` 用 rename + create 轮转文件后，进程必须换掉旧文件描述符，
    /// 否则后续日志继续写进已重命名/已压缩的旧 inode。
    pub async fn reopen(&self) -> io::Result<()> {
        match &self.sink {
            LogSink::Stdout(_) => Ok(()),
            LogSink::Directory(sink) => sink.reopen().await,
        }
    }
}

/// 查询日志输出目标。
enum LogSink {
    /// stdout（默认），句柄启动时创建一次并复用。
    Stdout(tokio::sync::Mutex<tokio::io::Stdout>),
    /// 目录文件：`dir/query.log`，追加写入，轮转交给外部 `logrotate`。
    Directory(DirectorySink),
}

/// 目录文件写入器：单行追加 + 可重开。
///
/// 互斥用 `tokio::sync::Mutex` 只保护文件句柄，`reopen` 的新句柄在拿锁之前
/// 就打开好，锁内只做一次替换。
struct DirectorySink {
    /// 日志目录（保持不变，重开时复用）。
    dir: PathBuf,
    /// 当前 `dir/query.log` 句柄。
    file: tokio::sync::Mutex<fs::File>,
}

impl DirectorySink {
    /// 创建目录并以追加模式打开/创建 `dir/query.log`。
    async fn open(dir: PathBuf) -> io::Result<Self> {
        let file = open_query_log(&dir).await?;
        Ok(Self {
            dir,
            file: tokio::sync::Mutex::new(file),
        })
    }

    /// 追加一行；写失败仅记 error（不中断服务）。
    async fn write(&self, line: &[u8]) {
        let mut file = self.file.lock().await;
        if let Err(e) = file.write_all(line).await {
            log::error!("query log write failed: {}", e);
        }
    }

    /// 重新打开 `dir/query.log`：先打开新句柄（失败时旧句柄保持不动，返回
    /// Err），成功后再取锁替换。
    async fn reopen(&self) -> io::Result<()> {
        let file = open_query_log(&self.dir).await?;
        *self.file.lock().await = file;
        Ok(())
    }
}

/// 以追加模式打开（或创建）`dir/query.log`，目录不存在时递归创建。
async fn open_query_log(dir: &Path) -> io::Result<fs::File> {
    fs::create_dir_all(dir).await?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("query.log"))
        .await
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
///
/// Directory-mode failures (creating the dir / opening the initial file)
/// are returned as `Err` so startup can abort.
pub async fn init(config: &Config, registry: &MetricsRegistry) -> Result<Logs, io::Error> {
    let raw = config.plugin_sections.get("log").cloned().unwrap_or_default();
    let cfg: LogConfig = serde_yaml::from_value(raw).unwrap_or_default();
    let logger = QueryLogger::new(&cfg).await?;
    let metrics = LogsMetrics::new(registry);
    Ok(Logs {
        logger,
        metrics: OnceLock::from(metrics),
    })
}

impl Logs {
    /// No-op retained for API stability: lines are written immediately.
    pub async fn flush(&self) {}

    /// 重新打开查询日志文件（`SIGHUP` / `systemctl reload`），配合外部
    /// `logrotate` 的 rename + create 轮转。stdout 模式为空操作。
    pub async fn reopen(&self) -> io::Result<()> {
        self.logger.reopen().await
    }

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
            time: ctx.start_time,
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
            time: SystemTime::UNIX_EPOCH,
        }
    }

    fn render(qlog: &QueryLog, template: &CompiledTemplate) -> String {
        let mut out = BytesMut::new();
        qlog.format_into(template, &mut out);
        String::from_utf8(out.to_vec()).unwrap()
    }

    #[test]
    fn test_compile_template_parses_placeholders() {
        let t = compile_template(
            "{name} {type} {port} {size} {duration} {rcode} {remote} {action} {proto} {answers} {time}",
        );
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
                Segment::Text(" ".into()),
                Segment::Field(Field::Time),
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

    #[test]
    fn test_render_time_placeholder() {
        // UNIX_EPOCH + 1000 天整秒 → 1972-09-27；偏移取本地时区，仅校验形状。
        let t = compile_template("{time}");
        let qlog = QueryLog {
            time: SystemTime::UNIX_EPOCH + Duration::from_secs(1000 * 86_400),
            ..sample_qlog("A")
        };
        let rendered = render(&qlog, &t);
        // 形状：DD/MM/YYYY:HH:MM:SS ±HHMM（长度 25）。
        assert_eq!(rendered.len(), 25, "rendered: {rendered:?}");
        let b = rendered.as_bytes();
        assert_eq!(&rendered[2..3], "/");
        assert_eq!(&rendered[5..6], "/");
        assert_eq!(&rendered[10..11], ":");
        assert_eq!(&rendered[13..14], ":");
        assert_eq!(&rendered[16..17], ":");
        assert_eq!(&rendered[19..20], " ");
        assert!(b[0].is_ascii_digit() && b[1].is_ascii_digit(), "rendered: {rendered:?}");
        // 时区无关：本地时区偏移 ±HHMM 是合法数字。
        let off = &rendered[21..25];
        assert!(off.as_bytes().iter().all(u8::is_ascii_digit), "rendered: {rendered:?}");
    }

    // -- directory file sink ----------------------------------------------

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rsdns-logtest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// 目录模式：多次写入按顺序追加到 `dir/query.log`，不产生归档。
    #[tokio::test]
    async fn test_directory_sink_appends_lines() {
        let dir = tmp_dir("append");
        let sink = DirectorySink::open(dir.clone()).await.unwrap();

        sink.write(b"first\n").await;
        sink.write(b"second\n").await;
        sink.file.lock().await.flush().await.unwrap();

        assert_eq!(std::fs::read_to_string(dir.join("query.log")).unwrap(), "first\nsecond\n");
        assert!(!dir.join("query.log.1").exists(), "rsdns 不再自己轮转");
        assert!(!dir.join("query.log.1.gz").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// logrotate 语义：rename 掉 `query.log` + create 之后，`reopen` 必须换到
    /// 新文件；否则日志继续写进已重命名的旧 inode。
    #[tokio::test]
    async fn test_reopen_after_logrotate_rename() {
        let dir = tmp_dir("reopen");
        let sink = DirectorySink::open(dir.clone()).await.unwrap();

        sink.write(b"old-line\n").await;
        sink.file.lock().await.flush().await.unwrap();

        // logrotate: 挪走当前文件（`compress`/`delaycompress` 由外部完成）。
        std::fs::rename(dir.join("query.log"), dir.join("query.log.1")).unwrap();
        assert!(!dir.join("query.log").exists());

        // postrotate: systemctl reload → SIGHUP → reopen。
        sink.reopen().await.unwrap();

        sink.write(b"new-line\n").await;
        sink.file.lock().await.flush().await.unwrap();

        assert_eq!(
            std::fs::read_to_string(dir.join("query.log")).unwrap(),
            "new-line\n",
            "重开后的新文件只含轮转之后的日志"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("query.log.1")).unwrap(),
            "old-line\n",
            "旧文件内容不被改动"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// 重开失败（目录不可用）时保留旧句柄、返回 Err，服务继续写旧文件。
    #[tokio::test]
    async fn test_reopen_failure_keeps_old_handle() {
        let dir = tmp_dir("reopen-fail");
        let sink = DirectorySink::open(dir.clone()).await.unwrap();
        sink.write(b"before\n").await;
        sink.file.lock().await.flush().await.unwrap();

        // 把目录整体挪走，再用一个普通文件占住原路径：`create_dir_all` 必然
        // 失败（NotADirectory），而旧句柄仍指向挪走后的文件。
        std::fs::rename(&dir, dir.with_extension("moved")).unwrap();
        std::fs::write(&dir, b"not a dir").unwrap();

        assert!(sink.reopen().await.is_err(), "不可用目录必须返回 Err");

        sink.write(b"after\n").await;
        sink.file.lock().await.flush().await.unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.with_extension("moved").join("query.log")).unwrap(),
            "before\nafter\n",
            "重开失败后继续用旧句柄写入"
        );

        std::fs::remove_file(&dir).unwrap();
        std::fs::remove_dir_all(dir.with_extension("moved")).unwrap();
    }

    /// 旧格式 `{dir}:{maxsize}:{numfile}` 直接报错（内置轮转已移除）。
    #[tokio::test]
    async fn test_rotating_spec_is_rejected() {
        let cfg = LogConfig {
            format: "{name}".into(),
            directory: Some("/var/log/rsdns:5m:5".into()),
        };
        let err = QueryLogger::new(&cfg).await.err().expect("must reject rotating spec");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("logrotate"), "err: {err}");
    }
}
