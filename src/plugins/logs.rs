//! `logs` stage — outermost query logger.
//!
//! Wraps the whole pipeline: records the query, runs the rest of the
//! pipeline, then renders and writes a log line on unwind unless
//! `ctx.skip_log` was set by a downstream stage.
//!
//! Lines go either to stdout (async, buffered as `bytes::Bytes`) or, when
//! `log.directory` is set (`{dir}:{maxsize}:{numfile}`), to a rotating file
//! `dir/query.log`: once the active file reaches `maxsize` it is gzip
//! archived as `query.log.N.gz` and a fresh file continues; at most
//! `numfile` files (active + archives) are kept.  Directory-mode I/O runs
//! through `tokio::fs` (never blocking a worker); gzip compression, being
//! a synchronous `flate2` API, runs in `spawn_blocking`.

use bytes::{BufMut, Bytes, BytesMut};
use flate2::write::GzEncoder;
use flate2::Compression;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use std::fmt::Write as _;
use std::io::{self, SeekFrom};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};
use tokio::fs;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::config::{
    default_log_directory, parse_log_directory_checked, Config, LogConfig, LogDirectory, DEFAULT_LOG_DIRECTORY,
};
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

/// 查询日志：预编译模板 + 写出（stdout 或轮转目录文件）。
///
/// 每次查询渲染一行 `Bytes` 后写出。目录模式行级写入 `tokio::fs` 写入器
/// （异步，不阻塞 worker），stdout 模式走 tokio 异步写出。
pub(crate) struct QueryLogger {
    template: CompiledTemplate,
    sink: Arc<LogSink>,
}

impl QueryLogger {
    /// 构建 logger。目录模式下创建目录并打开初始文件，失败返回 Err
    /// （启动报错退出）；`directory` 解析失败记 warning 并按默认目录处理。
    pub async fn new(cfg: &LogConfig) -> Result<Arc<Self>, io::Error> {
        let sink = match cfg.directory.as_deref() {
            Some(spec) => {
                let ld = match parse_log_directory_checked(spec) {
                    Some(ld) => ld,
                    None => {
                        log::warn!("invalid log.directory {:?}; using default {:?}", spec, DEFAULT_LOG_DIRECTORY);
                        default_log_directory()
                    }
                };
                Arc::new(LogSink::Directory(tokio::sync::Mutex::new(RotatingFileSink::open(ld).await?)))
            }
            None => Arc::new(LogSink::Stdout(tokio::sync::Mutex::new(tokio::io::stdout()))),
        };
        Ok(Arc::new(Self {
            template: compile_template(&cfg.format),
            sink,
        }))
    }

    pub async fn write(&self, qlog: &QueryLog<'_>) {
        let line = qlog.format(&self.template);
        match &*self.sink {
            LogSink::Stdout(stdout) => {
                let mut stdout = stdout.lock().await;
                if let Err(e) = stdout.write_all(&line).await {
                    log::warn!("query log write failed: {}", e);
                }
            }
            LogSink::Directory(sink) => sink.lock().await.write(&line).await,
        }
    }
}

/// 查询日志输出目标。
enum LogSink {
    /// stdout（默认），句柄启动时创建一次并复用。
    Stdout(tokio::sync::Mutex<tokio::io::Stdout>),
    /// 轮转目录文件：`dir/query.log` + gzip 归档（行级写入短临界区，压缩
    /// 在 `spawn_blocking` 中执行，不阻塞 tokio worker）。
    Directory(tokio::sync::Mutex<RotatingFileSink>),
}

/// 轮转文件写入器：单行追加 + 大小累计 + 轮转（gzip 归档 / 编号顺移 /
/// 超限删除）。所有文件操作走 `tokio::fs`（异步），由调用方确保互斥。
struct RotatingFileSink {
    dir: PathBuf,
    maxsize: u64,
    numfile: usize,
    file: fs::File,
    written: u64,
}

impl RotatingFileSink {
    /// 打开 `dir` 下的轮转日志：创建目录，以追加模式打开/创建 `query.log`
    /// 并回退到文件末尾累计已写字节（启动恢复计数）。
    async fn open(spec: LogDirectory) -> io::Result<Self> {
        let dir = PathBuf::from(&spec.dir);
        fs::create_dir_all(&dir).await?;
        let path = dir.join("query.log");
        let mut file = fs::OpenOptions::new().create(true).append(true).open(&path).await?;
        let written = file.seek(SeekFrom::End(0)).await?;
        Ok(Self {
            dir,
            maxsize: spec.maxsize,
            numfile: spec.numfile,
            file,
            written,
        })
    }

    /// 追加一行；若已有内容且写满阈值则先轮转再写（空文件不轮转，避免
    /// 产生空归档）。
    async fn write(&mut self, line: &[u8]) {
        if self.written > 0 && self.written + line.len() as u64 > self.maxsize {
            self.rotate().await;
        }
        match self.file.write_all(line).await {
            Ok(()) => self.written += line.len() as u64,
            Err(e) => log::error!("query log write failed: {}", e),
        }
    }

    /// 轮转：先把旧归档编号顺移/淘汰（腾出 `query.log.1.gz`），再把当前
    /// `query.log` 整体 gzip 为 `query.log.1.gz`（`spawn_blocking` 中流式
    /// 压缩），原文件截断继续追加。失败仅记 error，不中断服务。
    async fn rotate(&mut self) {
        self.collect().await;
        let src = self.dir.join("query.log");
        let dst = self.dir.join("query.log.1.gz");
        if let Err(e) = self.file.flush().await {
            log::error!("query log flush before rotate failed: {}", e);
        }
        match gzip_file(&src, &dst).await {
            Ok(()) => {
                // 归档成功后再截断原文件；截断失败时下轮再试（文件仍可追加）。
                if let Err(e) = self.file.set_len(0).await {
                    log::error!("query log truncate after rotate failed: {}", e);
                    return;
                }
                if let Err(e) = self.file.seek(SeekFrom::Start(0)).await {
                    log::error!("query log rewind after rotate failed: {}", e);
                }
                self.written = 0;
            }
            Err(e) => log::error!("query log rotate failed: {}", e),
        }
    }

    /// 归档编号顺移：`query.log.N.gz` → `query.log.(N+1).gz`，编号从大到小；
    /// 顺移后编号超过 `numfile-1` 的归档删除。任一文件失败仅记 warning，
    /// 继续处理其余。
    async fn collect(&self) {
        let mut archives: Vec<u64> = {
            let mut entries = match fs::read_dir(&self.dir).await {
                Ok(entries) => entries,
                Err(e) => {
                    log::warn!("query log: read_dir {:?}: {}", self.dir, e);
                    return;
                }
            };
            let mut idxs = Vec::new();
            while let Some(entry) = entries.next_entry().await.transpose() {
                match entry {
                    Ok(entry) => {
                        if let Some(idx) = archive_index(&entry.file_name()) {
                            idxs.push(idx);
                        }
                    }
                    Err(e) => log::warn!("query log: read_dir {:?}: {}", self.dir, e),
                }
            }
            idxs
        };
        archives.sort_unstable();
        let keep_max = (self.numfile - 1) as u64;
        for &idx in archives.iter().rev() {
            let from = self.dir.join(format!("query.log.{idx}.gz"));
            let to = self.dir.join(format!("query.log.{}.gz", idx + 1));
            if idx + 1 > keep_max {
                if let Err(e) = fs::remove_file(&from).await {
                    log::warn!("query log: remove old archive {:?}: {}", from, e);
                }
            } else if let Err(e) = fs::rename(&from, &to).await {
                log::warn!("query log: shift archive {:?} → {:?}: {}", from, to, e);
            }
        }
    }
}

/// 流式 gzip 压缩 `src` 到 `dst`（边读边压，不整体载入内存）。`flate2` 为
/// 同步 API，在 `spawn_blocking` 中执行，避免阻塞 tokio worker。
async fn gzip_file(src: &Path, dst: &Path) -> io::Result<()> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let mut input = std::fs::File::open(src)?;
        let mut encoder = GzEncoder::new(std::fs::File::create(dst)?, Compression::default());
        io::copy(&mut input, &mut encoder)?;
        encoder.finish()?;
        Ok(())
    })
    .await
    .map_err(io::Error::other)? // JoinError → io::Error
}

/// 从归档文件名解析编号：`query.log.N.gz` → `Some(N)`。
fn archive_index(name: &std::ffi::OsStr) -> Option<u64> {
    let s = name.to_str()?;
    let rest = s.strip_prefix("query.log.")?;
    let n = rest.strip_suffix(".gz")?;
    n.parse::<u64>().ok()
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

    // -- rotation ---------------------------------------------------------

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rsdns-logtest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[tokio::test]
    async fn test_rotate_archives_and_truncates() {
        let dir = tmp_dir("rotate");
        let mut sink = RotatingFileSink::open(LogDirectory {
            dir: dir.to_string_lossy().into_owned(),
            maxsize: 8,
            numfile: 5,
        })
        .await
        .unwrap();

        // 两行各 8 字节：第一行写满 8 字节不轮转，第二行触发轮转。
        sink.write(b"aaaaaaaa").await;
        assert!(dir.join("query.log").exists());
        assert!(!dir.join("query.log.1.gz").exists(), "未超限不轮转");

        sink.write(b"bbbbbbbb").await;
        assert!(dir.join("query.log.1.gz").exists(), "超限后产生归档");
        // 写入仅拷贝进缓冲即返回，落盘是异步的；先 flush 再读，避免读到
        // set_len(0) 之后、本行落盘之前的空文件。
        sink.file.flush().await.unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("query.log")).unwrap(), "bbbbbbbb");
        assert_eq!(sink.written, 8);

        // 归档内容与轮转前文件一致（gzip 解压后）。
        let mut gz = flate2::read::GzDecoder::new(std::fs::File::open(dir.join("query.log.1.gz")).unwrap());
        let mut content = String::new();
        use std::io::Read;
        gz.read_to_string(&mut content).unwrap();
        assert_eq!(content, "aaaaaaaa");

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn test_rotate_keeps_numfile_archives() {
        let dir = tmp_dir("numfile");
        let mut sink = RotatingFileSink::open(LogDirectory {
            dir: dir.to_string_lossy().into_owned(),
            maxsize: 4,
            numfile: 3,
        })
        .await
        .unwrap();

        // 4 个归档周期 + 收尾写入；共应保留 query.log + 2 个 .gz。
        sink.write(b"aaaa").await;
        sink.write(b"bbbb").await;
        sink.write(b"cccc").await;
        sink.write(b"dddd").await;
        sink.write(b"ee").await;
        assert_eq!(sink.written, 2);

        assert!(dir.join("query.log.1.gz").exists());
        assert!(dir.join("query.log.2.gz").exists());
        assert!(!dir.join("query.log.3.gz").exists(), "超过 numfile-1 的归档被删除");

        // 每个归档都能解压且长度正确。
        for idx in 1..=2 {
            let mut gz =
                flate2::read::GzDecoder::new(std::fs::File::open(dir.join(format!("query.log.{idx}.gz"))).unwrap());
            let mut content = String::new();
            use std::io::Read;
            gz.read_to_string(&mut content).unwrap();
            assert_eq!(content.len(), 4, "archive {idx} content: {content:?}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn test_empty_file_never_rotates() {
        let dir = tmp_dir("empty");
        let mut sink = RotatingFileSink::open(LogDirectory {
            dir: dir.to_string_lossy().into_owned(),
            maxsize: 1,
            numfile: 3,
        })
        .await
        .unwrap();
        sink.write(b"abc").await; // 第一行直接写入，即使超过 maxsize 也不轮转
        assert!(!dir.join("query.log.1.gz").exists());
        sink.file.flush().await.unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("query.log")).unwrap(), "abc");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
