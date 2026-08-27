# rsdns 查询日志方案

> 2025-08-07 | 提案
>
> 2026-08-07 更新：本文已按当前实现回写。文中会区分“已实现”与“可选增强”，避免提案继续偏离代码。

## 1. 动机

`rsdns` 需要两类日志：

- 运行时/系统日志：启动、监听、错误、告警等，由 `xray_rs::common::rslog` 负责。
- 查询日志：每次 DNS 查询的结构化访问日志，由 `src/server.rs` 内的 `QueryLogger` 负责。

查询日志当前已经支持：

- 自定义模板
- 输出到 stdout 或文件
- 可配置缓冲区大小
- 定期 flush
- 记录查询动作标签（如 `hosts`、`forward(default)`、`block-nxdomain`）

当前实现未包含以下字段：

- `upstream`（监听本地地址）
- `upstream_proto`（监听协议标签）

这两个字段仍可作为后续增强，但不是现状。

## 2. 当前实现

### 2.1 配置结构

当前 `src/config.rs` 中的查询日志配置为：

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    /// Format template with placeholders: `{type}`, `{name}`, `{proto}`, `{remote}`,
    /// `{action}`, `{port}`, `{size}`, `{duration}`, `{rcode}`.
    #[serde(default = "default_format")]
    pub format: String,

    /// Log file path. None means stdout.
    pub file: Option<String>,

    /// Write buffer size in bytes, default 16384 (16 KB).
    #[serde(default = "default_buf_size")]
    pub buf_size: usize,
}

fn default_format() -> String {
    "{remote}:{port} {name} [{type}] {rcode} [{action}] {duration}".into()
}
```

顶层 `Config` 包含：

```rust
pub struct Config {
    // ...
    #[serde(default)]
    pub log: LogConfig,
}
```

### 2.2 当前支持的占位符

| 占位符 | 含义 | 数据来源 | 示例 |
|--------|------|----------|------|
| `{type}` | 查询类型 | `query.query_type()` → `u16` | `1` / `28` |
| `{name}` | 查询名 | `query.name().to_ascii().to_lowercase().trim_end_matches('.')` | `example.org` |
| `{proto}` | 客户端接入协议 | `serve_udp` / `serve_tcp` 传入 | `udp` / `tcp` |
| `{remote}` | 客户端 IP | `client_addr.ip()` | `192.168.1.1` / `[::1]` |
| `{port}` | 客户端端口 | `client_addr.port()` | `54321` |
| `{size}` | 请求大小 | `data.len()` | `42` |
| `{duration}` | 查询耗时，秒，保留 5 位小数 | `Instant::elapsed()` | `0.01234` |
| `{rcode}` | 应答状态码 | `response.metadata.response_code` | `NOERROR` |
| `{action}` | 查询动作标签 | `do_query()` 返回值 | `hosts` / `forward(default)` |
| `{time}` | 请求发起时刻（wall-clock，本地时区，`DD/MM/YYYY:HH:MM:SS ±HHMM`） | `QueryContext::start_time` | `27/08/2026:11:40:30 +0800` |

未识别占位符会按原样保留，例如 `{foo}` 仍输出 `{foo}`。

### 2.3 YAML 示例

```yaml
log:
  format: "{remote}:{port} {name} [{type}] {rcode} [{action}] {duration}"
  file: /var/log/rsdns/query.log
  buf_size: 16384

log: {}

log:
  file: /var/log/rsdns/query.log
```

省略 `log` 或使用 `log: {}` 时，使用默认模板、stdout、16 KB 缓冲区。

## 3. 当前默认格式

```text
{remote}:{port} {name} [{type}] {rcode} [{action}] {duration}
```

示例：

```text
192.168.1.100:54321 example.org [1] NOERROR [forward(default)] 0.01234
[::1]:12345 example.org [28] NXDOMAIN [block-nxdomain] 0.00501
10.0.0.1:9999 localhost [1] NOERROR [hosts] 0.00023
```

## 4. 实现说明

### 4.1 `QueryLog`

当前 `src/server.rs` 中：

```rust
pub struct QueryLog {
    pub qtype: u16,
    pub name: String,
    pub proto: &'static str,
    pub remote: IpAddr,
    pub port: u16,
    pub size: usize,
    pub duration: Duration,
    pub rcode: ResponseCode,
    pub action: String,
}
```

与原始提案相比：

- 已实现 `action`
- 未实现 `upstream`
- 未实现 `upstream_proto`

### 4.2 模板渲染

当前实现没有采用多次 `String::replace()` 的方式，而是做了一次模板扫描：

```rust
impl QueryLog {
    pub fn format(&self, template: &str) -> String {
        let mut result = String::with_capacity(template.len() + 128);
        let mut rest = template;
        while let Some(start) = rest.find('{') {
            result.push_str(&rest[..start]);
            rest = &rest[start + 1..];
            if let Some(end) = rest.find('}') {
                self.write_field(&mut result, &rest[..end]);
                rest = &rest[end + 1..];
            } else {
                result.push('{');
            }
        }
        result.push_str(rest);
        result
    }
}
```

这个版本比提案初稿中的逐个 `replace()` 更省分配，也更适合热路径。

### 4.3 `QueryLogger`

当前实现：

- `stdout` 和文件都使用 `BufWriter`
- `QueryLogger` 内部持有 `Arc<Mutex<LogWriter>>`
- `write()` 只写入缓冲区
- `start_flush_task()` 每 5 秒 flush 一次
- 进程退出前在 `main()` 中显式 `flush()`

对应关键代码位于：

- `src/server.rs:87-147`
- `src/main.rs:587-620`

## 5. 已实现行为与边界

- 查询日志与系统日志分离
- 查询日志模板可空，可自定义
- IPv6 remote 地址写成 `[addr]`
- `action` 由 `do_query()` 路径决定，便于定位命中来源
- 目前不记录监听本地地址和监听协议字段

## 6. 可优化点

1. 增加 `{upstream}` 和 `{upstream_proto}`
2. 将 `action: String` 尽量收敛为借用或小枚举，减少热路径分配
3. 如果查询日志量非常大，可将 `std::sync::Mutex` 评估为更轻量的异步外日志线程模型
4. 可增加模板预解析，把占位符编译成 token 列表，减少每次 `find('{')` 的扫描成本

## 7. 模块改动现状

| 文件 | 当前状态 |
|------|----------|
| `src/config.rs` | 已包含 `LogConfig` 与默认值 |
| `src/server.rs` | 已包含 `QueryLog` / `QueryLogger` / 模板渲染 / 文件与 stdout writer |
| `src/main.rs` | 已构造 logger，启动周期 flush，并在退出前 flush |

## 8. 兼容性

- `log` 缺省时使用默认模板、stdout、16 KB 缓冲区
- `file` 缺省时输出到 stdout
- 未识别占位符保持原样，不报错
- 查询日志配置不影响运行时系统日志，系统日志仍由 `rslog` 负责
