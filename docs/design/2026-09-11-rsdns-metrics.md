# rsdns 指标增强方案（有效指标 + upstream 请求指标）

- 日期: 2026-09-11
- 状态: 提案（待审阅）
- 影响面: `src/metrics.rs`、`src/server.rs`、`src/main.rs`、`src/upstream/mod.rs`、`src/plugins/ui.html`、`example/rsdns-all-example.yaml`
- 本提案不含实现；审阅通过后再落地。

## 1. 动机

当前 `src/metrics.rs` 注册表只提供 `Counter` 与 `Gauge` 两类指标，且没有分位/耗时分布能力。
现网可观测性存在两类缺口：

1. **端到端有效指标缺失**：现有 `rsdns_logs_queries_total{proto}` 只记录“被记录”的查询（受
   `skip_log` 影响），且没有任何关于最终应答 `rcode`、查询类型 `qtype`、整体耗时、入站解析失败的指标。
   这意味着：不知道 SERVFAIL 占比、不知道 A/AAAA/CNAME 分布、无法做 P50/P95/P99 延迟告警、无法区分
   “客户端发了垃圾包”与“上游挂了”。
2. **upstream 请求指标单薄**：仅有 `query_total{upstream,proto}` 与 `error_total{upstream,kind}`
   （按 `io::ErrorKind` 粗分 `timeout/refused/reset/other`），没有上游应答 `rcode` 分布、没有按上游的
   请求耗时直方图。无法回答“某个上游经常回 SERVFAIL 还是经常超时”“哪个上游整体更慢”。

本提案目标：在最小改动前提下补齐这些**有效指标**，并为耗时类指标引入轻量 `Histogram` 类型
（沿用现有自研注册表，不引入 `prometheus` crate，保持依赖最小化）。

## 2. 现状核查

| 区域 | 现有指标 | 说明 |
|------|----------|------|
| 注册表 | `Counter` / `Gauge`，无 `Histogram` | `Series` 仅存 `u64` |
| 日志 | `rsdns_logs_queries_total{proto}`、`rsdns_logs_skipped_total` | 受 `skip_log` 影响，非全量 |
| hosts | `rsdns_hosts_lookup_total`、`rsdns_hosts_hit_total`、`rsdns_hosts_entries` | — |
| groups | `rsdns_groups_lookup_total`、`rsdns_groups_hit_total{group}`、`rsdns_groups_entries{group}` | — |
| cache | `rsdns_cache_lookup_total{result}`、`rsdns_cache_entries` | `result` ∈ `fresh`/`miss` |
| rules | `rsdns_rules_evaluated_total`、`rsdns_rules_matched_total{action}` | — |
| upstream | `rsdns_upstream_query_total{upstream,proto}`、`rsdns_upstream_error_total{upstream,kind}` | 仅 transport 级错误 |
| pool | `rsdns_upstream_pool_connections{upstream,proto}`、`rsdns_upstream_pool_checkout_total{upstream,result}` | `result` ∈ `cached`/`created` |
| jemalloc | `rsdns_jemalloc_{allocated,active,resident,mapped}_bytes` | 仅 jemalloc build |

**关键事实**：`server.rs::handle_query` 已持有 `start: Instant` 与 `ctx`（含最终 `ctx.response`
与 `ctx.qtype()`），只需把 `MetricsRegistry` 注入 `DnsServer` 即可在 `handle_query` 内记录端到端指标，
无需改动各 stage 内部结构。`upstream::Upstreams::query` 已能拿到请求结果与 `io::Error`，可直接补 rcode /
latency 指标。

## 3. 设计

### 3.1 注册表新增 `Histogram` 类型（`src/metrics.rs`）

与 `Counter`/`Gauge` 同构，但底层累积 `f64` 的 `sum`/`count` 与每桶 `u64` 计数：

- 新增 `pub const DEFAULT_BUCKETS: &[f64]`（秒级，适合 DNS 耗时）：
  `&[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]`。
- `MetricsRegistry::histogram(name, help, label_names, buckets: &[f64]) -> Histogram`，
  内部 `validate_metric_name` + `assert_unique` 复用现有守卫（`assert_unique` 同时约束
  counter/gauge/histogram 同名冲突 —— 当前它只校验各自列表内唯一，需扩展为跨三类唯一）。
- `Histogram::observe(&self, value: f64)` 与 `Histogram::with_label_values(&[&str]) -> Histogram`。
- 渲染为 Prometheus 直方图格式（含 `le` 与 `+Inf`）：
  ```
  # HELP <name> <help>
  # TYPE <name> histogram
  <name>_bucket{<labels>,le="0.001"} 0
  ...
  <name>_bucket{<labels>,le="+Inf"} <count>
  <name>_sum{<labels>} <sum>
  <name>_count{<labels>} <count>
  ```
- 桶计数按“累积”语义维护：observe(x) 时 `count+=1`、`sum+=x`、对所有 `le >= x` 的桶 `+=1`。
- 测试：`test_histogram_*` 校验 `_bucket`/`_sum`/`_count` 输出与 `le="+Inf"` 存在；
  跨类型同名触发 `already registered`（扩展 `assert_unique` 调用点）。

> 不引入 `prometheus` crate：保持离线注册表依赖最小化，沿用现有 `encode_text` 出口（UI `/metrics` 已消费）。

### 3.2 端到端有效指标（新增 `ServerMetrics`，注入 `DnsServer`）

在 `run()` 中用同一 `&metrics` 构造 `ServerMetrics`，存入 `DnsServer`，`handle_query(&self, …)` 直接使用：

| 指标名 | 类型 | 标签 | 含义 / 取数点 |
|--------|------|------|----------------|
| `rsdns_queries_total` | Counter | `proto` | 入站查询总数（全量，含后续解析失败）。`handle_query` 入口 `inc()`。 |
| `rsdns_query_parse_errors_total` | Counter | — | 入站报文 `Message::from_vec` 失败或无 question 的次数（在 `handle_query` 两处 `Err` 返回前 `inc()`）。 |
| `rsdns_query_rcode_total` | Counter | `rcode` | 最终应答 `rcode` 分布。`handle_query` 末尾从 `ctx.response` 取 `metadata.response_code`，无响应视为 `SERVFAIL`。`rcode` 用 `format!("{}", rcode)`（如 `NOERROR`/`NXDOMAIN`/`SERVFAIL`/`REFUSED`/`FORMERR`）。 |
| `rsdns_query_qtype_total` | Counter | `qtype` | 查询类型分布。`ctx.qtype()` 用 `format!("{}", ...)`（如 `A`/`AAAA`/`CNAME`/`HTTPS`）。 |
| `rsdns_query_duration_seconds` | Histogram | `proto` | 端到端处理耗时（`ctx.start.elapsed().as_secs_f64()`，取点为应答构建完成、写回缓存前）。 |

> 注：`rsdns_queries_total{proto}` 与现有 `rsdns_logs_queries_total{proto}` 区分清晰——前者是“收到”，
> 后者是“被 query-log 记录”（受 `skip_log` 影响）。两者并存不冲突，命名已区分。

### 3.3 upstream 请求指标（扩展 `UpstreamMetrics`，`src/upstream/mod.rs`）

在 `Upstreams::query` 内补两项，并保持现有 `query_total` / `error_total` 不变：

| 指标名 | 类型 | 标签 | 含义 / 取数点 |
|--------|------|------|----------------|
| `rsdns_upstream_rcode_total` | Counter | `upstream`, `rcode` | 上游应答 `rcode` 分布。仅在 `group.query` 返回 `Ok(message)` 时记录 `message.metadata.response_code`（`format!("{}", rcode)`）。与 `error_total`（transport 级）互补：transport 失败走 `error_total`，上游正常回 SERVFAIL/NXDOMAIN 走本指标。 |
| `rsdns_upstream_latency_seconds` | Histogram | `upstream`, `proto` | 单次 upstream 调用耗时（从 `group.query` 前到后，`group.proto()` 作为 `proto` 标签）。覆盖 serial/parallel 多 client 重试的整体耗时。 |

> 池级指标（`rsdns_upstream_pool_connections`、`rsdns_upstream_pool_checkout_total`）已存在，本提案不改动，
> 仅在 UI 中集中展示（见 §3.4）。

### 3.4 UI 仪表盘（`src/plugins/ui.html` `MODULES`）

在「查询」模块追加端到端四项；新增「上游」模块聚合全部 upstream 相关指标：

```js
// 查询模块 items 追加：
{ name: "rsdns_queries_total", label: "收到查询", fmt: fmtCount, desc: "所有协议入站查询", perLabel: "proto" },
{ name: "rsdns_query_rcode_total", label: "应答 rcode", fmt: fmtCount, desc: "最终应答 rcode 分布", perLabel: "rcode" },
{ name: "rsdns_query_qtype_total", label: "查询类型", fmt: fmtCount, desc: "查询类型分布", perLabel: "qtype" },
{ name: "rsdns_query_duration_seconds", match: { proto: "udp" }, label: "UDP 耗时(P50≈le=0.05)", fmt: fmtCount, desc: "端到端耗时直方图 _count", perLabel: "le" },

// 新增模块：
{
  title: "上游",
  color: "var(--upstream)",
  items: [
    { name: "rsdns_upstream_query_total", label: "上游请求", fmt: fmtCount, desc: "转发到各上游池的查询次数", perLabel: "upstream" },
    { name: "rsdns_upstream_error_total", label: "上游错误", fmt: fmtCount, desc: "上游 transport 错误", perLabel: "kind" },
    { name: "rsdns_upstream_rcode_total", label: "上游 rcode", fmt: fmtCount, desc: "上游应答 rcode 分布", perLabel: "rcode" },
    { name: "rsdns_upstream_latency_seconds", label: "上游耗时", fmt: fmtCount, desc: "各上游请求耗时直方图 _count", perLabel: "le" },
    { name: "rsdns_upstream_pool_connections", label: "空闲连接", fmt: fmtInt, desc: "各上游池空闲连接数", perLabel: "upstream" },
    { name: "rsdns_upstream_pool_checkout_total", label: "连接借出", fmt: fmtCount, desc: "连接池借出次数", perLabel: "result" },
  ],
},
```

> UI 仅为展示聚合，`/metrics` 文本格式本身无需改动（直方图的 `_bucket`/`_sum`/`_count` 已是标准格式）。
> 直方图在 UI 中以 `_count` 按 `le` 维度展示分桶，符合现有 `perLabel` 机制。

## 4. 指标目录（落地后全量）

| 分类 | 指标 |
|------|------|
| 端到端 | `rsdns_queries_total{proto}`、`rsdns_query_parse_errors_total`、`rsdns_query_rcode_total{rcode}`、`rsdns_query_qtype_total{qtype}`、`rsdns_query_duration_seconds{proto}` |
| upstream | `rsdns_upstream_query_total{upstream,proto}`、`rsdns_upstream_error_total{upstream,kind}`、`rsdns_upstream_rcode_total{upstream,rcode}`、`rsdns_upstream_latency_seconds{upstream,proto}` |
| 连接池 | `rsdns_upstream_pool_connections{upstream,proto}`、`rsdns_upstream_pool_checkout_total{upstream,result}` |
| 既有（不变） | logs / hosts / groups / cache / rules / jemalloc 全部保留 |

## 5. 实现计划（文件级）

1. `src/metrics.rs`
   - 新增 `DEFAULT_BUCKETS`、`Histogram` 结构（底层 `HistogramSeries` 存 `sum:f64`/`count:u64`/桶 `Vec<u64>`）、`MetricsRegistry::histogram(…)`。
   - `encode_text` 增加 histogram 分支；`assert_unique` 扩展为跨三类唯一。
   - 新增 `test_histogram_*` 与跨类型同名 `should_panic` 测试。
2. `src/server.rs`
   - 新增 `ServerMetrics` 结构（字段见 §3.2）；`DnsServer` 增加 `server_metrics: ServerMetrics` 字段。
   - `handle_query` 入口 `inc` `rsdns_queries_total`；两处解析失败前 `inc` `rsdns_query_parse_errors_total`；末尾记录 `rsdns_query_rcode_total` / `rsdns_query_qtype_total` / `rsdns_query_duration_seconds`。
   - `DnsServer::new` 签名增加 `server_metrics` 参数（或内部用 `&metrics` 构造）。
3. `src/main.rs`
   - `run()` 中 `let server_metrics = ServerMetrics::new(&metrics);` 并传入 `DnsServer::new(pipeline, server_metrics)`。
   - 单测路径（`server.rs` 内 `MetricsRegistry::default()`）无需 registry 时给 `ServerMetrics` 缺省实现（与 `logs`/`hosts` 等 `OnceLock` 模式一致）。
4. `src/upstream/mod.rs`
   - `UpstreamMetrics::new` 增加 `rsdns_upstream_rcode_total`、`rsdns_upstream_latency_seconds`（带 `DEFAULT_BUCKETS`）。
   - `Upstreams::query` 计时并补记录（ok 路径记 rcode；成功/失败均 observe latency）。
5. `src/plugins/ui.html`
   - 按 §3.4 更新 `MODULES`（查询模块追加 + 新增上游模块）。
6. `example/rsdns-all-example.yaml`
   - 在 metrics 注释块补充新指标名（仅文档示例，无功能影响）。

## 6. 验收标准

- `make ci` 通过（fmt + clippy + check + test，含新增 registry 测试）。
- `curl /metrics` 输出包含全部新增指标，且直方图格式正确（`_bucket` 含 `le="+Inf"`、`_sum`、`_count`）。
- 端到端：制造若干查询后，`rsdns_query_rcode_total` 出现 `NOERROR`/`NXDOMAIN`/`SERVFAIL` 等；`rsdns_queries_total` ≥ `rsdns_logs_queries_total`（因含 skip_log 与解析失败）。
- upstream：转发查询后 `rsdns_upstream_query_total` 与 `rsdns_upstream_rcode_total` 同步增长；注入上游超时后 `rsdns_upstream_error_total{timeout}` 与 `rsdns_upstream_latency_seconds` 可见。
- 不引入新 crate 依赖；不改动既有指标语义（名称/标签不变）。

## 7. 风险与权衡

- **rcode/qtype 标签基数**：`rcode`/`qtype` 取值有限（DNS 标准枚举），基数可控，不会爆时间序列。
- **直方图内存**：每个 `le` 组合 × 标签组合存 `Vec<u64>`，标签仅 `proto`/`upstream`（少量），开销可忽略。
- **`assert_unique` 跨类唯一**：避免不同区域误用同名（如已有 `rsdns_upstream_query_total` 不会被重复注册），属收紧而非放宽。
- **不新增 `prometheus` crate**：保持离线构建依赖最小化（与现有 registry 设计一致）；直方图按 Prometheus 文本格式自渲染即可被任意 scraper 采集。
