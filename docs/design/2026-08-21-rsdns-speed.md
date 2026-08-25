# rsdns speed 插件：按测速结果对 A/AAAA 记录排序

> 2026-08-21 | 提案 v2
>
> v2 变更（按评审意见）：
> 1. **移除 metrics 与排序结果缓存**——插件不做任何指标埋点，也不缓存测速结果（每次命中都实测）；
> 2. 新增 **`enable` 使能开关，默认关闭**；
> 3. `prefer_family` 更名为 **`family`**，取值 `ANY`（默认）/ `A` / `AAAA`；**当请求类型与 family 匹配时才开始排序**。

## 1. 动机

CDN / 多活域名常返回多个 A（或 AAAA）记录，客户端（浏览器、App）通常取第一条或随机一条，
可能选到高延迟甚至不可达的节点。rsdns 需要一个 `speed` 插件：在返回给客户端之前，
对 A/AAAA 记录做一次真实连接测速（TCP 握手），按 RTT 升序重排应答，让客户端优先命中最快节点。

测速作为**通用函数**实现，放在 `plugins/speed.rs` 中，供本插件的排序阶段及其他插件
（如未来按延迟选上游、按延迟做 geo 分流的规则动作）复用。

## 2. 目标 / 非目标

### 目标

- 新增 `speed` 插件，配置项：`enable`（默认 `false`）、`type`（默认 `syn`）、`port`（默认 443）、
  `family`（默认 `ANY`）、`timeout`（默认 1s）。
- 仅当应答中 A/AAAA 记录数 ≥ 2 且请求类型与 `family` 匹配时生效；对记录测速后按 RTT 升序排序
  （CNAME 排最后，保持现有行为）。
- `groups` 每项支持 `skip_speed: true`，命中组时跳过测速排序。
- 测速函数通用化（`plugins/speed.rs` 内独立函数），可被其他插件复用。
- 不引入 metrics、不做测速结果缓存。

### 非目标

- 不做 UDP/ICMP 测速（TCP SYN 探测最接近真实场景且无需新依赖）。
- 不做测速结果跨查询缓存、不做指标埋点。
- 不改变上游查询、缓存、规则语义；仅对最终应答的 A/AAAA 记录排序。

---

## 3. 配置

### 3.1 `speed:` 顶层段

```yaml
speed:
  enable: true       # 使能开关，默认 false（关闭时不排序）
  type: syn          # 测速类型，默认 syn（当前仅支持 syn）
  port: 443          # 探测目标端口，默认 443
  family: ANY        # 排序的地址族：ANY(默认) / A / AAAA
  timeout: 1s        # 单次探测超时，默认 1s（支持 500ms / 2s 等时长写法）
```

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct SpeedConfig {
    #[serde(default)]
    pub enable: bool,            // 默认 false
    #[serde(default = "default_speed_type")]
    pub r#type: String,          // "syn"（当前唯一取值）
    #[serde(default = "default_speed_port")]
    pub port: u16,               // 默认 443
    #[serde(default = "default_speed_family")]
    pub family: String,          // "ANY" | "A" | "AAAA"
    #[serde(default = "default_speed_timeout")]
    pub timeout: String,         // 时长串：数字 = 秒，可带 ms/s/m 后缀
}
```

- `enable`：总开关，默认 `false`；`false` 时插件直接放行。
- `type`：仅接受 `syn`（默认）；其他值警告并回退 `syn`。
- `family`：`ANY`（默认）/ `A` / `AAAA`，决定哪些请求类型参与排序（见 §4.2）。
- `timeout`：单个 IP 的探测超时；默认 1 秒。

### 3.2 `groups[].skip_speed`

```yaml
groups:
  - name: cdn
    domains: [cloudflare.com]
    skip_speed: true   # 可选，默认 false：命中该组时跳过测速排序
```

`GroupConfig` 增加 `#[serde(default)] pub skip_speed: bool`，与既有 `skip_cache` 平行。

---

## 4. 行为

### 4.1 触发条件

speed 插件在管线末端（`rules` 之后、日志之前）对最终应答做**就地**排序，触发条件（全部满足才测速）：

1. `enable == true`；
2. `ctx.skip_speed == false`（未被组命中跳过）；
3. 请求类型与 `family` 匹配（见 §4.2）；
4. 应答中该类型的 address 记录数 ≥ 2；
5. 应答为正常地址记录（非 NXDOMAIN / SERVFAIL / 空应答）。

否则原样放行。

### 4.2 family 匹配与排序规则

`family` 决定**哪些请求类型参与排序**，以及**排序哪一族记录**：

| family | 参与排序的请求类型 | 排序的记录 |
|--------|--------------------|------------|
| `ANY`（默认） | A、AAAA（ANY 查询同时排 A 与 AAAA） | 请求对应的 A / AAAA 记录 |
| `A` | A、ANY | A 记录 |
| `AAAA` | AAAA、ANY | AAAA 记录 |

- 请求类型不匹配 → 不排序，原样放行。
- 排序稳定：RTT 相同或测速失败（超时/连接拒绝/不可达）的记录保持原相对顺序；失败的记录
  **排在所有成功记录之后**（成功按 RTT 升序），不剔除、不改变应答内容。
- CNAME 记录始终排最后（沿用 `sort_answers_cname_last` 语义，由 server 在 speed 之后统一处理）。
- 排序不改变应答内容，只调整 A/AAAA 记录的相对顺序。

### 4.3 测速（通用函数）

```rust
/// 对一组 IP 做并发 TCP 握手测速，返回 (ip, Ok(rtt)) 或 (ip, Err)。
/// 通用函数：供 speed 插件及其他插件复用。不缓存、不埋点。
pub async fn measure_tcp_latencies(
    ips: &[IpAddr],
    port: u16,
    timeout: Duration,
) -> Vec<(IpAddr, std::io::Result<Duration>)>
```

- 每个 IP 一个并发 future 探测（`futures::join_all`，IP 数量一般 < 32，可控）。
- 探测方式：`TcpStream::connect((ip, port))`，外部用 `tokio::time::timeout(timeout, ...)` 包裹。
- 返回后立即 `drop` 连接（只测握手，不做任何数据交换）。
- 同一 IP 在一次排序中只探测一次（先去重）。
- 失败（超时/拒绝/网络不可达）由调用方按 §4.2 处理。

### 4.4 管线位置

```
logs → hosts → groups → cache → rules → [speed] → CNAME 排末 → 日志/回写
```

speed 在 `rules`（终端阶段）之后执行：此时 `ctx.response` 已确定。若某次查询被缓存 Fresh
短路（在 rules 之前返回），speed 仍会对缓存应答排序——缓存命中场景同样受益于测速排序。

---

## 5. 示例

```yaml
speed:
  enable: true
  type: syn
  port: 443
  family: ANY
  timeout: 1s

groups:
  - name: cdn
    domains: [cloudflare.com]
    skip_speed: true   # 命中该组不测速排序
```

---

## 6. 实现清单

| 文件 | 内容 |
|------|------|
| `src/config.rs` | `SpeedConfig` + 时长解析；`GroupConfig.skip_speed` |
| `src/query.rs` | `QueryContext.skip_speed: bool` |
| `src/plugins/speed.rs`（新） | `Speed` 插件 + 通用 `measure_tcp_latencies`（无 metrics、无缓存） |
| `src/plugins/groups.rs` | 命中组设 `ctx.skip_speed` |
| `src/plugins/mod.rs` | 注册 `speed` 模块 |
| `src/server.rs` | `Pipeline` 增加 `speed` 字段；`handle_query` 在 rules 后调用 |
| `src/main.rs` | 初始化 `speed` 阶段 |
| `example/rsdns-all-example.yaml` | 增加 `speed:` 与 `skip_speed` 示例 |

依赖变更：无新增依赖（`tokio::net::TcpStream` 已有）。

## 7. 风险与权衡

- **探测开销**：每次排序产生 N 次 TCP 握手（N = 地址数），不做缓存意味着高频查询同一域名
  会重复探测；默认 `enable: false`，由用户显式开启。若未来需要，可再加 TTL 缓存。
- **安全**：探测目标来自上游应答（IP:port），仅 TCP 握手、不发数据、立即断开，不构成服务。
- **与 CNAME 排序**：沿用现有 `sort_answers_cname_last`，speed 只排 A/AAAA，CNAME 恒在末尾。
