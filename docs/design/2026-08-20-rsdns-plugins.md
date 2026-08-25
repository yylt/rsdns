# rsdns 插件化方案（logs / hosts / groups / cache / rules / upstream）

> 2026-08-20 | 提案 v3
>
> v2 变更（按评审意见）：
> 1. 顶层配置改为 `binds` / `groups` / `upstreams` 三个数组（`groups`、`upstreams` 带 `name` 字段），`groups` 每项新增 `skip_cache` 属性；
> 2. 查询管线改为**缓存优先**：`hosts → groups → cache → rules → upstream`；
> 3. `match` 语法**不考虑向后兼容**：不再支持裸分组名、`*.example.com`、`*`，仅支持空（匹配所有）、`group:{name}`、`{domain,domain}`（无大括号）、`{1}.{domain}` 占位符模板。
>
> v3 变更：
> 1. `groups` 每项新增 `auto_reload`（秒，仅对 `file://` / `https://` 数据源生效），支持按组周期重载；
> 2. 每组建**独立 `DomainSuffixTrie`**（非共享单 trie），重载隔离、周期独立、指标按组天然可分；
> 3. §6 细化 `{1}.{domain}` 占位符模板的全部具体形式与语法约束。
>
> v4 变更（按实现调整）：
> 1. `groups` 与 `hosts` 的 `file://` 源改用 **`notify` 库文件监控**，文件变化时主动重建并原子替换 trie，**移除 `auto_reload` 周期重载**；
> 2. **移除 `https://` 远程源**（`groups.domains` 仅支持内联域名与 `file://`）。

## 1. 动机

当前 `src` 的查询管线 `hosts → cache → rules → upstream` 与 `log` 被硬编码在 `server.rs::do_query` 与 `main.rs` 的启动流程中：

- `logs`、`hosts`、`cache`、`rules` 各自拥有配置结构，但初始化逻辑散落在 `main.rs`，行为被写死在 `do_query` 里。
- 规则 `match` 只支持“组名 / `*`”，无法表达“匹配所有”“内联域名集合”“占位符模板”。
- 没有任何可观测性：无法知道各环节命中率、错误率、耗时。

本提案把 `logs`、`hosts`、`groups`、`cache`、`rules`、`upstream` 全部重构为**一等插件**：

1. 每个插件**注册自己的配置段**，并用该配置**初始化自身**；
2. 查询管线变成一条**插件链**，缓存优先；`groups` 通过 `skip_cache` 控制缓存，`logs` 之外的插件可通过查询上下文控制“日志是否打印”“是否 cache”；
3. 规则 `match` 语法重新设计（见 §5）；
4. 每个插件**各自注册并暴露 metrics**，通过新增的 `metrics` HTTP 监听暴露 Prometheus 文本格式。

---

## 2. 目标 / 非目标

### 目标

- 统一的插件框架：`Plugin` trait、`PluginFactory`（注册配置 + 初始化）、`PluginRegistry`、`PluginHub`（插件间能力交换）、查询上下文 `QueryContext`。
- 迁移 `logs / hosts / groups / cache / rules / upstream` 为插件。
- 顶层配置数组化：`binds`、`groups`、`upstreams`（带 `name`），`groups` 带 `skip_cache`。
- 查询管线缓存优先：`hosts → groups → cache → rules → upstream`。
- 规则 `match` 新语法（§5），支持占位符替换。
- 每插件注册 metrics；新增 `/metrics` 端点。

### 非目标

- 不做插件热加载 / 动态编译（插件在启动期静态注册）。
- 不引入 gRPC/管理 API 暴露 metrics（用独立轻量 HTTP 端点）。
- 不改上游连接池内部算法（`pool.rs`），只增加指标埋点。
- `match` 不做任何旧语法兼容（裸分组名 / `*.example.com` / `*` 一律报配置错误）。

---

## 3. 总体设计

### 3.1 顶层配置结构（数组化）

```yaml
binds:                      # 数组：监听地址（非插件，server 使用）
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"

groups:                     # 数组：域名分组，带 name / skip_cache
  - name: ad
    domains:
      - file:///etc/rsdns/ad.txt          # 文件源（notify 监控，变化自动重载）
      - doubleclick.net                   # 内联静态域名
    skip_cache: true        # 可选，默认 false：命中该组时跳过缓存
  - name: intranet
    domains: [corp.internal, lan]

upstreams:                  # 数组：上游池，带 name
  - name: default
    mode: serial
    servers:
      - address: 223.5.5.5
        bootstrap: true
      - address: tls://dot.pub
  - name: overseas
    mode: parallel
    servers:
      - address: tls://8.8.8.8
```

```rust
pub struct Config {
    pub binds: Vec<BindConfig>,                  // { address }
    pub groups: Vec<GroupConfig>,                // { name, domains, skip_cache }
    pub upstreams: Vec<UpstreamGroupConfig>,     // { name, mode, servers }
    #[serde(flatten)]
    pub plugin_sections: BTreeMap<String, serde_yaml::Value>, // rules / cache / log / metrics / plugins
}

pub struct GroupConfig {
    pub name: String,
    /// 域名条目：内联域名、"file://..."。
    /// 数据层剥除 "*." 前缀；每行支持 "#" 注释与空行。
    pub domains: Vec<String>,
    #[serde(default)]
    pub skip_cache: bool,
}

pub struct UpstreamGroupConfig {
    pub name: String,
    #[serde(default)]
    pub mode: QueryModeConfig,     // serial | parallel
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
}
```

> 变更：`bind` → `binds`、`groups` 从 `HashMap<String, Vec<String>>` 变为 `Vec<GroupConfig>`、`upstream` → `upstreams`（数组 + `name`）。`rules / cache / log / metrics` 仍为顶层段，由对应插件消费。

### 3.2 查询管线：缓存优先

新管线为一条有序插件链（按 `PluginFactory::order()` 排序）：

```
logs(0) → hosts(10) → groups(15) → cache(20) → rules(30) → upstream(40)
```

| 顺序 | 插件 | 行为 |
|------|------|------|
| 0 | `logs` | 外层包裹：进入时计时，回卷时按 `ctx.skip_log` 决定是否打印；本身不短路 |
| 10 | `hosts` | 静态映射命中 → `Respond`（硬性覆盖，语义同现在） |
| 15 | `groups` | 解析域名归属组，设 `ctx.group` / `ctx.skip_cache`，**不短路** |
| 20 | `cache` | 缓存优先：`skip_cache` → 直接 `Continue`；Fresh → `Respond`；Miss → `Continue`；回卷后按 `ctx.skip_cache` 决定是否写入 |
| 30 | `rules` | 顺序匹配：block/cname → `Respond`；forward → 设 `ctx.upstream` 并 `Continue`；无匹配 → NXDOMAIN `Respond` |
| 40 | `upstream` | 终端：按 `ctx.upstream` 查询上游，写 `ctx.response`；经 `PluginHub` 提供给 rules 的 forward/cname 使用 |

要点：

- **缓存优先**：Fresh 命中在 rules 之前短路返回，规则不参与（保留旧行为）。需要绕过缓存时，用 `groups` 的 `skip_cache: true`（在 cache 之前已解析）。
- **“在 logs、cache 之后插件可控制日志/是否 cache”**：
  - 日志：`logs` 是最外层，任意链上插件（groups/cache/rules/自定义）写 `ctx.skip_log`，回卷时 `logs` 据此不打印；
  - 缓存：`groups`（cache 之前）写 `ctx.skip_cache` 控制**查询与写入**；cache 之后的插件（rules、自定义 `after: cache` 插件）可在回卷路径设 `ctx.skip_cache` 控制**写入与后续刷新**；自定义插件也可用 `before: cache` 锚点插入 cache 之前控制查询。

### 3.3 核心类型

```rust
// plugin.rs —— 插件框架核心

pub type PluginFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 查询上下文：贯穿整条链。
pub struct QueryContext {
    pub msg: Message,
    pub key: CacheKey,
    pub client: SocketAddr,
    pub proto: &'static str,
    pub start: Instant,

    // 控制位 —— 插件可控制
    pub skip_log: bool,     // logs 回卷时不打印
    pub skip_cache: bool,   // cache 跳过查询与写入

    // 状态
    pub response: Option<Message>,
    pub action: String,
    pub upstream: Option<String>,   // forward 目标（rules 设置）
    pub group: Option<String>,      // 域名归属组（groups 设置）
}

// 实现注：初版未保留 scratch 字段——占位符解析经 hub 完成，跨插件共享
// 数据暂不需要；如后续插件需要可重新加入。

pub enum Decision {
    Continue,   // 交给下一个插件
    Respond,    // ctx.response 已就绪，短路回卷
}

pub struct Next<'a> { /* ... */ }
impl<'a> Next<'a> {
    pub fn call(self, ctx: &mut QueryContext) -> PluginFuture<'a, Decision>;
}

pub trait Plugin: Send + Sync {
    fn name(&self) -> &'static str;
    fn register_metrics(&self, registry: &MetricsRegistry);
    fn handle<'a>(&'a self, ctx: &'a mut QueryContext, next: Next<'a>) -> PluginFuture<'a, Decision>;
}
```

链运行器（`server.rs::do_query` 的替代）：

```rust
pub async fn run_chain(plugins: &[Box<dyn Plugin>], ctx: &mut QueryContext) -> Decision {
    async fn step(i: usize, plugins: &[Box<dyn Plugin>], ctx: &mut QueryContext) -> Decision {
        if i == plugins.len() { return Decision::Respond; } // 链尾：无应答则 SERVFAIL
        let next = Next::new(move |ctx| step(i + 1, plugins, ctx));
        plugins[i].handle(ctx, next).await
    }
    step(0, plugins, ctx).await
}
```

> 说明：`Plugin::handle` 用 `BoxFuture` 形式而非 `async-trait`，与仓库 `common::BoxFuture` 风格一致、不加依赖；如实现时希望更直观，可引入 `async-trait`（二选一，倾向前者）。

### 3.4 配置注册：PluginFactory 与 PluginRegistry

```rust
pub trait PluginFactory: Send + Sync {
    fn name(&self) -> &'static str;                 // "logs" / "hosts" / "groups" / "rules" / "cache" / "upstream"
    fn config_key(&self) -> &'static str;           // YAML 段名："log" / "hosts" / "groups" / "rules" / "cache" / "upstreams"
    fn order(&self) -> u8;                          // 链内排序：0/10/15/20/30/40
    fn default_config(&self) -> serde_yaml::Value;  // 未配置时使用
    fn build(&self, raw: &serde_yaml::Value, hub: &PluginHub)
        -> Result<Box<dyn Plugin>, ConfigError>;    // 用配置初始化自身
}

pub struct PluginRegistry {
    factories: Vec<Box<dyn PluginFactory>>,
    pub metrics: MetricsRegistry,
    pub hub: PluginHub,
}

impl PluginRegistry {
    pub fn register(&mut self, f: impl PluginFactory + 'static);   // 内建在 main.rs 注册
    pub fn load(&self, config: &Config) -> Result<Vec<Box<dyn Plugin>>, ConfigError>;
}
```

`PluginRegistry::load` 对每个已注册 factory：取 `plugin_sections[config_key]`（缺省用 `default_config()`；`binds/groups/upstreams` 直接从 `Config` 字段读取）→ `factory.build(raw, hub)` → 按 `order()` 排序成链。

**扩展点**：自定义插件通过 `plugins:` 列表注册（见 §7），通过 `PluginHub` 获得/提供能力（占位符解析器、upstream 提供者），并声明 `after/before` 锚点插入链中。

### 3.5 PluginHub（插件间能力交换）

```rust
pub struct PluginHub {
    upstreams:    RwLock<Option<Arc<dyn UpstreamProvider>>>,
    placeholders: RwLock<AHashMap<u32, Vec<Arc<dyn PlaceholderResolver>>>>,
}

pub trait UpstreamProvider: Send + Sync {
    async fn query(&self, name: &str, msg: &Message) -> io::Result<Message>;
}
```

- `upstream` 插件初始化后向 hub 注册 `UpstreamProvider`；rules 插件的 forward/cname 动作通过 hub 调用。
- 占位符解析器（§6）由后续插件注册，rules 匹配时查询。
- `groups` 插件的组数据（域名 trie + skip_cache）为共享服务，通过 hub 暴露 `GroupProvider`，供 cache（可选）与 rules 使用。

---

## 4. 各插件设计

每个插件一个文件（`src/plugins/*.rs`），各自拥有：配置类型、初始化、链行为、**metrics**。

### 4.1 `logs` 插件（`plugins/logs.rs`）

- 配置：`LogConfig`（现有字段 + `enabled`，默认 true；保留 `format/file/buf_size/flush_interval_secs`）。
- 行为：外层包裹。`before` 记 `Instant`；`next.call` 后组装 `QueryLog`；若 `ctx.skip_log` 则跳过打印（计 `skipped`）。
- 迁移：现有 `QueryLogger` / 模板编译 / 异步写盘逻辑整体移入，接口不变。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_logs_queries_total{proto}` | Counter | 实际打印的查询数（proto=udp/tcp） |
| `rsdns_logs_skipped_total` | Counter | 因 `skip_log` 跳过的查询数 |
| `rsdns_logs_write_errors_total` | Counter | 写盘失败次数 |
| `rsdns_logs_flush_total` | Counter | flush 次数 |

### 4.2 `hosts` 插件（`plugins/hosts.rs`）

- 配置：`HostsConfig { entries: Vec<String> }`（顶层 `hosts:` 列表）。
- 行为：查 `HostsTrie`（现有 FST 实现），命中 → 构造应答 `Respond`。
- `file://` 源：启动期加载；随后用 `notify` 监控每个文件，变化时重建 trie 并原子替换（与 `groups` 相同机制）。
- 迁移：`hosts.rs` 的 `HostsTrie/Builders` 移入，`main.rs::build_hosts_trie/parse_hosts_line` 移入插件。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_hosts_lookup_total` | Counter | 查找次数 |
| `rsdns_hosts_hit_total` | Counter | 命中次数 |
| `rsdns_hosts_miss_total` | Counter | 未命中次数 |
| `rsdns_hosts_entries` | Gauge | 加载条目数 |
| `rsdns_hosts_file_load_errors_total` | Counter | `file:` 加载失败次数 |

### 4.3 `groups` 插件（`plugins/groups.rs`）

- 配置：`Vec<GroupConfig>`（顶层 `groups:` 数组，含 `name/domains/skip_cache`）。
- 数据模型：**每个组一张独立的 `DomainSuffixTrie`**（`GroupTrie`，见下），不共享一张大 trie。
- 行为：不短路。按配置顺序逐组 `lookup(domain)`，**首个命中组**设 `ctx.group = Some(name)`；若该组 `skip_cache` → 设 `ctx.skip_cache = true`；全不命中 → `ctx.group = None`，`skip_cache` 保持原值。
- 迁移：`main.rs::build_groups_trie` 移入；`domain_trie` 复用现有 FST，每组一个实例。

#### 4.3.1 每组独立 domain_trie（为何更好）

独立 trie 相对共享 trie 的优势：

| 维度 | 共享单 trie | 每组独立 trie（采用） |
|------|-------------|------------------------|
| 重载隔离 | 任一组成员变更需**重建整棵树**并原子切换全局引用 | 只重建变更组，其余组引用不动 |
| 数据源 | 混合 file 后难按组管理 | 每组可独立管理 file 源与版本 |
| 指标 | 按组计数需额外 tag 索引 | 天然按组（`rsdns_groups_hit_total{group}`） |
| 构建失败 | 任一组失败影响全部 | 只影响该组（该组保留旧 trie，其余正常） |
| 查询开销 | 1 次 lookup | G 次 lookup（G = 组数，通常 < 10，FST 为 ns 级，可接受） |

**语义**：同域多组时按配置顺序取**首个命中组**（先配置优先），需文档化。

#### 4.3.2 数据模型与查询

```rust
pub struct GroupTrie {
    trie: DomainSuffixTrie,      // 反转发域名 → 该组固定 tag（如 "hit"）
    version: u64,                // 重建版本（供 metrics / 调试）
}

pub struct GroupsPlugin {
    groups: Vec<GroupState>,     // 配置顺序 = 匹配优先级
    by_name: AHashMap<String, usize>,
}

pub struct GroupState {
    name: String,
    skip_cache: bool,
    files: Vec<GroupFile>,       // 内联域名 / file:// 源
    current: RwLock<GroupTrie>,  // 当前生效 trie（文件变化时原子替换）
}
```

`handle` 匹配：

```rust
for g in &self.groups {
    if g.current.read().trie.lookup(domain).is_some() {
        ctx.group = Some(g.name.clone());
        if g.skip_cache { ctx.skip_cache = true; }
        return next.call(ctx).await;   // 找到首个命中组即继续
    }
}
next.call(ctx).await  // 未命中任何组
```

#### 4.3.3 数据源加载与 `notify` 文件监控

- **内联域名**：启动期构建，永不重载。
- **`file://` 源**：启动期加载并构建；随后用 **`notify`**（`recommended_watcher`）监控每个文件，文件变化时：
  1. 重新读取文件（`read_to_string`；读取失败保留旧 trie 并告警，不中断服务）；
  2. 校验变更（内容指纹不同才重建）；
  3. 解析（去空白/`#` 注释/空行、剥 `*.` 前缀）→ 构建新 `DomainSuffixTrie` → 原子替换 `current` → `version += 1`。
- 同一组可混合内联 + file 源；重载只替换 file 源，内联部分保留。
- 行格式：每行一个域名或 `*.domain`（剥前缀）；`#` 注释、空行忽略。
- watcher 句柄由 tokio 任务持有直到进程退出，保持监控存活。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_groups_lookup_total` | Counter | 分组解析次数 |
| `rsdns_groups_hit_total{group}` | Counter | 命中组（label=组名） |
| `rsdns_groups_miss_total` | Counter | 未命中任何组 |
| `rsdns_groups_skip_cache_total{group}` | Counter | 因组 `skip_cache` 跳过缓存的次数 |
| `rsdns_groups_groups` | Gauge | 组数量 |
| `rsdns_groups_load_errors_total{group}` | Counter | 初始加载失败次数（file） |
| `rsdns_groups_reloads_total{group}` | Counter | 文件变化触发的重载成功次数 |
| `rsdns_groups_reload_errors_total{group}` | Counter | 自动重载失败次数（保留旧 trie） |
| `rsdns_groups_entries{group}` | Gauge | 各组当前 trie 条目数 |

### 4.4 `cache` 插件（`plugins/cache.rs`）

- 配置：`CacheConfig`（现有字段不变）。
- 行为（缓存优先）：
  - 查询：`ctx.skip_cache` → 直接 `Continue`；否则 `get_cached`：Fresh → 构造应答 `Respond`；Miss → `Continue`。
  - 写入：`next.call` 回卷后，若 `!ctx.skip_cache` 且响应来自上游（`ctx.action` 为 forward 系列）→ `cache_upstream_response`。
- 迁移：`cache.rs` 的 `DnsCache` 移入，`server.rs` 的 `cache_upstream_response / forward_to_upstream_bg` 移入。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_cache_lookup_total{result}` | Counter | 查询结果：fresh / miss |
| `rsdns_cache_bypass_total` | Counter | 因 `skip_cache` 跳过查询/写入的次数 |
| `rsdns_cache_insert_total` | Counter | 写入次数 |
| `rsdns_cache_evict_total` | Counter | LRU 淘汰次数（moka `eviction_listener`） |
| `rsdns_cache_entries` | Gauge | 当前条目数 |
| `rsdns_cache_ttl_clamped_total` | Counter | TTL 被 min/max 钳制次数 |

### 4.5 `rules` 插件（`plugins/rules.rs`）

- 配置：`Vec<RuleConfig>`（顶层 `rules:` 数组）。
- 行为：顺序匹配；block/cname → 构造应答 `Respond`；forward → 设 `ctx.upstream`、`Continue`；无匹配 → NXDOMAIN `Respond`。
- 迁移：`rule.rs` 的 `Rule/RuleAction/BlockResponse` 移入；`server.rs` 的 block/cname/forward 构造逻辑移入。
- 扩展：实现 `MatchTarget` 新语法与占位符解析（§5、§6）。
- **变更**：`forward` 动作移除 `cache` 字段——缓存控制统一由 `groups.skip_cache`（查询+写入）与链上 `ctx.skip_cache` 承担，规则自身不再表达缓存策略。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_rules_evaluated_total` | Counter | 参与匹配的查询数 |
| `rsdns_rules_matched_total{action}` | Counter | 命中动作：block-nxdomain / block-poison / cname / forward / nxdomain |
| `rsdns_rules_placeholder_resolved_total{status}` | Counter | 占位符解析：ok / unresolved |
| `rsdns_rules_parse_errors_total` | Counter | 规则配置解析错误数（含非法 match 语法） |

### 4.6 `upstream` 插件（`plugins/upstream.rs`，服务型能力）

- 配置：`Vec<UpstreamGroupConfig>`（顶层 `upstreams:` 数组，含 `name`）。
- 行为：不常驻链中；初始化构建 bootstrap → 解析域名 → 组装 `UpstreamGroup`（按 name 索引），向 hub 注册 `UpstreamProvider`。
- 迁移：`main.rs` 中 `parse_upstream / bootstrap_resolve_all / build_bootstrap_pools / build_resolved_pool` 及 `pool.rs` 移入/保持；`pool.rs` 增加指标埋点。

Metrics：

| 指标 | 类型 | 说明 |
|------|------|------|
| `rsdns_upstream_query_total{upstream,proto}` | Counter | 查询数（proto=udp/tcp/tls/doh/doh3/doq） |
| `rsdns_upstream_error_total{upstream,kind}` | Counter | 错误：timeout/refused/reset/other |
| `rsdns_upstream_rcode_total{upstream,rcode}` | Counter | 应答 rcode |
| `rsdns_upstream_latency_seconds{upstream}` | Histogram | 查询耗时 |
| `rsdns_upstream_pool_connections{upstream}` | Gauge | 池内连接数 |
| `rsdns_upstream_pool_checkout_total{result}` | Counter | checkout 成功/失败 |
| `rsdns_upstream_pool_cooldown_total{upstream}` | Counter | 地址进入冷却次数 |

### 4.7 服务级 metrics 与 `metrics` 插件（`plugins/metrics.rs`）

服务级（非链插件）：`dns_queries_total{proto}`、`dns_query_duration_seconds`（Histogram）、`dns_responses_total{rcode}`。

`metrics` 插件拥有 `MetricsRegistry` 并启动 HTTP 监听：

```yaml
metrics:
  bind: "0.0.0.0:9153"
  path: "/metrics"        # 默认 /metrics
```

实现复用仓库已有依赖 `hyper` + `hyper-util`（参照 `src/proxy/api.rs` 的 http1 service_fn 模式）：`GET /metrics` → `TextEncoder` 输出文本格式。未配置 `metrics:` 则不监听，指标仍在内存计数。

### 4.8 `MetricsRegistry`

```rust
// metrics.rs —— 手写文本编码（无外部依赖；接口与 prometheus 客户端对齐）
pub struct MetricsRegistry;   // 内部：counters/gauges/histograms 三组 family
impl MetricsRegistry {
    pub fn counter(&self, name: &str, help: &str, labels: &[&str]) -> Counter;
    pub fn gauge(&self, name: &str, help: &str, labels: &[&str]) -> Gauge;
    pub fn histogram(&self, name: &str, help: &str, labels: &[&str], buckets: &[f64]) -> Histogram;
    pub fn encode_text(&self) -> String;   // Prometheus text format
}
```

- **实现决策**：采用约 150 行手写文本编码，**未引入 `prometheus` crate**（离线构建无该依赖，且仅需文本格式）。`Counter`/`Gauge`/`Histogram` 均带 label 值句柄（`with_label_values` 返回携带 label 的克隆），直方图为标准累积桶 + `_sum`/`_count`。
- 指标名统一 `rsdns_<plugin>_<name>`，每个插件在 `register_metrics` 中注册自己的指标（满足“各插件需注意有各自的 metrics”）。
- `metrics:` 插件配置 `{bind, path}`，由 main 在启动时 `serve_metrics` 起 hyper http1 监听；未配置 `metrics:` 则不监听，指标仍在内存计数。
- 依赖变更：**不新增依赖**（§10 已更新）。

---

## 5. 规则 match 语法（无向后兼容）

`RuleConfig.match` 改为 `Option<String>`（`#[serde(default)]`，支持 `alias = "r#match"`），构建期解析为 `MatchTarget`。**仅支持以下四种形式**，其余一律报配置错误（`rules_parse_errors_total`）：

| 写法 | 含义 | 示例 |
|------|------|------|
| （缺省 / 空字符串） | 匹配所有 | `match:` 或 `match: ""` |
| `group:{name}` | 引用 `groups` 数组中的组（匹配 `ctx.group == name`） | `match: group:ad` |
| `{domain,domain}` | 内联域名集合（**无大括号**，逗号分隔；任一后缀匹配即命中） | `match: a.com,b.com` |
| `{1}.{domain}` | 占位符模板，`{N}` 由插件替换为具体 label 后做后缀匹配 | `match: "{1}.example.com"` |

**不再支持**：裸分组名（`match: ad`）、`*.example.com`、`*`、`match: "*.banned.example"` 等任何旧写法。

```rust
pub enum MatchTarget {
    MatchAll,                    // 空 / 缺省
    Group(String),               // group:{name}
    InlineDomains(Vec<String>),  // {a.com,b.com} 无大括号；单域名视为单元素列表
    Template(TemplatePattern),   // {1}.example.com
}

pub struct TemplatePattern { tokens: Vec<TemplateToken> }
pub enum TemplateToken {
    Label(String),      // 字面 label
    Placeholder(u32),   // {N}，N 从 1 开始
}

fn parse_match_target(s: &str) -> Result<MatchTarget, ConfigError>;
```

匹配语义：

- `MatchAll`：恒真。
- `Group`：`ctx.group == Some(name)`（groups 插件已在 cache 之前解析好归属组）。
- `InlineDomains`：任一域名后缀匹配（子域命中）；构建期合并进一个 `DomainSuffixTrie`（以规则序号为 tag）避免逐条扫描。
- `Template`：匹配时把每个 `Placeholder(n)` 用已注册解析器替换成具体 label，拼接成完整后缀模式再匹配；**任一占位符无解析器/解析失败 → 该规则不匹配**（计 `placeholder_resolved_total{status="unresolved"}`）。

> 单裸域名（如 `match: example.com`）视为**单元素内联列表**（后缀匹配）。若需严格只允许逗号分隔的多域名，可在实现期收紧为“必须含逗号”——本提案按“单域名=单元素内联列表”设计，待确认。

---

## 6. 占位符模板（`{1}.{domain}`）的具体形式

### 6.1 模板模型

模板 = 用 `.` 切分的 **label 序列**，每个 label 要么是字面量，要么是 `{N}` 占位符（N ≥ 1 的整数）。解析产物为 `TemplatePattern { tokens: Vec<TemplateToken> }`，匹配时把每个 `Placeholder(N)` 替换为解析器返回的**单个 label**（不含 `.`），再拼回完整域名做后缀匹配。

```rust
// 解析：输入 "{1}.{2}.example.com" → tokens:
//   [Placeholder(1), Label("."), Placeholder(2), Label("."), Label("example"), Label("."), Label("com")]
fn parse_template(s: &str) -> Result<TemplatePattern, ConfigError>;
```

- 以 `.` 为分隔：label 之间必须有点分隔；`.` 本身是**字面 label 边界**，不构成独立 token。
- 占位符 label 替换值**不允许含 `.`**（若解析器返回含点值，视为解析失败 → 该规则不匹配）。
- 字面 label 校验与正常域名 label 一致（`[a-z0-9-]`，IDN 先 punycode）；不含任何 `{`/`}` 的字符串直接归入 `InlineDomains`/`MatchAll` 分支，不走模板。

### 6.2 具体形式（全量）

| 形式 | 模板串 | 占位符 | 替换后匹配目标 | 典型用途 |
|------|--------|--------|----------------|----------|
| 单占位符 + 字面后缀 | `{1}.example.com` | `{1}` | `<r1>.example.com`（含 example.com 子域） | geoip 国家码、ISP、CDN 节点 |
| 字面前缀 + 占位符 | `cdn.{1}.com` | `{1}` | `cdn.<r1>.com` | 按客户端解析 cdn 子域 |
| 多占位符组合 | `{1}.{2}.example.com` | `{1}`,`{2}` | `<r1>.<r2>.example.com` | 地域+运营商 组合 |
| 占位符在中间 | `{1}.cn.{2}.com` | `{1}`,`{2}` | `<r1>.cn.<r2>.com` | 复合模板 |
| 纯占位符（无字面 label） | `{1}` | `{1}` | `<r1>`（仅命中该 label 本身） | 单 label 后缀匹配（较少用） |
| 无占位符 | `example.com` | 无 | 整个域名 | 归入 InlineDomains，不走模板 |

**约束**：

1. 占位符 `{N}` 中 N 为 ≥ 1 的整数；`{0}`、`{abc}`、`{1.5}`、不闭合的 `{1` 均为**非法**，报配置错误；
2. 相邻 label 之间必须有 `.` 分隔（`{1}{2}` 非法）；字符串首尾不允许是 `.`；
3. 字面 label 之间可含 `-`，但 `-` 不能作为标签首字符（沿用域名规则）；
4. `{N}` 与 `{domain}` 中 `{domain}` 是**示意**（表示“一个真实域名”），不是可替换 token；模板中真正的可替换 token 只有 `{N}`；
5. 同一规则内 `{N}` 可重复出现（如 `{1}.{1}.example.com`，两个 `{1}` 解析为同一值，同一解析器按 idx 调用，实现需缓存同 idx 结果）；
6. 模板匹配按替换后的**完整后缀匹配**（子域命中），与 `InlineDomains` 语义一致。

### 6.3 解析器注册与匹配流程

```rust
pub trait PlaceholderResolver: Send + Sync {
    /// 根据查询上下文把占位符 {idx} 替换为具体 label（不允许含 '.'）。
    fn resolve(&self, idx: u32, ctx: &QueryContext) -> Option<String>;
}
```

- 解析器通过 `PluginHub.placeholders` 按 `{N}` 索引注册；一个 idx 可注册多个解析器（如 geoip + asn），匹配时依次尝试，**首个成功**的结果生效；全部失败 → 该规则不匹配（计 `placeholder_resolved_total{status="unresolved"}`）。
- 匹配流程（仅含占位符的规则）：

```
for rule in rules {
    if rule.target is Template:
        labels = []
        for token in rule.tokens:
            match token {
                Label(l) => labels.push(l),
                Placeholder(n) => labels.push(resolve(n, ctx)?),   // 失败 → 本规则不匹配，尝试下一条
            }
        pattern = labels.join(".")
        if suffix_match(pattern, domain) { hit }
    else if rule.target.matches(ctx) { hit }
}
```

- 占位符解析器经 `PluginHub.register_placeholder(idx, resolver)` 注册（一个 idx 可注册多个，匹配时首个成功生效）。**当前实现**：`groups` 插件注册 `{1}` → 查询所属组名（`ctx.group`），供 `match: "{1}.example.com"` 这类“组名子域”匹配；geoip/asn 等解析器属后续插件扩展。
- 无占位符的规则零开销；含占位符的规则仅在匹配时做一次替换 + 后缀比较，并按结果计 `placeholder_resolved_total{status="ok|unresolved"}`。

### 6.4 示例

```yaml
# groups 插件注册 {1} 解析器：{1} = 查询所属组名（ctx.group）
# 客户端命中组 cdn（cloudflare.com）→ 匹配 cdn.cloudflare.com（及子域）
- match: "{1}.cloudflare.com"
  action: { type: forward, upstream: default }

# 内联域名集合（无大括号，逗号分隔）
- match: "a.com,b.com"
  action: { type: block, response: nxdomain }

# 字面前缀 + 占位符（未来可由 geoip 等插件提供 {1}）
- match: "cdn.{1}.com"
  action: { type: forward, upstream: cdn-pool }
```

---

## 7. 自定义插件（扩展点）

```yaml
plugins:
  - name: myfilter
    after: rules            # 或 before: cache / order: 25
    config:
      deny_suffixes: [".ads"]
```

- 注册方式：启动时 `registry.register(myfactory)`；`myfactory.config_key` 与 `plugins:` 列表中的 `name` 对应。
- 自定义插件可：向 `PluginHub` 注册占位符解析器；在链内任意位置设 `ctx.skip_log/skip_cache`（`after: cache` 时控制缓存写入与日志，`before: cache` 时控制缓存查询）；注册自己的 metrics。
- 本提案只定义机制，不实现具体自定义插件。

---

## 8. 配置示例

```yaml
binds:
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"

groups:
  - name: ad
    domains:
      - file:///etc/rsdns/ad-block.txt      # 文件源，notify 监控、变化自动重载
      - doubleclick.net                     # 内联静态域名
    skip_cache: true                        # 命中该组直接绕缓存
  - name: intranet
    domains: [corp.internal, lan]

upstreams:
  - name: default
    mode: serial
    servers:
      - address: 223.5.5.5
        bootstrap: true
      - address: tls://dot.pub
  - name: overseas
    mode: parallel
    servers:
      - address: tls://8.8.8.8

cache:
  size: 4096
  min_ttl: 60
  max_ttl: 3600

hosts:
  - "127.0.0.1 localhost"
  - "0.0.0.0 *.ad-domain.com"

log:
  enabled: true
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'

metrics:
  bind: "0.0.0.0:9153"
  path: /metrics

rules:
  # 1) 空 match = 匹配所有（最后兜底）
  - match: ""
    action: { type: forward, upstream: default }
  # 2) 组引用
  - match: group:ad
    action: { type: block, response: poison }
  # 3) 内联域名集合（无大括号，逗号分隔，后缀匹配）
  - match: foo.com,foo.org
    action: { type: forward, upstream: default }
  # 4) 占位符模板：{1} 由插件替换（如 geoip 国家码）
  - match: "{1}.example.com"
    action: { type: forward, upstream: default }
```

---

## 9. 行为变化

1. **配置形状**：`bind` → `binds`、`groups` 数组化（含 `skip_cache`）、`upstream` → `upstreams` 数组化（含 `name`）。旧配置不兼容，需迁移。
2. **缓存优先**：Fresh 命中在 rules 之前短路返回（与旧行为一致）；要绕过缓存用 `groups.skip_cache`，不再有规则级 `cache:false`（`forward.cache` 字段移除）。
3. **match 语法**：仅四种形式；裸分组名 / `*.example.com` / `*` 报配置错误。
4. **groups 提前解析**：域名归属组在 cache 之前解析（order 15），用于 `skip_cache` 与 rules 的 `group:` 匹配。
5. **每组独立 trie + notify 文件监控**：`groups` 与 `hosts` 的 `file://` 源由 `notify` 监控，文件变化主动重建并原子替换 trie；不再有 `auto_reload` 周期，`groups` 不支持 `https://` 远程源。同域多组按配置顺序取首个命中组。

**性能影响**：每次查询多 G 次 groups FST 查找（G = 组数，通常 < 10，FST 为 ns 级）；Fresh 命中时只经过 hosts + groups，不经过 rules。

---

## 10. 实现清单（全部完成）

| 阶段 | 文件 | 内容 | 状态 |
|------|------|------|------|
| P1 框架 | `plugin.rs`（新）、`metrics.rs`（新） | `Plugin / PluginFactory / PluginRegistry / PluginHub / QueryContext / Next / Decision`；手写 `MetricsRegistry`（§4.8） | ✅ |
| P2 配置重构 | `config.rs` | `binds / groups / upstreams` 数组化；`plugin_sections` flatten；移除 `forward.cache` | ✅ |
| P3 迁移 | `plugins/logs.rs`、`plugins/hosts.rs`、`plugins/groups.rs`、`plugins/rules.rs`、`plugins/cache.rs`、`plugins/upstream.rs` | 各插件拥有配置 + 初始化 + 链行为 + metrics；`server.rs::do_query` 改为 `run_chain`；`main.rs` 注册工厂组装链；groups 独立 trie + 加载器 | ✅ |
| P3.5 组重载 | `plugins/groups.rs` | `notify` 文件监控：file 读取、内容指纹变更检测、原子替换 trie、reload metrics | ✅ |
| P4 规则扩展 | `plugins/rules.rs` | `MatchTarget` 新语法解析（无旧语法）；`TemplatePattern`；`PlaceholderResolver` 注册与匹配（当前 `{1}` = 组名） | ✅ |
| P5 metrics 端点 | `plugins/metrics.rs`、`main.rs`、`pool.rs` | `metrics:` 配置 + hyper http1 `/metrics` 监听；`pool.rs` 埋点（checkout/connections/cooldown） | ✅ |
| P6 收尾 | `example/rsdns-all-example.yaml`、`src/**` tests | 示例更新为新格式；单测 34 项全通过；冒烟验证 UDP/TCP + 指标 | ✅ |

依赖变更：**新增 `notify`**（8.2，`default-features = false`，开启 `macos_kqueue` 使 macOS 上仍用内核事件而非轮询）——`groups` 与 `hosts` 的 `file://` 源用它做文件监控；metrics 采用手写文本编码（见 §4.8，离线构建无 `prometheus` crate）；hyper/hyper-util/hyper-rustls/moka 均为仓库既有依赖（hyper-rustls 增开 `http1` feature 供 DoH 与 metrics 客户端使用）。

## 11. 风险与权衡

- **配置不兼容**：v2/v3/v4 破坏性变更（数组化 + match 语法收紧 + `file:` → `file://` 源格式 + 移除 `auto_reload` / `https://` 源），示例与文档需同步重写；属有意为之。
- **每组独立 trie 的查询开销**：G 次 FST lookup（G 通常 < 10）；若未来组数上百需评估退化方案（如按命中率排序或合并索引）。
- **`notify` 文件监控**：依赖平台文件系统事件；编辑器“另存为”（rename 替换）通过监听文件路径的 Create/Modify/Remove 事件覆盖，个别环境（如跨文件系统原子替换）可能收不到事件，此时可考虑回退到父目录监控或轮询。
- **`prometheus` 依赖**：已采用手写编码（§4.8），`MetricsRegistry` 接口保持与 prometheus 客户端一致，未来可无缝替换。
- **async trait**：采用 `BoxFuture` 风格避免新依赖；如可接受 `async-trait` 则更直观。
- **moka eviction 计数**：`evict_total` 已通过 moka 0.12 `eviction_listener` 实现（确认可用）。
- **单裸域名 match**：按“单元素内联列表”处理（`validate_domain` 校验标签合法性）。
