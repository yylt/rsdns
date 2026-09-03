# rsdns forward rule Cloudflare ECH 补全：`cloudflare_ech` 配置与 HTTPS 应答替换

- 日期: 2026-09-03
- 状态: 已实现

## 1. 动机

部分只返回 CDN 边缘 IP 的解析链路（如走 `forward` 到自建/上游解析器，或上游
按来源网络裁剪了 HTTPS SVCB 记录）拿到的 HTTPS(SVCB) 应答**缺少 `ech` SvcParam**
（draft-ietf-tls-svcb-ech）。客户端需要 ECH 配置才能发起 ECH 连接；本地 DNS 拿
不到时，回退到明文 ClientHello，隐私/抗封锁能力丢失。

Cloudflare 的常见形态：某域名（或域名的 HTTPS 记录本身）解析到的 A 记录落在
Cloudflare 的 IP 网段内，但应答里的 HTTPS 记录是"无 ech"模板（即使用
`alpn`/`ipv4hint` 等、不含 `ech`）。此时可以用 Cloudflare 官方发布的、始终携带
`ech` 的 HTTPS 模板记录（通过查询固定域名，如 `crypto.cloudflare.com` 的 HTTPS
记录获得）来补全——把该模板中的 `ech` SvcParam 补进当前应答的 HTTPS 记录。

本提案在 `forward` 规则上新增可选字段 `cloudflare_ech`，为该规则转发的查询提供
"CF 网段 + ECH 补全"能力：应答里的 HTTPS 记录若属于 CF 网段且缺 `ech`，则用
`cloudflare_ech` 域名查询得到的 HTTPS 记录中的 `ech` 补全后替换该记录；不属于
CF 网段则不做任何事。

> 机制说明：Cloudflare 的 `crypto.cloudflare.com` HTTPS 记录携带的 `ech`
> SvcParam 是对 "crypto" 这个域名的 ECH 配置，直接整体替换到任意 CF 域名并不
> 一定语义正确（ECH 配置与公钥/SNI 相关）。本提案采用与用户确认过的实现口径：
> **"用 `cloudflare_ech` 查询得到的 HTTPS 记录替换当前记录"**（语义由该配置项
> 的使用者负责）。下文 §2/§3 均按此实现。

## 2. 目标 / 非目标

### 目标

- `forward` 规则动作新增可选字段 `cloudflare_ech: {domain}`，`{domain}` 为
  **字面域名**（不含 `{N}` 占位符替换），例如
  `cloudflare_ech: "crypto.cloudflare.com"`。
- 内置 Cloudflare 的 IPv4 CIDR 列表，用于子网匹配（见 §4.3）。
- 规则内对 **HTTPS(SVCB) 类型** 的查询应答做如下处理：
  1. 提取应答 HTTPS 记录 `ipv4hint` 中的 IPv4，校验是否落在 CF CIDR 内；
  2. 命中 CF 网段且该 HTTPS 记录不含 `ech` SvcParam → 用 `cloudflare_ech`
     查询得到的 HTTPS 记录替换当前记录（逐条替换，其余 HTTPS 记录原样保留，
     TTL 沿用被替换记录的 TTL）；
  3. 不在 CF 网段内（或没有 `ipv4hint`）→ 什么都不做。
- `cloudflare_ech` 模板查询走该规则同一个 `forward` 上游；模板按
  `(cloudflare_ech 域名, HTTPS)` 键做 TTL 缓存（复用 `DnsCache` 的
  `CacheRecord::Https` 路径），避免每条 HTTPS 应答都多一次上游往返。
- 只影响配置了 `cloudflare_ech` 的规则；未配置时行为完全不变。

### 非目标

- 不做 ECH 配置的语义校验（ECH 与 SNI/公钥的匹配由使用者负责）。
- 不改 A/AAAA 应答、不改非 HTTPS 查询类型。
- 不新增独立的"模板上游"配置（模板查询复用规则的 `upstream`）。
- 不改变 DNS 查询/应答的消息结构、不做 CF 网段的运行时更新（静态内置）。
- 不新增第三方依赖。

## 3. 方案

### 3.1 配置格式

`forward` 动作新增可选字段：

```yaml
rules:
  - match: "example.com"
    action:
      type: forward
      upstream: default
      cloudflare_ech: "crypto.cloudflare.com"   # 新增（可选）
```

- 类型 `Option<String>`，缺省为 `None`（行为与现状完全一致）。
- `{domain}` 为字面域名，**不**做 `{N}` 占位符替换（与用户确认）。
- 解析失败按规则解析的容错惯例处理（与 `edns` 一致）：记录 warning、禁用该
  规则的 `cloudflare_ech` 能力，不阻止启动。
- `cname` / `block` / `rewrite` 动作不提供该字段。

### 3.2 语义

对配置了 `cloudflare_ech` 的 forward 规则：

1. 上游应答到达后（TTL 覆盖 / answer 截断**之前**，与 `resolve_cname` 同层），
   若应答含 HTTPS(SVCB) 记录，逐条检查：
   - 记录必须命中 CF 网段且不含 `ech` SvcParam，才进入替换逻辑；
   - 替换源：查询 `cloudflare_ech` 域名的 HTTPS 记录（同一 upstream、qtype
     HTTPS），取其中第一条含 `ech` 的 HTTPS 记录作为模板；
   - 替换结果：新建 HTTPS 记录，owner = 原查询名、TTL = **被替换记录的 TTL**、
     RDATA = 模板记录（保留其 `svc_priority` / `target_name` / 全部 SvcParam）。
2. 模板查询失败（上游错误 / 无 HTTPS 记录 / 无含 `ech` 的记录）→ 该条不替换，
   原样保留原应答继续，不报错、不影响其他记录。
3. 不在 CF 网段内、没有 `ipv4hint`、记录已含 `ech` → 什么都不做（原样保留）。

处理顺序（在一次转发内）：`upstream 查询 → resolve_cnames → ECH 补全 → TTL
覆盖 → max_answers 截断`。ECH 补全在 TTL 覆盖之前，因此 `ttl` 覆盖仍对所有
answer 生效；截断发生在补全之后，不会丢弃补全结果（除非超过上限）。

### 3.3 配置解析与规则构建（`src/config.rs` + `src/plugins/rules.rs`）

- `src/config.rs`：`RuleActionConfig::Forward` 增加 `#[serde(default)]
  cloudflare_ech: Option<String>` 字段。
- `src/plugins/rules.rs`：
  - `RuleAction::Forward` 增加字段：
    - `cf_ech: Option<CfEch>`（`CfEch { template_name: String }`，构建期校验）；
  - `init()` 中解析：`cloudflare_ech` 为 `Some` 时调用 `validate_domain` 校验
    （与 match 内联域名同一校验），非法 → warning + `None`（该规则退化为普通
    forward）；`None` → 不启用。
  - `forward_query` 中在 `resolve_cnames` 之后调用补全逻辑（见 §3.4）。

### 3.4 补全逻辑（`src/plugins/rules.rs`）

纯函数 / async 辅助拆分：

- `fn cf_ech_replacement_https(records: &[Record], template: &SVCB, query_name: &Name) -> Vec<Record>`
  （纯函数，单测友好）：遍历 HTTPS 记录，`record_uses_cf(&r)` 命中 CF 网段且
  `r` 不含 `ech` → 构造 `Record::from_rdata(query_name.clone(), r.ttl(),
  RData::HTTPS(HTTPS(template.clone())))`；否则原样保留。返回新 `Vec`。
- `fn record_uses_cf(r: &Record) -> bool`：仅当 `r.data()` 为 `RData::HTTPS` 时，
  遍历其 `svc_params`：`SvcParamKey::Ipv4Hint(IpHint(ips))` → 任一
  `ipv4hint` IP 命中 CF CIDR 即视为命中；且不含 `SvcParamKey::EchConfigList`。
  其余情况返回 `false`。
- `async fn fetch_ech_template(&self, ctx, upstream, domain) -> Option<SVCB>`：
  走 `make_query_msg(domain, RecordType::HTTPS)` + `self.upstreams.query(...)`，
  从应答中取第一条含 `ech` 的 HTTPS 记录（`SvcParamValue::EchConfigList`）的
  `SVCB`。任何失败 → `warn` + `None`。

`forward_query` 集成（示意）：

```rust
// 在 resolve_cnames 之后：
if let Some(cf) = &cf_ech {
    if let Some(template) = self.fetch_ech_template(ctx, upstream, &cf.template_name).await {
        let query_name = ctx.msg.queries.first().map(|q| q.name()).unwrap();
        resp.answers = cf_ech_replacement_https(&resp.answers, &template, query_name);
    }
}
```

### 3.5 模板缓存

- `RuleAction::Forward` 的 `cf_ech` 只持有配置；缓存放 `Rules` 共享层。
- 在 `Rules` 上新增 `ech_cache: Option<Arc<DnsCache>>`，`init()` 用
  `DnsCache::new_metric(64, 60, 3600, false)` 构造（小容量专用缓存；max/min
  TTL 沿用全局 cache 默认的 60–3600 钳制），只有任一规则启用 `cloudflare_ech`
  时才创建。
- 查询模板前先 `get_cached(&CacheKey::new(domain, RecordType::HTTPS))`：
  - `Fresh(entry)` → 从 `entry.records` 取 `CacheRecord::Https(SVCB)`；
  - `Miss` → 上游查询成功后，用 `cache_upstream_response`（现有函数，已支持
    HTTPS 提取与 NoData 负缓存）写入，再读取。
- `Cache` 的 write-back 路径不变（客户端查询仍按主 key 正常缓存）。

> 因为 `DnsCache` 字段是私有的（`src/plugins/cache.rs`），`Rules` 通过
> `DnsCache` 的公开方法（`new_metric` / `get_cached` / `put`）与
> `plugins::util::cache_upstream_response` 交互，不需要改 `Cache` 的可见性。
> `CacheRecord` 是 `pub`，可直接 `matches!(record, CacheRecord::Https(svcb))`。

### 3.6 匹配查询类型

补全只应作用于 **HTTPS 查询** 的应答：`forward` 的 `qtype_matches` 已保证
`qtype: HTTPS`（或 `ANY`）的规则才命中 HTTPS 查询；上游应答类型与查询一致。
补全函数对非 HTTPS answer 天然跳过（`record_uses_cf` 只认 HTTPS 记录），因此
A/AAAA/MX 等应答零影响。

## 4. 内置 Cloudflare IPv4 CIDR 列表

### 4.1 来源

Cloudflare 官方 IP 范围（`https://www.cloudflare.com/ips-v4`，IPv4）。截至
2026-09-03 的发布列表见附录 §9（15 个网段）。

### 4.2 存放

在 `src/plugins/rules.rs` 内新增一个模块级常量数组（避免新增文件/依赖）：

```rust
/// Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4), used to
/// decide whether an HTTPS record belongs to Cloudflare.
const CLOUDFLARE_IPV4_CIDRS: &[&str] = &[
    "173.245.48.0/20",
    // ...（完整列表见 §9）
];
```

- 构建期把 `&str` 解析为 `Ipv4Net`（见下）。
- 用 `OnceLock<Vec<Ipv4Net>>` 惰性初始化（或直接放 `const` 里存原始字符串、
  首次匹配时解析——见 §4.4 权衡）。

### 4.3 子网匹配

不引入新 crate：用 `std::net::Ipv4Addr` 与整型移位自行实现 CIDR 包含判断
（`Ipv4Net` 不存在于 std）。最简做法：

```rust
struct Cidr { net: u32, prefix: u8 }
impl Cidr {
    fn contains(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
        (ip & mask) == (self.net & mask)
    }
}
```

- 解析：`a.b.c.d/len` → `net = u32::from(ip)`，`len ∈ [0,32]`。
- 由于列表是可信内置常量，解析失败用 `expect`（启动即暴露数据错误；不改
  用 warning 容错——这是"内置数据"，不是"用户配置"）。
- 匹配：`ipv4hint` 中的任一 IP 命中任一 CF CIDR 即命中（OR 语义）。

### 4.4 实现权衡

- `OnceLock<Vec<Cidr>>` 在 `init()` 时初始化一次，常驻内存（17 条 × 8B，可忽略）；
  查询热路径是纯整数比较，无锁（`OnceLock` 初始化后只读）。
- 不用 `ipnet`/`cidr` crate（新增依赖，违背"不新增依赖"）；std 实现约 15 行。

## 5. 配置变更影响

| 位置 | 变更 |
|------|------|
| `src/config.rs` | `RuleActionConfig::Forward` 增加 `cloudflare_ech: Option<String>`（`#[serde(default)]`） |
| `src/plugins/rules.rs` | `RuleAction::Forward` 增加 `cf_ech: Option<CfEch>`；`Rules` 增加 `ech_cache: Option<Arc<DnsCache>>`；`init()` 解析与构建；`forward_query` 补全调用；CF CIDR 常量 + 匹配函数；`fetch_ech_template` |
| `example/rsdns-all-example.yaml` | forward 示例注释补充 `cloudflare_ech` 用法 |
| `README.md` / `README.en.md` | rules/forward 说明补充 `cloudflare_ech`（如 README 描述 rules 字段则同步） |
| `Cargo.toml` | 无改动（无新增依赖） |

## 6. 测试

- **config**：`forward` 动作 `cloudflare_ech` 字段解析（合法域名 / 缺省 `None`）；
  非法域名（含 `{N}` 占位符、非法字符、空）→ 解析失败。
- **rules（纯函数）**：
  - `record_uses_cf`：构造带 `ipv4hint` 的 HTTPS 记录，用 CF 网段内/外 IP 各验
    一次；无 `ipv4hint` / 非 HTTPS / 已含 `ech` → `false`。
  - `cf_ech_replacement_https`：
    - CF 网段内、无 ech 的 HTTPS 记录被替换（owner = 查询名、TTL = 原 TTL、
      RDATA = 模板 SVCB）；
    - 网段外记录原样保留；已含 ech 的记录原样保留；非 HTTPS answer 原样保留；
    - 混合集合：只替换该替换的，其余不动。
  - CIDR 匹配：`contains` 对网段内/边界/网段外 IP 的断言。
- **rules（集成）**：`init` 后带 `cloudflare_ech` 规则的构建、非法值回退为
  `None`。
- 不新增 e2e；`make ci` 全绿。

## 7. 兼容性

- `forward` 现有字段全部不变；未配置 `cloudflare_ech` 时行为与现状完全一致。
- 查询流水线、cache（主路径）、upstream 均无改动。
- 模板缓存是规则层新增的私有 `DnsCache`，不参与主 cache 的容量/指标。

## 8. 风险与权衡

- **ECH 语义正确性**：模板 `ech` 来自 `cloudflare_ech` 域名的 HTTPS 记录，替换
  到目标域名后 ECH 与目标 SNI/公钥的匹配由使用者保证（Cloudflare 场景下其
  ECH 配置面向 CF 边缘通用）。文档/示例中会注明这一点。
- **模板缓存容量**：独立 64 条小缓存，TTL 60–3600 钳制；CF 的 ECH 模板 TTL
  一般较长，缓存命中率高。缓存条目极少（不同 `cloudflare_ech` 域名数量级很小）。
- **`resolve_cname` 交互**：ECH 补全在 `resolve_cname` 之后，只作用于最终应答
  （`resolve_cname` 已把 CNAME 目标替换为 A/AAAA，不含 HTTPS，因此实际不会同时
  触发——顺序保证安全即可）。
- **多 HTTPS 记录**：逐条替换，模板对每条使用同一份 SVCB（含各自原 TTL）。

## 9. 附录：Cloudflare IPv4 范围（2026-09-03）

来源：<https://www.cloudflare.com/ips-v4>（IPv4 发布列表）。

```text
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
```

> 实现时以仓库内常量列表为准；如需更新，直接改 `CLOUDFLARE_IPV4_CIDRS` 常量并
> 跑单测即可。
