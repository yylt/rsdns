# rsdns balance 承接 Cloudflare 模板替代：`balance.cloudflare`（ech / a / aaaa）

- 日期: 2026-11-10
- 状态: 已实现
- 取代: `2026-09-03-rsdns-forward-cf-ech.md`（规则级 `forward.cloudflare_ech`）

## 1. 动机

`cloudflare_ech` 目前挂在 `forward` 规则动作上（`src/plugins/rules.rs`）：

- 它本质是**对最终应答的后置改写**，与路由（命中哪条规则、用哪个 upstream）无关；
- 挂在规则上导致同一能力要按域名逐条重复配置，且只能作用于 `forward` 命中；
- 实现上要额外把 `Arc<Upstreams>`、模板缓存、CF 网段判断塞进 rules 阶段，
  与 rules 的职责（匹配 + 路由）混杂。

`balance` 已经是唯一后置应答 pass（`rules` 之后、缓存写回之前），天然适合承接：

- 只处理最终应答，不再关心应答来自 forward / cname / hosts / rewrite；
- `skip_balance`、缓存写回顺序、`prefers` / `max_answers` 的先后关系都已经定义；
- CF 网段匹配可以直接复用 `balance` 现有的 `Cidr`（v4 + v6 整数比较）。

同时把能力从"只补 HTTPS 的 `ech`"扩展为三类**可独立开关**的模板替代：

- **HTTPS**：CF 网段内且缺 `ech` 的 HTTPS 记录 → 用 `ech` 模板域名的 HTTPS 记录替代；
- **A**：应答 A 落在 CF IPv4 网段 → 用 `a` 模板域名的 A 记录替代；
- **AAAA**：应答 AAAA 落在 CF IPv6 网段 → 用 `aaaa` 模板域名的 AAAA 记录替代。

各模板通过各自指定的 upstream 解析，并按上游、域名和记录类型缓存。

## 2. 目标 / 非目标

### 目标

- 从 `forward` 动作**移除** `cloudflare_ech`，整体迁到 `balance.cloudflare`：

  ```yaml
  balance:
    cloudflare:
      ech: "linux.do@pxy"            # 可选：HTTPS 模板及上游组
      a: "cf.example.com@boot"       # 可选：A 模板及上游组
      aaaa: "cf.example.com@boot"    # 可选：AAAA 模板及上游组
  ```

- `ech` / `a` / `aaaa` **互相独立**：只配一项就只启用对应类型的替代；
  三项都缺省 → 能力关闭。`a` 不会隐式复用给 AAAA；需要两者时写两行。
- 每个字段必须指定 `domain@upstream`，引用已配置的上游组；无共享或默认上游。
  格式错误或上游不存在时 warn 并只禁用该字段。
- 新增内置 Cloudflare **IPv6** 网段；CF 判断统一为 `IpAddr` 级别（v4/v6 各用各的列表）。
- HTTPS 补全语义延续原实现（整条 HTTPS 记录替换为模板 SVCB，TTL 沿用原记录），
  触发条件补充 `ipv6hint`。
- A / AAAA 替代：对应地址族的记录命中 CF 网段时，用模板域名的 A / AAAA 记录
  替换该地址族的全部记录（owner / TTL 沿用被替换的第一条记录）。
- 模板查询走 `Upstreams::query`，按 `(domain, upstream, qtype)` 做 TTL 缓存，复用
  `DnsCache` 与 `cache_upstream_response`；失败/无记录时保留原应答。

### 非目标

- 不做 ECH / 证书 / SNI 的语义校验（替代后的地址是否真的服务目标域名由使用者负责）。
- 不新增"模板上游"独立配置：只支持引用已配置的 upstream 组名。
- 不改变 rules 的匹配 / 路由语义，不改变查询流水线阶段顺序。
- 不为模板查询引入 ECS、不继承规则级 `edns` / `ttl` / `deny_qtypes`。
- 不做 CF 网段的运行时更新（静态内置常量）。
- 不新增第三方依赖（CIDR 仍用 std 整数位运算）。
- 不在本提案里实现 DNSSEC 缓存旁路（见 `2026-09-11-rsdns-dnssec.md`），
  只保证替代逻辑对 `DO=1`/`CD=1` 查询跳过。

## 3. 配置

### 3.1 `balance.cloudflare`

```yaml
balance:
  mode: none
  max_answers: 10
  prefers: ["104.16.0.0/13"]
  cloudflare:
    ech: "linux.do@pxy"
    a: "cf.example.com@boot"
    aaaa: "cf.example.com@boot"
```

```rust
pub struct BalanceConfig {
    // ...现有字段
    #[serde(default)]
    pub cloudflare: Option<BalanceCloudflareConfig>,
}

pub struct BalanceCloudflareConfig {
    #[serde(default)]
    pub ech: Option<String>,       // HTTPS 模板域@上游组
    #[serde(default)]
    pub a: Option<String>,         // A 模板域@上游组
    #[serde(default)]
    pub aaaa: Option<String>,      // AAAA 模板域@上游组
}
```

- 三个模板域均为字面域名（不做 `{N}` 占位符替换），用迁移到 `plugins::util` 的
  `validate_domain` 校验；某个域非法/为空 → `warn` 并只禁用该类型，
  其余类型与 balance 其他字段照常生效。
- 段缺失或 `cloudflare` 缺失 → 能力关闭，行为与现状（无该能力）一致。
- 各字段必须是 `domain@upstream`；上游组名大小写敏感，必须已配置且非空。
  格式错误或上游不存在只禁用对应字段；不支持共享或默认上游。
- `aaaa` 不继承 `a`：只写 `a` 时 AAAA 查询不做替代。

### 3.2 删除 `forward.cloudflare_ech`

- 删除 `RuleActionConfig::Forward.cloudflare_ech`、`RuleAction::Forward.cf_ech`、
  `CfEch` 及 rules 内全部相关代码与配置测试。
- 旧配置里的 `forward.cloudflare_ech` 被 serde 静默忽略（`RuleActionConfig` 未开
  `deny_unknown_fields`），与 `forward.max_answers` 迁移到 `balance.max_answers`
  时的口径一致。
- 迁移方式：

  ```yaml
  # 旧
  rules:
    - match: "cdn.example.com"
      qtype: HTTPS
      action: { type: forward, upstream: default, cloudflare_ech: "crypto.cloudflare.com" }
  # 新
  balance:
    cloudflare:
      ech: "crypto.cloudflare.com@default"
  rules:
    - match: "cdn.example.com"
      action: { type: forward, upstream: default }
  ```

### 3.3 模板上游解析（init 期）

分别解析各字段的 `domain@upstream`，按 `config.upstreams[].name` 校验上游组名。
缺少 `@`、域名无效、上游为空或不存在时，仅禁用该字段并记录警告；三个字段
均无效时禁用 Cloudflare 替代。组内 server 是否可用由运行时查询决定（见 §4.2）。

## 4. 行为

### 4.1 管线位置与门控

```text
logs → hosts → groups → cache → rules → [balance] → 别名恢复 → cache 写回 → 日志
```

`balance.handle` 内顺序：

```text
enabled / skip_balance 门控
  → cloudflare 替代（HTTPS / A / AAAA，按各自模板域独立执行）
  → prefers 稳定排序
  → mode（none / round_robin / speed）
  → max_answers 截断
```

- `enabled == false`（无 `balance:` 段）或 `ctx.skip_balance == true`
  → 整个 pass 跳过，**包括** `cloudflare`。
- 组 `skip_balance: true` 与缓存 Fresh 命中都会置位 `skip_balance`：前者是用户
  显式跳过；后者是因为写回时已经替代过（缓存副本即最终应答），无需重复。
  若 `cache.skip_balance: false`，命中会重跑本 pass，替代是幂等的（模板地址仍在
  CF 网段内，再次替代结果相同），模板查询命中私有缓存，不增加上游往返。
- 仅对 `qtype` 为 `A` / `AAAA` / `HTTPS` / `ANY` 的查询生效；其他类型直接跳过替代
  （`max_answers` 的既有规则不变：仍只作用于 A/AAAA/ANY）。
- `ANY` 查询按"配置了哪个模板域"决定执行哪几类替代：`a` → A 族、`aaaa` → AAAA 族、
  `ech` → HTTPS 记录；三者彼此独立。
- 应答来源不限于 `forward`：`hosts` / `rewrite` / `cname` 产生的最终应答同样按
  记录内容判断。该能力默认关闭，开启即表示接受这一全局语义。

### 4.2 模板获取与缓存

- 模板缓存键包含域名、上游和记录类型：`(domain, upstream, qtype)`；同一域名
  经不同上游查询时互不共享结果，不同 qtype 也各占一个键。
- 复用 `DnsCache::new_metric(64, 60, 3600, false)` 作为私有模板缓存
  （容量 64，TTL 钳制 60–3600），只有任一模板域启用时创建。
- 取模板：先 `get_cached`；`Fresh` → 直接过滤所需类型的记录；`Miss` →
  `make_query_msg(domain, qtype)` → `Upstreams::query(upstream, msg)` →
  `cache_upstream_response(...)` → 再 `get_cached`。
- 模板查询**不**经过 hosts / groups / cache / rules 阶段，也不携带 ECS。
- 任何失败（构造查询失败、上游错误、无该类型记录、HTTPS 模板无 `ech`）→
  `warn` 一次并保留原应答，不影响其他记录、其他类型与其他查询。
- 模板查询按需触发：只有应答里真的存在对应类型的 CF 候选记录时才查该模板域，
  非 CF 应答零额外开销。

### 4.3 HTTPS 替代（`ech`）

对每条 `RData::HTTPS` 应答：

1. 遍历 SvcParams：`ech`（`EchConfigList`）存在 → 不是候选；
2. `ipv4hint` 任一 IP 命中 CF IPv4 列表，或 `ipv6hint` 任一 IP 命中 CF IPv6 列表
   → 候选；无 hint（或 hint 全在列表外）→ 不是候选；
3. 若存在候选：取 `ech` 模板域的 HTTPS 记录中**第一条含 `ech`** 的 SVCB，把候选
   记录替换为 `Record::from_rdata(原记录 owner, 原记录 TTL, RData::HTTPS(SVCB 模板))`；
4. 其余 HTTPS 记录、非 HTTPS 记录原样保留，位置不变。

与原实现的差异：owner 从"查询名"改为"被替换记录的 owner"（CNAME 链场景下
更正确；普通场景二者相同）。

### 4.4 A 替代（`a`）

对 `A` 查询：

1. 若应答中没有任何 A 记录，或没有任何 A 的 IP 命中 CF IPv4 列表 → 不动；
2. 取 `a` 模板域的全部 A 记录（上游应答中所有 A）；
3. 用模板 A 记录替换应答中**全部** A 记录：
   - owner = 被替换的第一条 A 的 owner；
   - TTL = 被替换的第一条 A 的 TTL（规则级 `forward.ttl` 已在此之前生效，因此
     仍被保留）；
   - 插入位置 = 第一条被替换 A 原位置；其他记录（CNAME 等）保持相对顺序；
4. 模板无 A 记录 / 查询失败 → 原样保留。

### 4.5 AAAA 替代（`aaaa`）

与 §4.4 同构，但：

- 只对 `AAAA` 查询；
- 触发条件为 AAAA 的 IP 命中 CF IPv6 列表；
- 模板来源是 `aaaa` 模板域的 AAAA 记录。

A / AAAA 的触发只看各自地址族；A 应答命中 CF 不会触发 AAAA 模板查询，
反之亦然。

补充约束（A / AAAA 通用）：

- 查询名等于对应模板域名时跳过该类型的替代（模板本身即权威答案，避免无意义的
  上游往返）；`ech` 同理。

### 4.6 与 TTL / prefers / max_answers / 缓存的关系

| 关注点 | 行为 |
|--------|------|
| `forward.ttl` | rules 阶段已改写完毕；替代沿用被替换记录的 TTL，不覆盖规则 TTL |
| `prefers` | 在替代之后排序：模板地址同样参与 `prefers` rank |
| `mode` | 在替代之后执行（round_robin / speed 作用于替代后的地址） |
| `max_answers` | 在替代之后截断；截断可能丢掉部分模板记录 |
| 缓存 | balance 早于 `cache.write_back`，缓存副本是替代后的应答；Fresh 命中默认跳过本 pass |
| 别名恢复 | 在 balance 之后执行：`hosts` 别名场景下 owner 最终被改写为客户端查询名 |

### 4.7 DNSSEC

`ctx.msg.edns` 的 `DO=1` 或 `ctx.msg.metadata.checking_disabled`（CD=1）为真时，
**跳过整个 `cloudflare` 替代**（重写应答集合会破坏 RRSIG 覆盖，与
`2026-09-11-rsdns-dnssec.md` §2 的约定一致）。`prefers` / `mode` / `max_answers`
的 DNSSEC 门控不在本提案范围（该文档尚未实现）。

### 4.8 初始化时序（两阶段）

`upstream::init` 需要 `&Balance`（用 `rank_ips` 给域名上游的 bootstrap 结果排序），
而 balance 的模板查询又需要 `Arc<Upstreams>`，因此 balance 采用两阶段初始化：

```rust
let mut balance = plugins::balance::init(&config);           // 解析配置
let upstreams = upstream::init(&config, &metrics, &hosts, &balance).await?;
balance.attach_upstreams(upstreams.clone());                  // 注入查询句柄
let rules = rules::init(&config, &metrics, upstreams)?;       // 共享同一个 Arc
```

`attach_upstreams` 之前 `cloudflare` 不会执行（`upstreams == None` 直接跳过）；
正常启动路径总会在服务开始监听前完成注入。`Pipeline` 仍按值持有 `Balance`。

## 5. 实现清单

| 文件 | 变更 |
|------|------|
| `src/config.rs` | `BalanceConfig.cloudflare: Option<BalanceCloudflareConfig>`（`ech` / `a` / `aaaa`，各自指定上游）；删除 `RuleActionConfig::Forward.cloudflare_ech` 与对应测试 |
| `src/plugins/balance.rs` | 迁入 CF IPv4 常量 + 新增 IPv6 常量（`OnceLock<Vec<Cidr>>`）；`Cloudflare` 配置与 `attach_upstreams`；`apply_cloudflare`（门控 / 候选判断 / 模板查询 / 缓存）；HTTPS、A、AAAA 替换纯函数；单测 |
| `src/plugins/rules.rs` | 删除 `CfEch`、`parse_cf_ech`、`cf_ech` 字段、`ech_cache`、`CLOUDFLARE_IPV4_CIDRS` / `Ipv4Cidr`、`record_uses_cf` / `cf_ech_replacement_https` / `first_ech_svcb_from_cache` / `svcb_has_ech` / `fetch_ech_template` 及相关测试与模块文档 |
| `src/plugins/util.rs` | `validate_domain` 从 rules 迁入并 `pub(crate)`（rules 与 balance 共用） |
| `src/main.rs` | `let mut balance`；`upstream::init` 后 `balance.attach_upstreams(upstreams.clone())` |
| `src/server.rs` | 测试构造 Pipeline 时同样 `attach_upstreams` |
| `example/rsdns-all-example.yaml` | 删除规则上的 `cloudflare_ech` 示例；在 `balance:` 段补充 `cloudflare` 用法注释 |
| `README.md` / `README.en.md` | `forward` 特性说明去掉 `cloudflare_ech`；如特性列表需要，补一句 balance 的 CF 模板替代能力 |
| `Cargo.toml` | 无改动 |

## 6. 测试

- **config**：`balance.cloudflare` 的 `ech` / `a` / `aaaa` 解析；
  缺省 `None`；空/非法域名 → 对应类型禁用但其余字段仍生效；
  `forward` 动作不再有该字段（旧配置静默忽略由现有 serde 行为保证，不额外断言）。
- **balance（纯函数）**：
  - CF 网段匹配：v4/v6 各自列表、边界 IP、族隔离（v4 IP 不命中 v6 列表）；
  - HTTPS 候选：`ipv4hint` 命中 / `ipv6hint` 命中 / 已含 `ech` / 无 hint / 网段外；
  - HTTPS 替换：候选记录被模板替换（owner / TTL 保留），其余记录原样；
  - A 替换：CF 与非 CF 混合应答只替换 A 族、位置与顺序、owner / TTL；
  - AAAA 替换：同上；模板为空时原样返回；
  - 独立开关：只配 `a` 时 AAAA / HTTPS 不替代；只配 `ech` 时 A/AAAA 不替代；
  - `ANY`：A / AAAA / HTTPS 按已配置模板域各自独立替换。
- **balance（init / 缓存）**：各模板的独立上游、非法格式与未知上游只禁用对应字段；
  同域名不同上游的缓存隔离。
- **rules**：删除 `cloudflare_ech` 后原有 forward 测试全部保留通过。
- 不新增 e2e；`make ci` 全绿。

## 7. 兼容性 / 迁移

- 旧 `forward.cloudflare_ech` 静默失效：升级后必须显式迁移到 `balance.cloudflare`。
  发布说明与示例配置会给出迁移片段（§3.2）。
- 旧的 `balance.cloudflare` 纯域名配置不再生效：每个字段须补充 `@upstream`，
  并删除共享的 `upstream` 字段。
- 未配置 `balance.cloudflare` 时，行为与加入本能力前完全一致。
- `balance` 其余字段、rules、cache、upstream、查询流水线均无改动。
- `balance.cloudflare` 是全局能力，不再天然限定到某条规则；需要"只对部分域名
  生效"时，用 `groups[].skip_balance: true` 把这些域名排除在 balance 之外
  （会同时跳过 `prefers` / `mode` / `max_answers`）。

## 8. 风险与权衡

1. **A/AAAA 替代的语义风险（最高）**：模板域名（如 `crypto.cloudflare.com`）解析出的
   地址被当成目标域名的地址返回。只有当目标域名与模板同属一个 CF 边缘（CF anycast
   按 SNI 选择站点）时才成立；否则会出现证书/路由不匹配。该能力默认关闭，文档与
   示例会显著标注"仅用于 CF 托管且 SNI 可用的场景"。
2. **全局生效**：从"按规则"变为"按应答内容"，`hosts` / `rewrite` 合成的 CF 网段地址
   也会被替代。开启即接受；需要排除时用 `skip_balance` 组。
3. **模板上游能力**：每类模板查询走字段指定的 upstream。若该上游剥离 ECH 或
   无法解析模板域名，替代会失败并保留原应答。应为各字段选择能返回相应记录的
   解析器（如可信公共解析器或 CF DoH）。
4. **CNAME 链**：A/AAAA 替代保留原 owner（链末记录 owner），不会把地址挂到查询名上；
   HTTPS 替代同样保留原 owner，避免破坏链。
5. **缓存与轮转**：替代发生在缓存写回前，同一 TTL 内所有客户端看到同一份替代结果；
   `round_robin` 只在首次取回时执行一次（既有取舍，不变）。
6. **DNSSEC**：DO/CD 查询跳过替代；若未来实现 DO/CD 缓存旁路，替代仍需保持跳过。
7. **模板缓存容量**：最多 1 条/类型/域名，容量 64 足够；TTL 钳制 60–3600，
   CF 模板 TTL 通常较长，命中率高。

## 9. 附录：Cloudflare 网段（2026-11-10）

来源：<https://www.cloudflare.com/ips-v4>、<https://www.cloudflare.com/ips-v6>。

IPv4（15 条，与现有常量一致）：

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

IPv6（7 条，本提案新增）：

```text
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
```

> 实现时以仓库内常量列表为准；更新时直接改常量并跑单测。