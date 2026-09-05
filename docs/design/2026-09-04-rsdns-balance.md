# rsdns balance 插件：均衡 / 偏好排序 A/AAAA 应答顺序（含 speed 模式）

> 2026-09-04 | 提案 v2
>
> v2 变更（按第二轮评审，合并原 speed 插件）：
> 1. **移除独立 `speed` 插件**，其 syn 测速能力作为 `balance` 的 `mode: speed` 并入；
> 2. `mode` 取值扩为 **`none`（默认）/ `round_robin` / `speed`**；`none` 表示除 `prefers` 排序与 `max_answers` 截断外什么都不做；
> 3. **`BalanceSpeedConfig` 不含 `family`**：speed 探测不做地址族过滤，按查询类型/分族自然生效（A 查询排 A、AAAA 查询排 AAAA、ANY 两组都排）；
> 3. **prefers 与 mode 的互斥**：`prefers` 若已把记录分出不同 rank，稳定偏好排序即为最终顺序，mode 不再执行（mode 只在族内全部同 rank——无 prefers / 全部未命中 / 同一 CIDR——时生效）。这回答了“prefers 排序后是否还需执行其他模式”：**不需要，偏好优先**；
> 4. `groups.skip_speed` 更名为 **`skip_balance`**：命中组跳过 balance 的**整个后置 pass**（prefers / mode / max_answers）；
> 5. 缓存命中（cache Fresh 短路）**跳过整个 balance**：顺序在写回时已由 balance 排定，同一 TTL 内各客户端拿到一致顺序，speed 也不重复探测。

## 1. 动机

CDN / 多活域名常返回多个 A（或 AAAA）记录。目前 rsdns 对返回顺序的可选干预：

- 独立 `speed` 插件：真实测速后按 RTT 升序排（代价是一次 TCP 握手探测，默认关闭）；
- `forward.max_answers`：按上游顺序截断到 N 条（默认 5），无法表达"优先某网段"或"分散负载"。

需求方希望把这些收敛进一个**后置应答处理插件**，按需组合：

1. `prefers`（CIDR 偏好）：应答 IP 命中越靠前的 CIDR 就越靠前，未命中排最后；
2. `mode`：`none`（什么都不做，默认）/ `round_robin`（无状态轮转分散负载）/ `speed`（原 speed 插件的 syn 测速排序）；
3. `max_answers` 上收为全局截断，发生在排序之后。

本提案把独立 `speed` 插件**移除**，能力并入 `balance`，形成单一后置 pass，避免两个后置阶段互相覆盖的复杂度。

## 2. 目标 / 非目标

### 目标

- 新增顶层 `balance:` 配置段：`mode`（`none` 默认 / `round_robin` / `speed`）、`prefers`（扁平 CIDR）、`max_answers`、`speed`（mode=speed 时的探测参数子段）。
- **删除 `speed` 插件**（`src/plugins/speed.rs`、顶层 `speed:` 段、`enable` 字段），syn 探测参数并入 `balance.speed`。
- 从 `forward` 动作移除 `max_answers`，收归 `balance`（全局）。
- `groups.skip_speed` → `skip_balance`：命中组跳过整个 balance 后置 pass。
- 缓存命中跳过整个 balance（写回时已排定顺序）。

### 非目标

- 不匹配客户端源 IP / 不做 geo / 智能调度。
- 不做有状态轮询（无跨查询共享游标、无按客户端记忆）。
- `mode: speed` 不做测速结果跨查询缓存（每次命中实测，同原 speed 插件）。
- 不改上游查询 / 规则 / groups 匹配 / 缓存命中判定语义。

---

## 3. 配置

### 3.1 `balance:` 顶层段

```yaml
balance:
  mode: none          # none（默认）/ round_robin / speed
  max_answers: 5      # 可选；全局每条应答最多返回 N 条（0 或缺省 = 不限）
  prefers:            # 可选；扁平 CIDR 列表，顺序 = 优先级
    - "223.5.5.0/24"
    - "114.114.0.0/16"
    - "2400:3200::/32"
  speed:              # 可选；仅 mode: speed 时读取
    type: syn         # 探测类型，默认 syn（当前唯一取值）
    port: 443         # 探测目标端口，默认 443
    timeout: 1s       # 单次探测超时，默认 1s（支持 500ms / 2s 等）
```

```rust
pub struct BalanceConfig {
    #[serde(default = "default_balance_mode")]  // "none"
    pub mode: String,
    #[serde(default)]
    pub prefers: Vec<String>,
    #[serde(default)]
    pub max_answers: Option<usize>,
    #[serde(default)]
    pub speed: Option<BalanceSpeedConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceMode { None, RoundRobin, Speed }
// BalanceMode::parse(s)：round_robin/round-robin → RoundRobin；speed → Speed；
// 其余（含空/none）→ None。未知值 init 时 warn 并回退 None。

pub struct BalanceSpeedConfig {
    pub r#type: String,   // "syn"（默认）
    pub port: u16,        // 443
    pub timeout: String,  // 时长串
}
```

- **`balance:` 段缺失** → 插件整体 inert：不排序、不轮转、不测速、不截断。
- `prefers` 内非法 CIDR：init 期 `warn` 并跳过该条，不视为启动失败。
- `mode` 非法值：`warn` 并回退 `none`。
- `speed.type` 非 `syn`：`warn` 并回退 `syn`。

### 3.2 `forward.max_answers` 移除

同 v1：删除 `RuleActionConfig::Forward.max_answers`、`RuleAction::Forward`/`ForwardOpts`/`forward_query` 中的 `max_answers` 与 `truncate_answers`。旧配置里 `forward.max_answers` 被 serde 静默忽略（无 `deny_unknown_fields`）。

### 3.3 `speed` 插件移除 / `groups.skip_balance`

- `src/plugins/speed.rs` 删除，顶层 `speed:` 段不再解析（残余 key 落入 `plugin_sections` 被忽略）。
- `GroupConfig.skip_speed` → `skip_balance`；`QueryContext.skip_speed` → `skip_balance`（命中组 / 缓存命中置位）。
- 迁移注意：旧配置里的 `groups[].skip_speed` 与 `speed:` 段会被静默忽略，不报错；示例与文档同步改写。

---

## 4. 行为

### 4.1 触发条件（全部满足才处理，否则原样放行）

1. 配置存在 `balance:` 段；
2. `ctx.skip_balance == false`（未被组 `skip_balance` / 缓存命中跳过）；
3. 查询类型为 A / AAAA / ANY（`ANY` 时 A 与 AAAA 作为**两个独立族**分别处理）；其余类型放行（含不做 `max_answers` 截断）。

### 4.2 prefers 排序（记录侧，先于 mode）

- init 期把 `prefers` 解析为有序 CIDR（v4+v6 整数位运算，不引 `ipnet`）。
- 对目标族每条记录：rank = **首个包含其 IP 的 CIDR 下标**；无命中 → rank = +∞。
- 若族内 rank **存在差异**：按 rank 稳定排序（命中者按 CIDR 优先级在前、同级保持原序，未命中者保持原序在后），**mode 不执行** —— 偏好优先，mode 不覆盖已建立的偏好。
- 若族内**全部同 rank**（`prefers` 为空 / 全部未命中 / 全部命中同一 CIDR）：先不做排序，进入 §4.3 交给 mode。

### 4.3 mode（仅全部同 rank 时执行）

| mode | 行为 |
|------|------|
| `none`（默认） | 什么都不做（同 rank 记录保持原序） |
| `round_robin` | 对该族记录做一次**随机起点轮转**（循环移位随机偏移量；`rand` 每次查询独立采样，无共享计数器、无状态） |
| `speed` | 对该族记录按 TCP 握手 RTT 稳定排序（成功按 RTT 升序在前，失败/超时排最后、保持原相对顺序）；A/AAAA 各自独立成族，A 查询只排 A、AAAA 查询只排 AAAA、ANY 查询两组都排 |

- 只有 `mode: speed` 时探测（`balance.speed` 参数仅在此时解析生效）。
- 全部同 rank 时若族内只有 1 条记录 → 不处理。

### 4.4 缓存命中 / `skip_balance`

- **缓存命中跳过整个 balance**：cache Fresh 短路时置 `ctx.skip_balance = true`。写回时 balance 已把顺序排定并截断，缓存副本即最终顺序；同一 TTL 内各客户端拿到一致顺序（round_robin 的"每次查询随机起点"只在首次上游取回时发生一次，命中不重复轮转/测速）。
- 组命中 `skip_balance: true`：跳过整个 balance（prefers / mode / max_answers 都不执行）。

### 4.5 截断（`max_answers`）

- prefers/mode 处理完成后，若 `max_answers` 为 `Some(n)` 且 `n > 0`，对**整条 answers** 截断到前 n 条（截断发生在排序后、`write_back` 前，客户端与缓存一致）。
- 省略 / `0` → 不截断。

### 4.6 管线位置

```
logs → hosts → groups → cache → rules → [balance] → 别名恢复 → cache 写回 → 日志
```

balance 为唯一后置 pass（speed 插件已并入），不短路。CNAME 等非 A/AAAA 记录位置不动（记录原位交换，只调 A/AAAA 族内相对顺序）。

---

## 5. 示例

```yaml
balance:
  mode: speed          # 需要测速时；mode: round_robin 或省略(none)亦可
  max_answers: 6
  prefers:
    - "223.5.5.0/24"   # 命中者最优先
    - "114.114.0.0/16"
  speed:
    type: syn
    port: 443
    timeout: 1s

# groups：命中 cdn 组跳过整个 balance
groups:
  - name: cdn
    domains: [cloudflare.com]
    skip_balance: true

rules:
  - match: ""
    action: { type: forward, upstream: default }
```

效果：
- 上游返回 A `[223.5.5.x, 8.8.8.8, 114.114.x.x, 1.1.1.1]`（mode 任意）→ 稳定重排为 `[223.5.5.x, 114.114.x.x, 8.8.8.8, 1.1.1.1]`，mode 不执行。
- 全部命中 `223.5.5.0/24`（同 rank）：
  - `mode: round_robin` → 每次查询随机轮转起点；
  - `mode: speed` → 按 RTT 排序；
  - `mode: none`（默认）→ 保持原序。
- `max_answers: 6` → 排序后整条截到 6 条。

---

## 6. 实现清单

| 文件 | 内容 |
|------|------|
| `src/config.rs` | `BalanceConfig`（mode/prefers/max_answers/speed 子段）、`BalanceMode`、`BalanceSpeedConfig`；`GroupConfig.skip_speed` → `skip_balance`；删除 `SpeedConfig` |
| `src/query.rs` | `QueryContext.skip_speed` → `skip_balance` |
| `src/plugins/balance.rs` | mode 枚举 none/round_robin/speed；prefers 排序与 mode 互斥（mode 仅全同 rank 时执行）；syn 测速并入；`max_answers` 截断；`skip_balance` 门控 |
| `src/plugins/speed.rs` | **删除** |
| `src/plugins/groups.rs` | `skip_speed` → `skip_balance` 置位 |
| `src/plugins/cache.rs` | 缓存命中置 `skip_balance`（替代 skip_speed） |
| `src/plugins/mod.rs` | 移除 `speed` 模块 |
| `src/server.rs` | `Pipeline` 移除 `speed` 字段；`handle_query` 只调用 `balance.handle` |
| `src/main.rs` | 移除 `speed::init`，初始化 `balance` |
| `example/rsdns-all-example.yaml` | `skip_balance` / `balance.mode/speed` 示例；删除 `speed:` 段与 `skip_speed` |
| `docs/design/2026-08-21-rsdns-speed.md` | 归档（保留历史，标注已并入 balance） |

依赖变更：无新增（`rand`、`futures`、`ahash`、tokio TCP 均为既有）。

## 7. 行为变化与风险

1. **不再默认截断**：未配置 `balance:` 的应答不再截到 5 条（v1 已确认）。
2. **speed 插件并入 balance**：原 `speed:` 顶层段不再生效；原 `speed.enable: true` 用户需改配 `balance.mode: speed` + `balance.speed`（参数默认与原 speed 一致：syn/443/1s）。
3. **默认不再轮转**：v1 默认 `round_robin` → v2 默认 `none`（只做 prefers/截断）；需要轮转的用户显式写 `mode: round_robin`。
4. **缓存命中不再重复处理**：round_robin/speed 只在首次上游取回时执行一次；同一 TTL 内缓存命中返回一致顺序（这是明确取舍：无状态轮转在命中路径不生效）。
5. **prefers 优先于 mode**：一旦 prefers 分出不同 rank，mode 不执行——不会出现"按 RTT 重排后又按偏好重排"或相反的双重排序。
6. **ANY 查询**：A 与 AAAA 分族，IPv4/IPv6 CIDR 天然互不匹配；`speed` 探测也按族独立进行。
7. **无回归面**：不改上游 / 缓存 / 规则语义；balance 后置 pass 在 `write_back` 前，缓存副本为平衡后顺序。
