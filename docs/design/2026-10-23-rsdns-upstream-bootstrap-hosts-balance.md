# 启动期上游域名解析复用 hosts 替换与 balance 排序

> 2026-10-23 | 提案

## 1. 动机

`upstream::init`（`src/upstream/mod.rs`）在启动期解析所有 `upstreams[].servers[]`
里的协议上游（UDP/TCP/DoT/DoH/DoH3/DoQ）。当某个服务器地址的 **host 是域名**
（如 `tls://dns.google`、`https://doh.pub/dns-query`）时，会产生一个
`UpstreamConfig::NeedResolve`，随后通过 **bootstrap 流程** 解析其 IP：把同
一份 `upstreams` 配置里“地址是 IP 字面量”的服务器当作 bootstrap 解析器，向它们
并发查询 A/AAAA，得到候选 `SocketAddr` 后建池。

这个流程是“非 rules”的（rules 阶段只在请求期持有装配好的 `Arc<Upstreams>`，
启动期解析不经过 rules），方向正确；但它与另外两个已有能力 **脱节**：

- **hosts**：用户已在 `hosts:` 段为某些域名配置了静态 IP（例如内网 DNS
  域名、ECH/自建上游域名）。这些域名作为上游时，理应直接命中 hosts 的静态映射，
  不必再发网络 bootstrap 查询（也更稳、不依赖其他 IP 上游存在）。
- **balance**：顶层 `balance:` 段的 `prefers` CIDR 偏好已经能对**应答** IP 做
  排序。上游服务器本身也可能解析出多个候选 IP，用户自然希望这些候选 IP 也按
  同一份 `prefers` 排序（优先选用落在偏好 CIDR 内的上游服务器），而不是交给连接池
  默认顺序。

目标：让启动期上游域名解析**先查 hosts（命中即替换、跳过网络 bootstrap），再按
balance `prefers` 对候选 IP 排序**，仍走“非 rules”的 `upstream::init` 流程。

## 2. 目标 / 非目标

### 目标

- `upstream::init` 在 bootstrap 某一个域名上游时，**先查 hosts**：
  - 命中**静态 IP**（直接 IP 映射，或别名/CNAME 链末端是静态 IP）→ 用这些 IP
    （按 `prefer_family` 过滤族）建池，**不再**发网络 bootstrap 查询；
  - 命中**别名/CNAME**（链末端无静态 IP）→ 取 hosts 指向的**新名称**，用该新名称
    走网络 bootstrap 解析并建池，**不再使用原始域名**；
  - 未命中 hosts → 用原始域名走网络 bootstrap。
- 域名上游解析出的候选 IP（无论来自 hosts 静态还是网络 bootstrap），在 `init` 建池前
  **按 `balance:` 的 `prefers` CIDR 列表做稳定排序**（命中外层 CIDR 的排前面；
  IPv4 CIDR 只排 A 记录 IP，IPv6 CIDR 只排 AAAA，家族隔离，与 balance 应答排序
  语义一致）。`prefers` 为空时排序为无操作。
- 解析流程**仍属于 `upstream::init`（非 rules）**，仅复用 hosts / balance 两个
  已有能力的“数据”，不引入新的解析器或 DNS 客户端。

### 非目标

- 不改 rules 阶段、不改请求期管线（`logs→hosts→groups→cache→rules→balance`）。
- 不把 `balance:` 的 `mode`（`round_robin`/`speed`）或 `max_answers` 用于上游
  服务器选择——只复用 `prefers` CIDR 排序。
- 不在 hosts 热重载时重新解析受影响的上游（本提案范围外的后续增强；保持启动期
  一次性解析语义）。
- 启动期 CNAME 解析不写回 hosts 静态表、不做链式网络递归（沿 hosts 别名链取“新
  名称”后即走网络解析该名称，最多跟到链末端）。

### 关于 hosts 命中的范围

`Hosts::handle` 区分 `Lookup::Ips`（直接 IP 映射）与 `Lookup::Alias`（别名/CNAME
改写：查询别名 → 查原域名 → 取原域名的 IP）。启动期用 `Hosts::resolve_host_name`
沿别名链解析一个上游域名，给出最终去向：

- `Static(ips)`：名称（含别名链末端）命中静态 IP 映射——直接建池；
- `Network(name)`：hosts 未命中，或别名链末端无静态 IP——调用方改用 `name`
  （原始域名、或别名指向的新名称）走网络 bootstrap 解析。循环别名被安全终结。

这与请求期 `handle` 的语义对齐：别名命中且原域名有 IP 时短路；原域名无 IP 时改写
继续走管线（此处对应“改用新名称走网络”）。

这与请求期 `handle` 的语义一致（alias 命中且原域名有 IP 时即短路），只是不触发
“原域名无 IP 时改写继续走管线”的分支。

## 3. 现状

`main.rs::run` 的装配顺序：

```
logs   = plugins::logs::init(...)
hosts  = plugins::hosts::init(...)        // 同步，产出 Hosts trie
groups = plugins::groups::init(...)
cache  = plugins::cache::init(...)
upstreams = upstream::init(&config, &metrics).await   // 在此做 bootstrap 解析
rules  = plugins::rules::init(&config, &metrics, upstreams)?
balance = plugins::balance::init(&config)             // 在 upstream 之后
```

- `upstream::init(config, registry)` 当前签名不含 hosts / balance；其 `bootstrap_resolve_all`
  仅通过 IP bootstrap 客户端做网络解析。
- `Hosts::handle` 暴露 `trie.read().lookup(domain) -> Lookup::{Ips, Alias, Miss}`，
  但没有一个“沿别名链解析上游域名、给出最终去向（静态 IP / 走网络的新名称）”的公开方法。
- `Balance` 持有 `cidrs: Vec<Cidr>` 和 `enabled: bool`，但 `Cidr` 是私有类型，
  没有“给定一批 IP 返回按 prefers 排序后的顺序”的公开方法。

## 4. 方案

### 4.1 调整 `main.rs` 装配顺序

把 `balance::init` 移到 `upstream::init` **之前**（balance 是纯同步、不依赖
upstream，顺序调换安全）：

```rust
let hosts  = plugins::hosts::init(&config, &metrics);
let groups = plugins::groups::init(&config, &metrics);
let cache  = plugins::cache::init(&config, &metrics);
let balance = plugins::balance::init(&config);                       // 上移
let upstreams = upstream::init(&config, &metrics, &hosts, &balance).await?;
let rules  = plugins::rules::init(&config, &metrics, upstreams)?;
```

`upstream::init` 新增两个参数：`hosts: &plugins::hosts::Hosts`、`balance: &plugins::balance::Balance`。
（这会在 `upstream` → `plugins::{hosts,balance}` 之间新增一条依赖；二者都是启动期
即装配好、内部以 `Arc` 持有、克隆/共享廉价的类型，耦合可接受。）

### 4.2 `Hosts` 新增公开方法 `resolve_host_name`

在 `src/plugins/hosts.rs` 给 `Hosts` 加一个方法：沿 hosts 别名/CNAME 链解析一个名称，
给出最终去向（新增 `HostResolution` 枚举）：

- `Static(ips)`：名称（含别名链末端）命中静态 IP 映射——调用方直接建池；
- `Network(name)`：hosts 未命中，或别名链末端无静态 IP——调用方改用 `name`
  （原始域名、或别名指向的新名称）走网络 bootstrap 解析。循环别名被安全终结。

```rust
/// `Hosts::resolve_host_name` 的解析结果：静态覆盖、或需要按给定名称走网络解析。
pub enum HostResolution {
    /// 完全由 hosts 静态覆盖（直接 IP，或别名链末端是静态 IP）。
    Static(Vec<IpAddr>),
    /// 需要网络解析的名称：hosts 未命中，或别名链末端无静态 IP（用此名称走
    /// 网络 bootstrap，不再使用原始域名）。
    Network(String),
}

impl Hosts {
    pub fn resolve_host_name(&self, name: &str) -> HostResolution {
        let trie = self.trie.read();
        let mut cur = name.to_string();
        let mut visited = std::collections::HashSet::new();
        loop {
            if !visited.insert(cur.clone()) {
                return HostResolution::Network(cur); // 循环别名 → 回退网络
            }
            match trie.lookup(&cur) {
                Lookup::Ips(ips) => return HostResolution::Static(ips.to_vec()),
                Lookup::Alias(original) => cur = original.to_string(),
                Lookup::Miss => return HostResolution::Network(cur),
            }
        }
    }
}
```

### 4.3 `Balance` 新增公开方法 `rank_ips`

在 `src/plugins/balance.rs` 给 `Balance` 加一个“按 `prefers` CIDR 稳定排序”的方法
（复用私有 `Cidr` 与 `contains`）。`enabled` 为 false 或 `cidrs` 为空时直接返回
输入顺序（无操作）：

```rust
/// 把候选 IP 按本 stage 的 `prefers` CIDR 做稳定排序：命中外层（索引更小）
/// CIDR 的 IP 排在前；同排名内保持原有相对顺序。家族隔离（v4 CIDR 只影响 v4 IP）。
/// 无 `prefers` / 未启用时原样返回。
pub fn rank_ips(&self, mut ips: Vec<IpAddr>) -> Vec<IpAddr> {
    if !self.enabled || self.cidrs.is_empty() {
        return ips;
    }
    let rank = |ip: &IpAddr| -> usize {
        self.cidrs.iter().position(|c| c.contains(*ip)).unwrap_or(usize::MAX)
    };
    ips.sort_by(|a, b| rank(a).cmp(&rank(b)));
    ips
}
```

（稳定排序：Rust 的 `slice::sort_by` 为稳定排序，相同 rank 保持输入顺序。）

### 4.4 改写 `upstream::init` 的 Phase 2（域名解析）

把现有“网络 bootstrap 一律发网络查询”替换为三步：**hosts 优先 → 网络 bootstrap
兜底 → balance 排序 → 建池**。

抽取一个小辅助，把 IP 列表按 `prefer_family` 过滤并转成 `SocketAddr`：

```rust
fn ips_to_addrs(ips: &[IpAddr], port: u16, fam: PreferFamily) -> Vec<SocketAddr> {
    ips.iter()
        .filter(|ip| match fam {
            PreferFamily::Ipv4 => ip.is_ipv4(),
            PreferFamily::Ipv6 => ip.is_ipv6(),
            PreferFamily::Any  => true,
        })
        .map(|ip| SocketAddr::new(*ip, port))
        .collect()
}
```

Phase 2 主体（替换现有 `bootstrap_resolve_all` 的单一网络路径）：

```rust
for idx in dynamic_indices {
    let UpstreamConfig::NeedResolve { server_name, port, prefer_family, .. } = &all_configs[idx] else { unreachable!() };
    let server_name = server_name.clone();
    let port = *port;
    let prefer_family = *prefer_family;

    // 1) hosts 优先：静态 IP 直接建池；别名/CNAME 取 host 指向的新名称走网络。
    let resolution = hosts.resolve_host_name(&server_name);
    let mut addrs: Vec<SocketAddr> = match &resolution {
        HostResolution::Static(ips) => ips_to_addrs(ips, port, prefer_family),
        HostResolution::Network(name) => {
            resolve_host_all(&bootstrap_clients, name, port, prefer_family).await
        }
    };

    // 2) 静态命中但按 prefer_family 过滤后为空，回退网络解析（用原域名）。
    if addrs.is_empty() && matches!(resolution, HostResolution::Static(_)) {
        addrs = resolve_host_all(&bootstrap_clients, &server_name, port, prefer_family).await;
    }

    if addrs.is_empty() {
        return Err(format!("failed to resolve dynamic upstream '{}'", server_name));
    }

    // 3) balance prefers 排序候选 IP。
    let ranked = balance.rank_ips(addrs.iter().map(|a| a.ip()).collect());
    let addrs: Vec<SocketAddr> = ranked.into_iter().map(|ip| SocketAddr::new(ip, port)).collect();

    info!("    resolved '{}' -> {:?}", server_name, addrs);
    let pool = build_resolved_pool(&all_configs[idx], addrs);
    all_configs[idx] = UpstreamConfig::Pool { pool };
}
```

说明：

- `resolve_host_all`（原 `bootstrap_resolve_all` 内部函数）提升为模块级函数，仅作为
  兜底；`bootstrap_resolve_all` 包装被内联到 Phase 2，复用其内部的 `resolve_host_all`。
- hosts 命中别名/CNAME（链末端无静态 IP）时，使用 hosts 指向的**新名称**走网络解析，
  **不再用原始域名**；这正是请求期 `handle` 中“原域名无 IP 时改写继续走管线”在启动
  期的对应处理。
- `NeedResolve` 的 `factory` / `raw_pool` / `proto` 经 `build_resolved_pool` 复用，
  建池逻辑不变。
- 若 `prefer_family` 为 `ipv4`/`ipv6` 且 hosts 给出的 IP 全部为另一族，则 `addrs`
  为空、回退到网络 bootstrap（用原始域名，行为稳健）。
- **放宽“无 IP 上游”启动报错**：当所有域名上游都被 hosts 覆盖（静态 IP 或别名新名称）
  时，不再强制要求存在 IP 上游；仅在“有上游既无 hosts 覆盖、又无 IP 服务器可网络解析”
  时才报错。

## 5. 配置影响

| 位置 | 变更 |
|------|------|
| `src/main.rs` | `balance::init` 上移到 `upstream::init` 之前；`upstream::init` 多传 `&hosts`、`&balance` |
| `src/plugins/hosts.rs` | `Hosts` 新增 `pub fn resolve_host_name` 与 `HostResolution` 枚举（替代原 `lookup_static`） |
| `src/plugins/balance.rs` | `Balance` 新增 `pub fn rank_ips` |
| `src/upstream/mod.rs` | `init` 签名新增 `hosts`/`balance`；Phase 2 改写为 hosts 优先 + balance 排序；`build_resolved_pool` 复用 |

无新增配置字段；`hosts:` 与 `balance:` 现有写法不变。

## 6. 测试

- **hosts**：`resolve_host_name` 单测——直接 IP 命中返回 `Static`；alias 且原域名有
  IP 返回 `Static`（原域名 IP）；alias 但原域名无 IP 返回 `Network`(新名称)；循环
  别名、未命中返回 `Network`(当前名)。
- **upstream**：`init` 集成测试——配置一个**域名** doh/dot 上游，并在 `hosts:` 中
  用 **CNAME 别名**（别名原域名无 IP）指向另一个域名；断言 `init` 不依赖 IP bootstrap
  客户端、改用 hosts 指向的新名称走网络解析即可完成（无 IP 上游、仅 hosts 覆盖也能
  成功），验证“CNAME→新名称解析”路径。
- **balance**：`rank_ips` 单测——给一组混合 v4/v6 IP 与 `prefers` CIDR，断言稳定
  排序结果（命中 CIDR 的在前、同排名保持顺序）；`enabled=false` / `cidrs` 为空时
  原样返回。
- **upstream**：`init` 集成测试，配置一个**域名** doh/dot 上游，并在 `hosts:` 中
  给该域名配置静态 IP；断言 `init` 不依赖 IP bootstrap 客户端即可完成（即无 IP
  上游、仅有 hosts 覆盖的域名上游时也能成功），且解析出的地址等于 hosts 的 IP
  （过滤 `prefer_family`）。该用例不触网，验证“hosts 优先”短路。
- **upstream**：`rank_ips` 接入后，给一个会解析出多 IP 的域名（或 hosts 给多 IP）
  并配置 `prefers`，断言最终候选顺序符合 `prefers`。

## 7. 兼容性

- `hosts:` 段为空 / 未配置：域名上游回退到原网络 bootstrap，**行为不变**。
- `balance:` 段为空 / 未配置：`rank_ips` 为无操作，候选顺序不变，**行为不变**。
- 启动期仍是“非 rules”流程，不改动请求期管线、rules、cache。
- `balance` 在启动期（上游服务器 IP 排序）与请求期（应答 IP 排序）复用同一份
  `prefers`，是两个独立的、互不影响的用途，已在文档中明确区分。

## 8. 风险

- `upstream` 新增对 `plugins::{hosts,balance}` 的依赖方向。二者均为启动期装配、
  内部 `Arc` 持有的轻量类型，且该依赖只发生在 `init`（装配期），不影响请求期，
  可接受。
- hosts 多 IP 与 `prefer_family` 组合：过滤后为空时回退网络 bootstrap，避免误判
  为解析失败。
- balance 排序只影响连接池初始候选顺序；运行时连接池仍按自适应加权/冷却独立决策，
  排序仅作为偏好提示，不会破坏现有故障转移语义。
