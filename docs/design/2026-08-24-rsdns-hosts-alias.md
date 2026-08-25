# rsdns `hosts` 插件支持 `domain domain,…` 代替域名（别名）格式

## 1. 背景

当前 `hosts` 插件（`src/plugins/hosts.rs`）只支持 `IP domain [domain...]`
格式：一行 = 一个 IP + 若干域名，命中后直接以**查询名**为 owner 返回 A/AAAA 并
短路管线（`Step::Respond`）。

没有“域名 → 域名”的别名能力：无法把一批代替域名（`domain,…`）统一指向一个
**原始域名**。

使用场景：CDN / 内网别名——多个域名映射到一个原始域名，客户端查询代替域名时按
原始域名解析。

## 2. 目标

`hosts` 增加 `original_domain alias1 alias2 ...` 别名行（**空白分隔**，与现有 IP
行一致；首个 token 为原始域名，其余为代替域名/别名）。查询**别名**时的行为：

- 原始域名在 hosts 中有 IP 映射 → **hosts 短路**（`Respond`）：按**查询名**返回
  A/AAAA（data），IP 取自原始域名映射；
- 原始域名在 hosts 中无 IP 映射 → **hosts 不短路**：把解析目标改写为原始域名，
  **继续走管线**（groups → cache → rules → upstream），最终应答（data 或 nodata）
  一律按**查询名**呈现（question 与 answer owner 均为查询名，非原始域名）；
- 两种情况均**无 CNAME 记录**。

不新增配置段：`hosts:` 条目仍是字符串列表，按行解析（内联条目 + `file://` 源均
支持，file 监控/原子替换机制不变）。

**非目标**：不生成 CNAME 记录；不支持多级链式别名（只解析一层，见 §3）；不新增
metrics。

## 3. 语义决策

| 决策点 | 决定 |
|---|---|
| 行格式 | `original_domain alias1 alias2 ...`，空白分隔；首个 token = 原始域名，其余 = 别名 |
| 别名命中 + 原域名有 IP | hosts 短路；按**查询名**返回 A/AAAA（owner = 查询名），IP = 原域名的 IP 列表；无 CNAME |
| 别名命中 + 原域名无 IP | hosts 改写解析目标为原域名，**继续走管线**（groups/cache/rules/upstream）；最终应答按**查询名**呈现——data（上游解析出 IP）或 nodata（NOERROR 空应答）均改 owner/question 为查询名；上游返回 NXDOMAIN 时同样按查询名呈现 NXDOMAIN |
| 直接查询原域名 | 行为不变（原域名另有 IP 行则命中 IP，否则继续管线） |
| 链式别名 | **不支持**：只解析一层；原域名在 hosts 中不是 IP 映射（是别名或不存在）→ 走“无 IP”分支（改写为该原域名继续管线） |
| 自引用 / 无别名 | 忽略（`foo.com foo.com`；`foo.com` 单 token 不构成别名行） |
| 与 IP 行同名冲突 | 保持现有“按配置顺序逐条解析”，trie 同 key 后定义覆盖先定义；文档化，建议别名行放 IP 行之后 |
| 原域名为纯数字串 | 跳过该别名行（避免与 IP 索引 tag 的 usize 歧义，见 §6） |
| 缓存 | hosts 短路应答不写缓存（与现有 hosts 一致）；无 IP 分支改写后由 cache 按**原域名** key 正常查询/写入 |
| metrics | 复用现有 `lookup_total / hit_total / entries`，不新增 |
| 应答 question | 两条分支的应答 question 均为查询名（有 IP 分支天然是查询名；无 IP 分支由 server 恢复为查询名） |

## 4. 实现

### 4.1 数据结构（`src/plugins/hosts.rs`）

现有 `HostsTrie` 的 trie tag 只承载 IP 列表下标（usize 字符串）。扩展为两类 tag：
IP 行 tag = 下标字符串；别名行 tag = 原始域名。查询结果用一个枚举表达：

```rust
pub enum Lookup<'a> {
    /// 直接命中 IP 映射（现有行为）。
    Ips(&'a [IpAddr]),
    /// 命中别名：tag 为原始域名（需再查一次原域名的 IP 映射）。
    Alias(&'a str),
    Miss,
}

impl HostsTrie {
    pub fn lookup(&self, domain: &str) -> Lookup<'_> {
        match self.trie.lookup(domain) {
            Some(tag) => match tag.parse::<usize>() {
                Ok(idx) => self.ips.get(idx).map(|v| Lookup::Ips(v.as_slice())).unwrap_or(Lookup::Miss),
                Err(_) => Lookup::Alias(tag),
            },
            None => Lookup::Miss,
        }
    }
}
```

构建端新增别名行解析（tag = 原域名字符串，不走 `domain_to_idx` / `ips`）：

```rust
/// 解析一行别名：`original_domain alias1 alias2 ...`。
fn parse_alias_line(builder: &mut HostsTrieBuilder, line: &str) {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return;
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let original = parts[0];
    // 原域名是 IP 或纯数字串 → 跳过（IP 行交给 parse_hosts_line；纯数字串
    // 会与 IP 索引 tag 的 usize 解析歧义）。
    if original.parse::<IpAddr>().is_ok() || original.parse::<usize>().is_ok() {
        return;
    }
    for alias in &parts[1..] {
        if alias == &original {
            continue; // 自引用忽略
        }
        builder.insert_alias(alias, original);
    }
}

impl HostsTrieBuilder {
    /// 别名：`alias → original`，tag 为原域名（区别于 IP 行的下标 tag）。
    pub fn insert_alias(&mut self, alias: &str, original: &str) {
        self.builder.insert(alias, original);
    }
}
```

`build_hosts_trie` 对每条 entry（及 file 源的每一行）先试 IP 行、再试别名行。
`parse_hosts_line` 增加返回 `bool`（true = 该行已消费；false 交给
`parse_alias_line`）：

```rust
fn parse_hosts_line(builder: &mut HostsTrieBuilder, line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return true; // 空/注释行：已消费
    }
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return false;
    }
    if let Ok(ip) = parts[0].parse::<IpAddr>() {
        for domain in &parts[1..] {
            builder.insert(domain, ip);
        }
        return true;
    }
    false // 非 IP 行 → 尝试别名行
}

// build_hosts_trie 内每行：
if !parse_hosts_line(&mut builder, line) {
    parse_alias_line(&mut builder, line);
}
```

> 现有行为保持：非法行（首 token 既非 IP、又不足 2 个 token）静默跳过，不报错。

### 4.2 `Hosts::handle` 逻辑（`plugins/hosts.rs`）

```rust
pub fn handle<'a>(&'a self, ctx: &'a mut QueryContext) -> Step {
    self.metrics.lookup_total.inc();
    let name = ctx.name().to_string();
    match self.trie.read().lookup(&name) {
        Lookup::Miss => Step::Continue,
        Lookup::Ips(ips) => self.respond_data(ctx, &name, ips.to_vec()),
        Lookup::Alias(original) => {
            // 别名：原域名有 IP → 按查询名返回 data（短路）；
            // 无 IP（含原域名也是别名）→ 改写解析目标为原域名，继续走管线，
            // 最终应答由 server 按查询名呈现。
            match self.trie.read().lookup(original) {
                Lookup::Ips(ips) => self.respond_data(ctx, &name, ips.to_vec()),
                _ => {
                    ctx.original_name = Some(name);
                    ctx.rewrite_name(original);
                    Step::Continue
                }
            }
        }
    }
}

/// 按查询名构造 hosts A/AAAA 应答并短路（owner = 查询名，IP 来自原域名映射）。
fn respond_data(&self, ctx: &mut QueryContext, name: &str, ips: Vec<IpAddr>) -> Step {
    self.metrics.hit_total.inc();
    match build_hosts_response(&ctx.msg, name, ctx.qtype(), &ips) {
        Ok(resp) => {
            ctx.response = Some(resp);
            ctx.action = "hosts".into();
            Step::Respond
        }
        Err(e) => {
            log::warn!("hosts building response for {} failed: {}", name, e);
            ctx.response = Some(build_servfail(&ctx.msg));
            ctx.action = "hosts".into();
            Step::Respond
        }
    }
}
```

`build_hosts_response`（`plugins/util.rs`）签名不变：`(msg, name, qtype, ips)`，
owner 即传入的查询名。

### 4.3 `QueryContext`（`src/query.rs`）

```rust
pub struct QueryContext {
    // ... 现有字段 ...
    /// hosts 别名改写前的客户端查询名（别名本身）。由 hosts 在把解析目标
    /// 改写为原域名时设置；server 在应答收尾时把 question 与 answer owner
    /// 恢复为该名字（无 IP 分支的“按查询名呈现”）。
    pub original_name: Option<String>,
}

impl QueryContext {
    /// 把解析目标改写为 `name`（hosts 别名：别名 → 原始域名）。
    /// 同步更新 cache key 与 msg 的 question name，使后续
    /// groups/cache/rules/upstream 全部按新目标处理。
    pub fn rewrite_name(&mut self, name: &str) {
        self.key.name = name.to_string();
        if let Ok(n) = hickory_proto::rr::Name::from_utf8(name) {
            if let Some(q) = self.msg.queries.first_mut() {
                q.set_name(n);
            }
        }
    }
}
```

### 4.4 `server.rs` 应答收尾（按查询名呈现）

`handle_query` 在 speed 阶段之后、写回缓存/日志之前，恢复应答的 question 与
answer owner 为 `ctx.original_name`（若设置）：

```rust
// 别名无 IP 分支：应答按客户端查询名（original_name）呈现，而非解析目标。
if let Some(original) = ctx.original_name.take() {
    if let Ok(n) = hickory_proto::rr::Name::from_utf8(&original) {
        if let Some(resp) = ctx.response.as_mut() {
            if let Some(q) = resp.queries.first_mut() {
                q.set_name(n.clone());
            }
            for ans in &mut resp.answers {
                ans.name = n.clone();
            }
        }
    }
}
```

> 缓存写入不受影响：`cache_upstream_response` 只提取记录（owner 无关），key 为
> 改写后的原域名——别名查询的结果按原域名缓存，后续直查原域名可直接命中。

### 4.5 示例与文档

`example/rsdns-all-example.yaml` 的 `hosts:` 段增加一行：

```yaml
hosts:
  - "127.0.0.1 localhost"
  - "::1       localhost"
  - "edge.example.com cdn1.example.com cdn2.example.com"   # 别名：查询 cdn1/cdn2 → 按 edge.example.com
```

`plugins/hosts.rs` 模块文档注释同步更新格式说明（IP 行 + 别名行两种格式）。

### 4.6 测试

- 纯函数：`parse_hosts_line`（返回 bool）、`parse_alias_line`（IP 行 / 别名行 /
  注释 / 空行 / 自引用 / 单 token / 原域名为 IP / 纯数字）。
- `HostsTrie::lookup`：`Ips` / `Alias` / `Miss` 三类；别名 tag 与原域名 IP 行共存。
- `Hosts::handle`：
  - 别名 + 原域名有 IP → `Respond`，answer owner = 查询名、IP = 原域名 IP；
  - 别名 + 原域名无 IP → `Continue`，`ctx.original_name == Some(查询名)`、
    `ctx.key.name` / msg question 改写为原域名；
  - 直接查原域名 → 现有行为（`Respond` data）。
- `QueryContext::rewrite_name`：key 与 msg question 同步改写。
- 沿用现有测试风格，不引入 mock（`handle` 通过真实 trie 构造测试）。

## 5. 验证

`make ci`（fmt + clippy + check + test）通过。

## 6. 风险 / 待确认

- **链式别名**：只解析一层；原域名在 hosts 中不是 IP 映射（是别名或不存在）→
  改写为该原域名继续管线（该原域名若又是别名，不再二次解析）。如需多级链式解析
  可后续扩展。
- **数字域名歧义**：原域名为纯数字串时跳过该别名行（避免与 IP 索引 tag 的 usize
  解析冲突）。
- **同名冲突**：别名行与 IP 行使用同一 trie、同一 key 时后定义覆盖先定义（保持
  现有按配置顺序解析行为）。
- **NXDOMAIN 呈现**：无 IP 分支若管线最终返回 NXDOMAIN（rules 无匹配），按查询名
  呈现 NXDOMAIN（question 改写，无 answer）。与“data 或 nodata”同属“按查询名返回
  信息”的自然延伸。
- **日志**：无 IP 分支日志中的 `{name}` 为改写后的原域名（`ctx.name()`）；如需
  记录客户端查询名可后续在 logs 阶段消费 `ctx.original_name`，本期不实现。
