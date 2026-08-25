# rsdns 设计方案

> 2025-08-05 | 提案

## 概述

rsdns 是一个独立的 DNS 服务端程序，启动时加载 YAML 配置文件，对外提供 UDP / TCP DNS 服务。上游支持 UDP、TCP、DoT (DNS over TLS)、DoH (DNS over HTTPS)、DoH3 (DNS over HTTP/3)。

核心能力：
- 域名分组 → FST 后缀匹配路由
- hosts 后缀匹配 → 固定 IP 响应
- 多上游并发，第一个返回生效
- 带 `serve_expired` / `keep_ttl` 的 LRU 缓存
- bootstrap 机制解析 DoH/DoT 域名
- 规则动作：block (nxdomain / poison)、cname (template)、forward

---

## 查询流程

```
请求进入
  │
  ▼
① 查 hosts (FST suffix trie) ── 命中 → 返回固定 IP
  │
  ▼
② 按序匹配 rules (FST suffix trie lookup group)
  ├── action: block
  │     response: nxdomain → NXDOMAIN
  │     response: poison   → A=0.0.0.0, AAAA=::
  │
  ├── action: cname (template)
  │     target: bar.com → 递归 resolve bar.com, 返回其 IP
  │
  └── action: forward
        cache=true:
          ├── fresh → return
          ├── stale + upstream fail → serve_expired? stale : SERVFAIL
          └── miss → upstream (组内并发, 第一个返回)
        cache=false:
          → 直接 upstream, 不查 cache 也不写 cache
        ttl: 若指定则重写响应中的 TTL
```

---

## 配置

### 完整示例

```yaml
bind:
  - address: "0.0.0.0:53"           # UDP
  - address: "tcp://0.0.0.0:53"     # TCP

# 域名分组 → 构建 FST suffix trie
groups:
  ad:
    - file:/path/to/ad-block.txt
    - "*.doubleclick.net"
  intranet:
    - "*.corp.internal"
  foo:
    - foo.com
    - "*.foo.org"

# 上游池: name → servers (组内并发, 第一个返回)
upstream:
  default:
    servers:
      - address: 223.5.5.5
        bootstrap: true
      - address: tls://dot.pub
      - address: https://doh.pub/dns-query
  overseas:
    servers:
      - address: tls://8.8.8.8
      - address: h3://doh3.example/dns-query

cache:
  size: 4096
  min_ttl: 60
  max_ttl: 3600
  serve_expired: true                # 上游不可用时返回过期缓存
  keep_ttl: false                    # 全局; 可每规则覆盖

# hosts: 后缀匹配, 纯 FST trie (不打 tag, 直接映射到 IP)
hosts:
  - "127.0.0.1 localhost"
  - "0.0.0.0 *.ad-domain.com"
  - file:/etc/hosts

# 规则: 顺序匹配, 命中即停止
rules:
  - match: foo
    qtype: ANY
    action:
      type: cname
      target: site.182682.xyz
      ttl: 600

  - match: ad
    action:
      type: block
      response: poison               # A=0.0.0.0, AAAA=::

  - match: intranet
    action:
      type: forward
      upstream: default
      cache: false                   # 跳过 cache

  # 默认 catch-all
  - match: "*"
    action:
      type: forward
      upstream: default
      keep_ttl: true                 # 保留上游原始 TTL
```

---

## 数据结构

### Config (`src/config.rs`)

```rust
pub struct Config {
    pub bind: Vec<BindConfig>,
    pub groups: Vec<HashMap<String, Vec<String>>>,
    pub upstream: HashMap<String, UpstreamPool>,
    pub cache: Option<CacheConfig>,
    pub hosts: Vec<String>,
    pub rules: Vec<RuleConfig>,
}

pub struct BindConfig {
    pub address: String,          // "0.0.0.0:53" | "tcp://0.0.0.0:53"
}

pub struct UpstreamPool {
    pub servers: Vec<ServerConfig>,
}

pub struct ServerConfig {
    pub address: String,          // "223.5.5.5" | "tls://dot.pub" | "https://..." | "h3://..."
    pub bootstrap: bool,
}

pub struct CacheConfig {
    pub size: Option<usize>,
    pub min_ttl: Option<u32>,
    pub max_ttl: Option<u32>,
    pub serve_expired: Option<bool>,
    pub keep_ttl: Option<bool>,
}

pub struct RuleConfig {
    pub r#match: String,          // group 名 或 "*" catch-all
    pub qtype: Option<String>,    // "A" | "AAAA" | "ANY" | "PTR" ...
    pub action: RuleActionConfig,
}

pub enum RuleActionConfig {
    Block {
        #[serde(default = "default_block_response")]
        response: BlockResponse,  // nxdomain | poison
    },
    Cname {
        target: String,
        ttl: Option<u32>,
    },
    Forward {
        upstream: String,
        #[serde(default = "default_true")]
        cache: bool,
        ttl: Option<u32>,         // 重写响应 TTL (None=使用上游值)
        keep_ttl: Option<bool>,   // 保留上游原始 TTL, 优先级高于 ttl
    },
}

pub enum BlockResponse {
    NXDomain,
    Poison,
}
```

### UpstreamClient (`src/upstream.rs`)

```rust
pub enum UpstreamProtocol {
    Udp,
    Tcp,
    Tls { server_name: String },
    Https { url: String },
    H3 { url: String },
}

pub struct UpstreamClient {
    addrs: Vec<SocketAddr>,
    protocol: UpstreamProtocol,
    tls_config: Option<Arc<ClientConfig>>,
    bootstrap: bool,
    is_dynamic: bool,    // true: addrs 需要启动时解析
}

/// 上游组: 组内所有上游并发查询, 第一个成功返回
pub struct UpstreamGroup {
    clients: Vec<UpstreamClient>,
}

impl UpstreamGroup {
    /// 并发: FuturesUnordered → 第一个成功返回
    /// 全部失败返回错误
    pub async fn query(&self, msg: &Message) -> io::Result<Message>;
}
```

### Rule Engine (`src/rule.rs`)

```rust
pub enum RuleAction {
    Block { response: BlockResponse },
    Cname { target: String, ttl: u32 },
    Forward { upstream: String, cache: bool, ttl: Option<u32>, keep_ttl: Option<bool> },
}

pub enum BlockResponse {
    NXDomain,
    Poison,
}

pub struct Rule {
    pub group: String,               // group 名; "*" = catch-all
    pub qtype: Option<RecordType>,   // None = 所有类型
    pub action: RuleAction,
}
```

### DnsCache 增强 (`src/cache.rs`)

```rust
pub enum CacheResult {
    Fresh(CacheEntry),
    Stale(CacheEntry),
    Miss,
}

impl DnsCache {
    /// 返回区分新鲜/过期/stale
    pub fn get_cached(&self, key: &CacheKey) -> CacheResult;

    /// keep_ttl=true 时跳过 min_ttl/max_ttl 钳制
    pub fn put(&self, key: CacheKey, records: Vec<CacheRecord>, ttl: u32, keep_ttl: bool);
}
```

---

## Hosts 后缀匹配

Hosts 使用独立的 FST trie，key 为反转域名，value 为 IP 地址索引：

```rust
pub struct HostsTrie {
    trie: DomainSuffixTrie,     // FST: 反转发域名 → tag_id
    ips: Vec<Vec<IpAddr>>,      // tag_id → IP 列表
}

impl HostsTrie {
    pub fn lookup(&self, domain: &str) -> Option<Vec<IpAddr>>;
}
```

构建时：`*.ad.example.com` → 去前缀 `*` → 插入 `ad.example.com` → 自动后缀匹配。

---

## Bootstrap

`bootstrap: true` 的上游用**系统 DNS** 解析地址，并用于解析 `bootstrap: false` 上游的域名。

启动流程：

1. 解析所有 `bootstrap: true` 上游的地址（用 `ToSocketAddrs`）
2. 用这些上游解析 `bootstrap: false` 的 DoH/DoT 域名
3. 替换 `UpstreamClient` 中的动态地址
4. 广播 ready，开始处理客户端请求

---

## 实现清单

| # | 文件 | 内容 |
|---|------|------|
| 1 | `config.rs` | 重写 Config / UpstreamPool / RuleConfig / RuleActionConfig / ServerConfig |
| 2 | `hosts.rs` (新) | HostsTrie: FST 后缀匹配 + IP 索引 |
| 3 | `rule.rs` (新) | Rule / RuleAction / BlockResponse 定义 + 匹配逻辑 |
| 4 | `upstream.rs` | 重写: DoH (hyper POST), DoH3 (h3/quinn), UpstreamGroup (并发, 第一个返回), bootstrap 字段 |
| 5 | `cache.rs` (新) | DnsCache 增强: CacheResult, serve_expired, keep_ttl |
| 6 | `server.rs` | 重写: serve_udp + serve_tcp (RFC 1035), 完整响应构造 (A/AAAA/CNAME records), forward + cache 集成 |
| 7 | `main.rs` | 重写: parse_upstream (所有协议), build_groups/build_hosts/build_rules, bootstrap 流程, 启动 DnsServer |
| 8 | `Cargo.toml` | 添加 `h3`, `quinn` 依赖 |
