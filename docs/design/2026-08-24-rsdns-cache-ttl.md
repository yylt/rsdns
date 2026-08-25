# rsdns cache：移除 server-stale，改用 moka 每条目 TTL 自动过期删除

## 1. 背景

当前 `DnsCache`（`src/plugins/cache.rs`）的过期处理是**手动**的：

- `CacheEntry` 保存 `expires_at: Instant`，写入时计算 `now + ttl_duration`；
- `get_cached` 读取时自行比较 `expires_at` 判定 Fresh / Stale；
- `serve_expired: true` 时把过期条目当作 Stale 兜底应答返回，并标记
  `ctx.served_stale`，让 `rules` 阶段用上游新鲜结果替换（`refresh_stale`），
  失败则保留过期应答。

这套 server-stale 逻辑横跨 `cache` / `rules` / `query` 三个模块，引入
`served_stale`、`CacheResult::Stale`、`forward-stale` 动作、`serve_expired_total`
指标，行为分支多、维护成本高。

moka 0.12 原生支持**每条目 TTL**（`Expiry` trait + 后台自动过期驱逐），可以
替代手动 `expires_at` 判定与过期清理。

## 2. 目标

1. **移除 server-stale**：不再返回过期数据。上游不可用/失败 → SERVFAIL。
   删除 `serve_expired` 配置、`served_stale` 状态、`CacheResult::Stale`、
   `forward-stale` 动作、`serve_expired_total` 指标，以及 `rules` 中的 stale 分支。
2. **改用 moka 每条目 TTL 自动过期删除**：过期判定与驱逐交给 moka
   （读取时排除已过期条目，后台 housekeeper 定时清理），删除手动
   `expires_at` 新鲜度判定。
3. 保留现有能力：LRU 容量、`min_ttl`/`max_ttl` 钳制、`keep_ttl`、
   正/负缓存（NXDOMAIN/NoData）、TTL 递减应答、`rsdns_cache_lookup_total` /
   `rsdns_cache_entries` 指标。

## 3. 现状（关键代码路径）

- `DnsCache::get_cached` → `Fresh`：构造应答 `Respond`（短路，跳过 rules）；
  `Stale`（`serve_expired`）→ 构造过期兜底 + `ctx.served_stale = true` +
  `Continue`（rules 尝试刷新）；`Miss` → `Continue`。
- `rules::handle` / `apply_rule` 多处 `ctx.served_stale` 分支：无匹配时保留过期
  应答；forward 失败时保留过期应答；`forward_query` 成功后 `served_stale = false`
  允许写回缓存。
- `server::handle_query` 回卷：`cache.write_back` 跳过 `ctx.served_stale` 的响应。

## 4. 方案

### 4.1 每条目 TTL：moka `Expiry`

不同记录 TTL 不同，不能使用 cache 级 `time_to_live`（全局统一时长）。改用
moka `Expiry` trait（`moka::Expiry`，`future` feature 下已可用，无需改 Cargo.toml）：

```rust
struct TtlExpiry { min_ttl: Duration, max_ttl: Duration, keep_ttl: bool }

impl Expiry<CacheKey, CacheEntry> for TtlExpiry {
    fn expire_after_create(&self, _k: &CacheKey, v: &CacheEntry, _created_at: Instant) -> Option<Duration> {
        Some(self.duration_for(v))
    }
    fn expire_after_update(&self, _k: &CacheKey, v: &CacheEntry, _updated_at: Instant, _remaining: Option<Duration>) -> Option<Duration> {
        Some(self.duration_for(v)) // 重新插入 = 重置为新 TTL（必须覆盖默认的“保留剩余时长”）
    }
}

fn duration_for(&self, v: &CacheEntry) -> Duration {
    if self.keep_ttl {
        Duration::from_secs(v.ttl as u64)
    } else {
        Duration::from_secs(v.ttl as u64).clamp(self.min_ttl, self.max_ttl)
    }
}
```

要点：

- **`expire_after_update` 必须覆盖**：trait 默认返回 `duration_until_expiry`
  （保留旧剩余时长），而我们需要每次 `put` 都按新 TTL 重新计时（与现状
  `put` 重算 `expires_at` 一致）。
- **`expire_after_read` 保持默认**（返回剩余时长，读不延长 TTL）——与现状一致。
- TTL 钳制 / keep_ttl 的时长计算仍集中在 `DnsCache`，Expiry 从
  `CacheEntry.ttl` 计算，`put` 中不再需要为驱逐而维护独立逻辑。
- `CacheEntry.expires_at` **保留**，仅供 `remaining_ttl` 计算应答 TTL 递减；
  moka 负责过期/驱逐。

### 4.2 `get_cached` 简化

moka `get` 读取时即排除已过期条目（命中即新鲜），因此：

```rust
pub async fn get_cached(&self, key: &CacheKey) -> Option<CacheEntry> {
    let entry = self.inner.get(key).await;
    // 指标：Some → "fresh"，None → "miss"
    entry
}
```

删除 `CacheResult` 枚举（不再有 Stale 变体）。`rsdns_cache_lookup_total` 的
`result` label 收敛为 `fresh` / `miss`。

### 4.3 删除 server-stale 全链路

- `config.rs`：`CacheConfig` 移除 `serve_expired` 字段。
- `query.rs`：移除 `served_stale` 字段。
- `plugins/cache.rs`：移除 `CacheResult::Stale`、`serve_expired` 字段、
  `serve_expired_total` 指标、`Cache::lookup` 的 Stale 分支、`write_back` 的
  `served_stale` 跳过；模块文档更新。
- `plugins/rules.rs`：移除全部 `ctx.served_stale` 分支（无匹配 → 一律 NXDOMAIN；
  forward 失败 → 一律 SERVFAIL；`forward_query` 成功后不再需要清标志）。
- `server.rs`：注释更新（cache 阶段：fresh 短路 / miss 继续，无 stale）。
- 行为变化：**上游失败不再回退过期数据**，返回 SERVFAIL。

### 4.4 配置与示例同步

- `example/rsdns-all-example.yaml`：删除 `serve_expired: true` 行与注释。
- `tests/e2e/test_rsdns.go`：3 处配置删除 `serve_expired: true`。
- serde 默认忽略未知字段，旧配置残留 `serve_expired: true` 不会报错（被静默
  忽略）；文档与示例同步清理以避免误导。

### 4.5 指标

- 删除 `rsdns_cache_serve_expired_total`。
- `rsdns_cache_lookup_total{result}` 的 label 变为 `fresh` / `miss`。
- `rsdns_cache_entries` gauge 语义说明：moka 惰性驱逐，已过期未物理删除的
  条目可能短暂计入；读取路径永远不会返回它们。

## 5. 涉及文件

| 文件 | 改动 |
|---|---|
| `src/plugins/cache.rs` | `TtlExpiry` + builder `expire_after`；`get_cached` → `Option`；删 Stale/serve_expired/指标；`new_metric` 签名去 `serve_expired`；模块文档；单测 |
| `src/config.rs` | `CacheConfig` 删 `serve_expired` |
| `src/query.rs` | 删 `served_stale` 字段 |
| `src/plugins/rules.rs` | 删 `served_stale` 分支（3 处）+ 注释 |
| `src/server.rs` | 注释更新 |
| `src/plugins/util.rs` | 测试中 `new_metric` 调用签名更新 |
| `example/rsdns-all-example.yaml` | 删 `serve_expired` |
| `tests/e2e/test_rsdns.go` | 3 处删 `serve_expired: true` |
| `docs/design/2026-08-20-rsdns-plugins.md` | 指标表与 cache 行为描述更新 |
| `AGENTS.md` | 架构描述（cache 行）更新 |

## 6. 测试

- `plugins/cache.rs` 单测：
  - 保留：fresh 命中、miss、空条目、NoData action_name、`remaining_ttl` 递减 /
    keep_ttl 原样。
  - 替换 `test_cache_stale`：短 TTL 写入（如 `min_ttl=0, max_ttl=1, ttl=1`），
    sleep 超过 TTL 后 `get_cached` 返回 `None`（验证 moka 自动过期）。
  - 新增（可选）：同 key 重新 `put` 后 TTL 重置（验证 `expire_after_update`
    覆盖生效）。
- `make ci`（fmt + clippy + check + test）通过。

## 7. 验证

`make ci` 通过；`make build-rsdns`（debug）通过。

## 8. 已确认决策（审阅通过）

1. 上游失败 → **SERVFAIL**，不再回退过期数据。
2. 保留 `CacheEntry.expires_at`，仅用于应答 TTL 递减计算（过期判定交给 moka）。
3. 旧配置中的 `serve_expired` 被 serde 静默忽略（不报错、不生效）。

## 9. 注意事项 / 兼容性

- 旧配置中的 `serve_expired` 被 serde 静默忽略，不报错、不生效。
- 行为变更明确：上游失败 → SERVFAIL（不再返回过期数据）。若后续需要
  “过期兜底”，应作为独立新功能重新设计（如返回过期数据同时后台刷新），
  不在本次范围内。
- moka 的每条目 TTL 过期是异步惰性驱逐：`entry_count`/gauge 不保证即时归零，
  读取路径保证不返回过期条目。
