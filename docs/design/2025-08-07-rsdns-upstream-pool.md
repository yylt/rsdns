# rsdns 上游连接池重构方案

> 2025-08-07 | 提案
>
> 2026-08-07 更新：本文已按当前实现回写，并明确区分“当前实现”“原始目标”“已知问题”。原提案中的部分机制尚未落地，不能再视为现状。

## 1. 动机

`rsdns` 已从早期固定上游客户端模型，演进到按协议建 `ConnectionPool` 的实现。当前代码已经具备以下基础能力：

- 不同协议通过 `ConnFactory` 延迟建连
- 域名上游在启动期通过 bootstrap 查询解析出 A + AAAA 全量地址
- 池内连接长期驻留，由 reaper 周期维护
- 地址选择带有基础失败反馈和冷却机制
- 上游组内并发查询，先成功先返回

但当前实现仍与原始提案目标有明显差距，尤其在连接复用模型和生命周期控制上。

## 2. 当前实现总览

### 2.1 组件关系

当前实际结构如下：

```text
UpstreamGroup
  -> Vec<UpstreamClient>
       -> Arc<ConnectionPool>
            -> VecDeque<PooledConn>
                 -> CloneableSender
                      -> protocol sender / mux wrapper
```

职责分工：

- `UpstreamGroup`：组内并发查询，第一条成功响应返回
- `UpstreamClient`：向单个池发起一次查询
- `ConnectionPool`：维护同一 upstream 的一组长期连接
- `CloneableSender`：把 `DnsRequestSender` 包成可 clone 的句柄
- `factory.rs`：按协议构造 UDP/TCP/TLS/DoH/DoH3/DoQ sender

### 2.2 当前启动流程

当前 `src/main.rs` 的启动阶段为：

1. 解析配置，构造 `UpstreamConfig`
2. phase 1：从已是 `Pool` 的 bootstrap upstream 中收集 `bootstrap_clients`
3. phase 2：对需要域名解析的非 bootstrap upstream，用 bootstrap 客户端解析 A + AAAA 全量地址
4. phase 3：将剩余静态 TCP upstream 转为 `Pool`
5. phase 4：组装 `UpstreamGroup`

与原提案相比，当前实现已经是“pool-first”模型，而不是 `DnsExchange` 列表模型。

## 3. 当前连接池实现

### 3.1 核心类型

当前 `src/pool.rs` 中：

```rust
pub struct ConnectionPool {
    connections: Arc<Mutex<VecDeque<PooledConn>>>,
    active_count: Arc<AtomicUsize>,
    max_size: usize,
    min_idle: usize,
    addresses: Vec<AddrState>,
    factory: ConnFactory,
    config: PoolConfig,
    reaper_handle: Mutex<Option<JoinHandle<()>>>,
    cursor: AtomicUsize,
}

struct PooledConn {
    sender: CloneableSender,
    created_at: Instant,
    last_used: Instant,
    addr: SocketAddr,
}

struct AddrState {
    addr: SocketAddr,
    consecutive_failures: AtomicU32,
    cooldown_until: Mutex<Option<Instant>>,
}
```

### 3.2 与原始提案的差异

当前实现不是“checkout -> 使用 -> return/drop wrapper -> 回 idle 队列”的模型，而是：

- 连接长期保存在 `connections`
- `checkout()` 仅返回某个 `PooledConn.sender.clone()`
- 没有独立 `CheckoutGuard`
- 没有“最后一个 clone drop 时再决定是否归还”的逻辑
- 连接健康状态主要由 reaper 和 `is_shutdown()` 判定

因此，原提案中以下内容尚未实现：

- `error_count` 聚合反馈
- `take_error_count()`
- 按 request 失败结果在 drop 时更新 `AddrState`
- 真正的 borrowed/returned 生命周期

## 4. 当前 checkout / reaper 行为

### 4.1 checkout

当前 `checkout()` 逻辑：

1. 锁住 `connections`
2. 若池非空，使用 `cursor` 做 round-robin 选取
3. 若连接 `is_shutdown()` 或超出 `max_lifetime`，移除并继续重试
4. 若没有可用连接且 `active_count < max_size`，则调用 `build_cloneable()` 新建连接
5. 建连失败时记录地址失败，短暂 sleep 后继续

这比原提案简单，但也意味着：

- 没有真正“借出占用”的概念
- 多个调用方可能长期共享同一个底层连接
- 池容量控制更接近“连接总数”而不是“借出数”

### 4.2 reaper

当前 reaper 每 10 秒执行一次：

1. 清理 dead / expired 连接
2. 对非 UDP 池挑选一个 stale 连接做 `SOA .` 健康检查
3. 调用 `refill_idle()`，把连接数补到 `min_idle`

这是当前实现最关键的后台维护机制。

## 5. 地址选择与反馈

### 5.1 已实现能力

当前 `pick_addr()` 已经具备：

- 过滤冷却中的地址
- 按 `prefer_family` 过滤 IPv4 / IPv6
- 使用 `1 / (1 + consecutive_failures)` 作为权重
- 无候选时走 fallback

### 5.2 反馈来源

当前地址反馈来自：

- 建连失败：`on_conn_error(addr)`
- 健康检查失败：`on_conn_error(addr)`
- 健康检查成功：`on_conn_success(addr)`

当前并不会因为某一个普通 query 失败，就立刻把该失败反馈回地址状态。这一点和原提案不同。

## 6. 协议工厂现状

### 6.1 已实现协议

当前 `src/factory.rs` 已包含：

- `udp_factory()`
- `tcp_factory()`
- `tls_factory()`
- `doh_factory()`
- `doh3_factory()`
- `doq_factory()`

### 6.2 现状说明

- UDP / DoH / DoH3 / DoQ 直接返回对应 sender
- TCP / TLS 通过 `MuxedSender` 包裹 `DnsMultiplexer`

这里与原始提案“所有协议统一为 CloneableSender 生命周期模型”不同。当前实现是两层包装：

- `pool.rs` 统一使用 `CloneableSender`
- `factory.rs` 对 TCP / TLS 还额外做了一层 `MuxedSender`

## 7. Bootstrap 行为现状

### 7.1 已实现行为

- 域名型 DoT / DoH / DoH3 / DoQ upstream 会在启动时通过 bootstrap client 解析 A + AAAA
- 解析出的全部地址会注入 `ConnectionPool`

### 7.2 当前限制

当前 `build_bootstrap_pools()` 只会收集 `UpstreamConfig::Pool`。

因此：

- bootstrap 的 UDP upstream 可以工作
- bootstrap 的静态 TLS / DoH / DoH3 / DoQ IP upstream 可以工作
- bootstrap 的静态 `tcp://` upstream 目前不会在 phase 1 转成 pool，因此不会参与 bootstrap 查询

这是一个实现缺口，不应被文档掩盖。

## 8. 已知问题

### 8.1 `reap()` 清理条件存在实现 bug

当前 `pool.rs` 中的保留条件与注释语义相反：

```rust
conns.retain(|conn| conn.is_shutdown() || conn.created_at.elapsed() > self.config.max_lifetime);
```

这会保留 shutdown / expired 连接，而不是清理它们。需要单独修复。

### 8.2 `MuxedSender` 没有真正发挥多路复用优势

当前 TCP / TLS 的 `MuxedSender` 后台任务是“逐 request 取出，再等待该 request 响应完成”，这会造成：

- 同一连接上的请求串行化
- head-of-line blocking
- 队列可堆积

这与原提案中对多调用方复用的性能预期不完全一致。

### 8.3 `MuxedSender` 的 shutdown 生命周期不完整

当前 `shutdown()` 主要通过 `AtomicBool` 暴露状态，但未彻底收束后台任务生命周期，存在任务滞留风险。

### 8.4 UDP pool 配置语义绕

当前 `RawPoolConfig::into_pool_config(true)` 让 UDP 默认 `max_size = 0`，随后 `parse_upstream()` 再把它改成 1。行为可用，但语义不直观，建议简化。

## 9. 优化方向

### 9.1 近期建议

1. 修复 `reaper` 的连接清理条件
2. 补齐 bootstrap TCP upstream 的 phase 3 / phase 1 行为一致性
3. 简化 UDP `max_size` 默认值处理
4. 让 `MuxedSender` shutdown 真正结束后台任务

### 9.2 中期建议

1. 重新设计 TCP/TLS multiplex 驱动，避免串行化请求
2. 用 bounded channel 替代 unbounded channel，控制内存上界
3. 评估是否保留两层包装：`MuxedSender` + `CloneableSender`

### 9.3 长期方向

如果仍然希望回到原始提案的完整生命周期模型，可继续推进：

- `CheckoutGuard`
- `error_count`
- drop 时反馈地址状态
- 更明确的 idle / active 归还语义

但在此之前，文档应以当前代码为准，而不是假定这些机制已经存在。

## 10. 当前配置字段

当前 `PoolConfig` 运行时字段包括：

- `max_size`
- `min_idle`
- `idle_timeout`
- `max_lifetime`
- `health_interval`
- `connect_timeout`
- `dns_timeout`
- `prefer_family`
- `health_check_timeout`
- `max_consecutive_fail`
- `cool_down`
- `is_udp`

对应 YAML 原始字段位于 `src/config.rs::RawPoolConfig`。

## 11. 文档定位

本文现在兼具两层含义：

- 当前实现说明：帮助读代码和理解现状
- 后续演进路线：标识哪些内容仍是目标而非已完成

后续若修复上述已知问题，建议把本文继续按“现状”更新，而不是只保留理想化设计。
