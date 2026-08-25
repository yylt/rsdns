# rsdns `forward` 动作新增 `resolve_cname` 配置

## 1. 背景

当前 `forward` 动作（`src/plugins/rules.rs`）只做一件事：把查询发给
指定 upstream，应用 TTL 覆盖与 `max_answers` 截断后直接作为应答。对上游只返回
CNAME 而不带最终地址（如非递归 / 权威上游）的情况没有处理，客户端拿不到可直接
连接的 A/AAAA。

## 2. 目标

新增 `forward.resolve_cname: bool`（默认 `false`，不改变现有行为）。启用后，当
上游应答**第一条**是 CNAME 记录时，主动解析其 target：

- 若应答中**连续多条都是 CNAME**（纯 CNAME 链，如 `static.eeo.cn →
  static.eeo.cn.cdn.dnsv1.com → best.sched.skalego.tdnsstic1.cn`），**只处理
  最后一条 CNAME**：直接解析最后一个 target，跳过多级中间链。
- **返回 A/AAAA** → **替换**：删除原 CNAME（链），仅保留解析得到的 A/AAAA
  记录，且这些记录的 owner name **改写为原查询名**（与现有 `cname` 动作
  `handle_cname` 把上游应答 owner 改写为 `query_name` 的行为一致）。
- **返回空**（无 answer）→ **丢弃**该（最后一条）CNAME，停止处理（不检查
  下一条——因为已是最后一条；若链上其他记录也被移除则返回空 NOERROR/NODATA）。
- **返回 CNAME**（target 本身仍是 CNAME）→ **不丢弃**，原样返回上游原始响应
  （不追链）。

首条非 CNAME 时不触发任何处理，原样返回。

## 3. 语义决策

| 决策点 | 决定 |
|---|---|
| 触发条件 | 应答首条为 CNAME；连续多条 CNAME 时只处理最后一条 |
| A/AAAA 替换方式 | 删除原 CNAME（链），仅保留 A/AAAA，owner 改写为原查询名 |
| 返回空 | 丢弃该（最后一条）CNAME，停止处理，不检查下一条 |
| 返回 CNAME 分支 | 保留原 CNAME，停止处理，原样返回上游原始响应 |
| 解析用哪个 upstream | 复用同一条 forward 规则指定的 upstream；qtype 与原查询一致 |
| 解析出错（upstream 查询失败） | 保持原响应原样返回（不丢弃、不替换） |
| 解析返回首条为其他类型（MX/TXT/HTTPS…） | 原样返回，不破坏数据 |

不递归追多级 CNAME 链；不新增独立配置（如单独指定解析 upstream / 解析 qtype）。

## 4. 实现

### 4.1 `src/config.rs`

`RuleActionConfig::Forward` 增加字段：

```rust
/// 上游应答第一条为 CNAME 时，主动解析其 target（同 upstream、同 qtype）。
#[serde(default)]
resolve_cname: bool,
```

### 4.2 `src/plugins/rules.rs`

- `RuleAction::Forward` 增加 `resolve_cname: bool`。
- `init()` 的 `RuleActionConfig::Forward` 分支填充该字段。
- `apply_rule` 的 Forward 分支把 `*resolve_cname` 传给 `forward_query`。
- `forward_query` 在拿到上游响应后、TTL 覆盖与 `max_answers` 截断**之前**插入
  resolve 处理：

```rust
if resolve_cname {
    self.resolve_cnames(ctx, upstream, &mut resp).await;
}
```

- 新增 `resolve_cnames` 方法：当应答首条为 CNAME 且连续多条都是 CNAME 时，
  定位到最后一条 CNAME（取 `answers` 末尾，若末尾非 CNAME 则取末尾之前最近
  的 CNAME）并解析其 target；逻辑见 §2。抽出纯函数辅助：
  - 定位函数：`last_cname_index(answers)` → 连续 CNAME 链的最后一个 CNAME 下标；
  - 分类函数：按解析结果**首条 answer** 判定 `Empty / Address(A·AAAA) / Cname / Other`；
  - 替换函数：从解析结果过滤出 A/AAAA 记录，并把 owner name 改写为原查询名。

### 4.3 测试

- 纯函数单测：分类（空 / A / AAAA / CNAME / 其他）、A/AAAA 过滤 + owner 改写。
- config 解析测试：`action: { type: forward, upstream: default, resolve_cname: true }`。
- 沿用现有测试风格，不引入 mock 框架（resolve 循环依赖真实 upstream，仅测纯函数部分）。

## 5. 验证

`make ci`（fmt + clippy + check + test）通过。
