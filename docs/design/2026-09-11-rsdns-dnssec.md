# rsdns DNSSEC 支持（透传语义）方案

- 日期: 2026-09-11
- 状态: 提案（待审阅）
- 影响面: `src/server.rs`、`src/query.rs`、`src/plugins/{cache,util,rules,balance}.rs`、`src/upstream/mod.rs`、`example/rsdns-all-example.yaml`、`README.md` / `README.en.md`
- 本提案不含实现；审阅通过后再落地。

## 1. 动机

rsdns 当前对 EDNS / DNSSEC 相关报文没有任何显式处理，而"能透传 DNSSEC"和"能作为
验证解析器应答 DNSSEC 客户端"是两件不同的事。先确认现状：

### 1.1 现状核查（已用代码与实验验证）

| 环节 | 行为 | 结论 |
|------|------|------|
| 入站 EDNS OPT | 原样解析进 `ctx.msg.edns`（hickory `Message` 字段） | 保留 |
| 出站 DO 位 | `forward_query` 克隆 `ctx.msg` 后直接送上游（`rules.rs:821`），未动 DO | 透传 |
| 上游 RRSIG/NSEC/DNSKEY/DS | 未启用 hickory `__dnssec` 特性，这些类型按 `RData::Unknown`（原始字节）解析与重编码 | **字节级不变**（见 §1.2 实证） |
| 应答 AD 位 | 上游应答整体成为 `ctx.response`，未被清除 | 透传（仅缓存命中路径会丢，见 §3.3） |
| 上游 TC 截断 | UDP 上游的 `MAX_RECEIVE_BUFFER_SIZE = 4096`，hickory 不做 TCP 重试 | **缺口** |
| 缓存命中 | `CacheRecord` 只含 A/AAAA/CNAME/MX/TXT/HTTPS（`cache.rs:51`），RRSIG/NSEC/SOA 全部丢弃 | **缺口** |
| `balance.max_answers` | 对 `response.answers` 整体 `truncate`（`balance.rs:239`） | **缺口**（会剪断 RRset） |
| `forward.ttl` 覆盖 | `rewrite_ttl_in_response` 改所有 answer 的 TTL | 与 RRSIG 校验兼容，见 §3.4 |

### 1.2 实证：RRSIG/NSEC 无需 `__dnssec` 也能字节级透传

`hickory-proto` 0.26.1 在未开 `__dnssec` 时，`RData::read` 把 DNSSEC 类型走
`NULL`（raw bytes）分支（`record_data.rs`:`r if r.is_dnssec()` 分支被
`#[cfg(feature = "__dnssec")]` 排除 → 落到 `RData::Unknown { code, rdata }`），
`emit` 再原样写回。本地用与 rsdns 相同的 hickory 构建做了往返实验：

```text
OK RRSIG (46): type+rdata byte-identical round-trip
OK NSEC (47): type+rdata byte-identical round-trip
OK DNSKEY (48): type+rdata byte-identical round-trip
OK DS (43): type+rdata byte-identical round-trip
OK NSEC3 (50): type+rdata byte-identical round-trip
OK ad=true do=true payload=1232 rcode=NoError
```

即：**DNSSEC 记录与 AD/DO 位在 rsdns 的纯转发路径上已经是正确的**，不需要新增
依赖、不需要引入 `__dnssec`。本提案要做的不是"让 DNSSEC 能过"，而是"别在
rsdns 自己的缓存、截断、改写逻辑里把它弄坏"。

## 2. 目标 / 非目标

### 目标

1. 带 `DO=1` 或 `CD=1` 的查询**不经过缓存**（不查、不写），避免缓存命中时
   丢失 RRSIG/NSEC、以及"上游应答有 RRSIG、缓存命中应答没有"的静默降级。
2. 保证 DNSSEC 场景下 rsdns **不修改上游应答的应答集合**：
   - `balance` 对带 `DO=1`/`CD=1` 的应答不做 `max_answers` 截断；
   - `forward.resolve_cname` 对带 `DO=1`/`CD=1` 的应答不做 CNAME 链折叠/替换
     （折叠会改写 owner、重排/丢弃记录，破坏 RRSIG 覆盖）；
   - `cloudflare_ech` 补全对带 `DO=1`/`CD=1` 的应答跳过。
3. 在日志/指标里体现"这条查询是 DNSSEC 查询"，便于排障。
4. 明确并在文档中写下：**rsdns 是 DNSSEC 透传者，不是验证者**，AD 位按上游
   原样转发，`CD` 本身含义（关闭验证）由上游/客户端负责。

### 非目标

- **不做本地验证**：不内置根信任锚、不自行验 RRSIG/DNSKEY/DS、不做 NSEC(3)
  否定证明、不自行置位 AD。见 §7.1 的原因与后续路径。
- **不做 UDP→TCP 截断兜底**（本次决定只写文档建议，见 §3.5）。
- 不扩展 `CacheRecord` 以缓存 RRSIG/NSEC/SOA（本次决定绕过缓存，见 §3.3）。
- 不改上游连接模型、不改协议（UDP/TCP/DoT/DoH/DoH3/DoQ）实现。
- 不新增依赖。
- 不处理 `block` / `rewrite` / `cname` / `hosts` 的 DNSSEC 语义（这些动作的应答
  由 rsdns 本地合成：没有 RRSIG，AD 不置位，天然是"未验证"；`cname` 动作还会
  做二次解析与 owner 改写，本身就不是 DNSSEC 应答）。DNSSEC 客户端拿到这类
  应答时会看到"无签名"，这是正确的诚实行为，不需要额外代码。

## 3. 方案

### 3.1 DNSSEC 查询的判定

新增一个纯函数（放 `src/plugins/util.rs`，与 `make_response_base` 等同层）：

```rust
/// 查询是否请求 DNSSEC 数据（EDNS DO=1）或要求跳过验证（CD=1）。
/// 两者任一为真即视为"DNSSEC 查询"：应答里可能带 RRSIG/NSEC，
/// 缓存与应答改写都必须避让。
pub(crate) fn is_dnssec_query(msg: &Message) -> bool {
    msg.metadata.checking_disabled || msg.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
}
```

- `Edns::flags().dnssec_ok` 与 `Metadata::checking_disabled` 都是 hickory 公开
  字段/方法，无需额外解析。
- 该函数在 `server.rs::handle_query` 构造完 `QueryContext` 后调用一次，结果写入
  `ctx` 的新字段（见 §3.2），避免各阶段重复判断。

### 3.2 `QueryContext` 新增字段（`src/query.rs`）

```rust
/// 请求带 DO=1 或 CD=1（DNSSEC 查询）：缓存与应答改写必须避让。
/// 由 server 在构造后立即置位；各阶段只读。
pub dnssec: bool,
```

- `QueryContext::new` 里初始化为 `false`，由 `handle_query` 在
  `QueryContext::new(...)` 之后立刻 `ctx.dnssec = is_dnssec_query(&ctx.msg);`
  ——保持 `new` 的签名不变（现有 5 处测试调用 `QueryContext::new` 全部无需改）。
- `hosts` 别名路径会 `rewrite_name`，但 `dnssec` 与名字无关，不受影响。

### 3.3 缓存避让（`src/plugins/cache.rs`）

`Cache::lookup` 与 `Cache::write_back` 各加一条前置判断：

```rust
if ctx.skip_cache || ctx.dnssec {
    return Step::Continue;   // lookup
}
```

```rust
if ctx.skip_cache || ctx.dnssec {
    return;                  // write_back
}
```

语义与现有 `skip_cache` 完全一致（既不查也不写），**不新增第三种缓存开关**，
直接用 `ctx.dnssec` 复用既有分支结构。`skip_balance` 由 `lookup` 命中时设置，
DNSSEC 查询不再命中缓存，因此 `skip_balance` 不会因 DNSSEC 被动置位。

CLOUDFLARE ECH 的私有模板缓存（`Rules::ech_cache`）不受影响 —— 它只缓存
HTTPS 模板，与客户端 DNSSEC 无关。

### 3.4 应答改写避让（`src/plugins/rules.rs` + `src/plugins/balance.rs`）

`forward_query` 当前顺序为：`upstream → resolve_cnames → cf_ech → ttl 覆盖`
（`rules.rs:820-845`）。DNSSEC 查询下把中间两步跳过：

```rust
let mut resp = self.upstreams.query(upstream, &msg).await?;
if opts.resolve_cname && !ctx.dnssec {
    self.resolve_cnames(ctx, upstream, &mut resp, opts.subnet).await;
}
if let Some(cf) = opts.cf_ech {
    if !ctx.dnssec && resp.answers.iter().any(record_uses_cf) { /* … */ }
}
if let Some(ttl) = opts.ttl {
    rewrite_ttl_in_response(&mut resp, ttl);
}
```

- `resolve_cnames` 会删除 CNAME 链、改写 A/AAAA 的 owner（
  `collapse_completed_chain`，`rules.rs:1079`）或用二次查询结果整体替换
  answer（`rules.rs:942`）；这些都会让 RRSIG 与 RRset 不再对应。DNSSEC 查询下
  原样返回上游应答，由客户端/上游负责验证。
- `cloudflare_ech` 同理：它替换 HTTPS 记录 RDATA（`rules.rs:836`），在有 RRSIG
  覆盖 HTTPS RRset 时必然验签失败。

`balance.rs::handle` 在既有 `ctx.skip_balance` 判断处并列判断：

```rust
if !self.enabled || ctx.skip_balance || ctx.dnssec {
    return Step::Continue;
}
```

理由：`prefers`/`mode` 只重排 A/AAAA 记录（同一 RRset 内重排不破坏 RRSIG 覆盖，
DNS 语义允许），但 `max_answers` 会**截断整个 answer 列表**（`balance.rs:239`），
可能把 RRSIG 与它覆盖的记录拆开，或剪掉 NSEC。整个阶段一并跳过是最小且最安全
的选择；DNSSEC 查询本就不是高 QPS 路径。

**`forward.ttl` 覆盖保留，不改**：`rewrite_ttl_in_response` 改的是记录 TTL，
而 DNSSEC 校验用 RRSIG 的 `Original TTL` 字段重建签名数据（hickory `tbs.rs:119`
明确写入 `input.original_ttl`），与记录当前 TTL 无关。因此 TTL 覆盖**不破坏**
签名验证。保留它是为了不扩大行为变化面（`ttl` 是用户显式配置）。

### 3.5 UDP 上游截断：本次不修，文档给出建议（已确认）

DNSSEC 应答（A + RRSIG + NSEC 等）体积明显大于普通应答，UDP 上游极易返回
`TC=1`。当前 rsdns：

- `src/server.rs:38` `MAX_DNS_SIZE = 4096`，客户端 UDP 报文本身没有截断处理；
- 上游 UDP 接收缓冲固定 4096（hickory `udp_client_stream.rs:140`
  `MAX_RECEIVE_BUFFER_SIZE.min(request.max_payload())`）；hickory 的
  `DnsExchange` 不因 `TC=1` 自动改走 TCP。

即：**UDP 上游 + DNSSEC 场景下 rsdns 会把截断应答当完整应答返回**。本次按确认
结论**不做兜底**，改为在文档/示例中明确建议：

> DNSSEC 场景的上游请使用 `tcp://` / `tls://` / `https://` / `h3://` / `quic://`，
> 避免 `TC=1` 造成的数据不完整。

附带说明（避免误读）：即使上游是加密传输，若**客户端到 rsdns**这一段是 UDP，
rsdns 也不做 TC 置位/截断处理（`MAX_DNS_SIZE=4096` 下超长应答会原样发 UDP）。
这属于既有行为，不在本提案范围。

### 3.6 可观测性（可选，低成本）

- 日志：`ctx.action` 已是 `forward({upstream})`；建议在 `logs` 的 action 标签
  上追加后缀（如 `forward(default)/dnssec`）会改变日志格式兼容性，**故不改**。
- 指标：`src/metrics.rs` 的 `MetricsRegistry::counter` 对重名断言唯一
  （`assert_unique`），新增需在 `handle_query` 或 `cache` 注册。建议在
  `cache` 阶段旁新增一个计数器 `rsdns_cache_dnssec_bypass_total`（无标签），
  在 §3.3 的 `ctx.dnssec` 分支自增；或在 `logs` 阶段挂
  `rsdns_logs_queries_total{proto=...}` 之外新增
  `rsdns_queries_dnssec_total`。
- 决策：**仅在 `cache` 阶段加 `rsdns_cache_dnssec_bypass_total`**（一处，
  无标签，纯计数，便于确认"DNSSEC 流量真的绕过了缓存"）。其余不动，避免
  扩大改动面。

## 4. 改动清单

| 文件 | 改动 |
|------|------|
| `src/query.rs` | `QueryContext` 新增 `pub dnssec: bool`（`new` 中初始化 `false`） |
| `src/plugins/util.rs` | 新增 `pub(crate) fn is_dnssec_query(msg: &Message) -> bool` |
| `src/server.rs` | `handle_query` 中 `QueryContext::new` 后置位 `ctx.dnssec` |
| `src/plugins/cache.rs` | `lookup` / `write_back` 增加 `ctx.dnssec` 短路；新增 `rsdns_cache_dnssec_bypass_total` 计数器 |
| `src/plugins/rules.rs` | `forward_query`：`resolve_cnames` / `cf_ech` 在 `ctx.dnssec` 时跳过 |
| `src/plugins/balance.rs` | `handle` 的早退条件增加 `ctx.dnssec` |
| `example/rsdns-all-example.yaml` | 注释补充：DNSSEC 建议用 TCP/加密上游；`ttl` / `resolve_cname` / `cloudflare_ech` / `max_answers` 在 DNSSEC 查询下不生效 |
| `README.md` / `README.en.md` | 新增"DNSSEC"小节：透传语义、缓存绕过、上游建议、非验证者定位 |
| `Cargo.toml` | 无改动（不启用 hickory `__dnssec`，不加依赖） |

## 5. 测试

均为单元测试，全部离线，不新增 e2e（e2e 需公网，见 `tests/e2e/README.md`）。

- **`util`（纯函数）** `is_dnssec_query`：
  - 无 EDNS、无 CD → `false`；
  - `Edns::default()`（DO=0）→ `false`；
  - DO=1 → `true`；CD=1（无 EDNS）→ `true`；DO=1 且 CD=1 → `true`。
- **`cache`**：
  - 预置一条 A 缓存；以 DO=1 查询同一 key → `lookup` 返回 `Continue`（不命中）；
  - DO=1 查询经 `write_back` 后不留缓存条目（后续普通查询仍 miss）；
  - 普通查询行为不变（回归）。
- **`rules`**：`forward_query` 层面用 DO=1 的 `QueryContext` 验证
  `resolve_cnames` / `cf_ech` 被跳过 —— 采用现有测试风格：构造带 CNAME 首条
  answer 的应答，断言 DNSSEC 查询下 `resp.answers` 未被折叠/替换（非 DNSSEC
  下会被替换），两次对照。
- **`balance`**：复用现有 `test_ctx` / `run_balance` 辅助（`balance.rs:410/426`）：
  - 4 条 A + `max_answers: 2`，`ctx.dnssec = true` → 仍为 4 条；
  - 同一输入 `ctx.dnssec = false` → 2 条（对照，证明避让生效）。
- **往返回归（纯函数级）**：构造含 `RData::Unknown { code: RRSIG/NSEC, .. }` 的
  `Message`，`to_vec` → `from_vec` → 断言类型与 RDATA 字节完全一致（把 §1.2 的
  实验固化成测试，hickory 升级时能第一时间发现透传被破坏）。
- `make ci` 全绿。

## 6. 兼容性

- 未带 DO/CD 的查询：所有路径行为与现状完全一致（新增判断全在 `ctx.dnssec`
  为 `true` 时才生效）。
- `ctx.dnssec` 为 `true` 时：DNSSEC 查询不写缓存 → 缓存容量/命中率指标不受
  污染；上游压力略增（这是正确性的代价，且 DNSSEC 查询占比通常很低）。
- 配置项无新增、无删除；`forward.ttl` 语义不变。
- 文档关于"rsdns 不是验证者"的定位会写清楚，避免使用者误以为 AD=1 来自 rsdns。

## 7. 风险与权衡

### 7.1 为什么本次不做本地验证

本地验证需要：内置/更新根信任锚（DS/DNSKEY 轮转、RFC 5011）、完整
DNSKEY/DS 链验证、NSEC/NSEC3 否定证明、时钟与签名有效期处理、bogus→SERVFAIL
策略、以及为验证而获取 DNSKEY/DS 的额外上游查询与缓存。这是一套独立子系统，
而不是"顺手补上"。hickory 提供 `hickory-net/src/dnssec/`（`DnssecDnsHandle`）
与 `hickory-proto/src/dnssec/`（`Verifier` / `TrustAnchors`），但它需要一个
`DnsHandle` 包装层与信任锚配置，且当前 rsdns 的连接池模型是"按池 checkout 的
`Exchange`"，与 `DnssecDnsHandle` 的句柄包装方式需要专门适配。因此作为**后续
阶段**单独立项（见 §8）。

### 7.2 透传语义下 AD 位的诚实性

rsdns 原样转发上游 AD 位。若上游不验证却置 AD，rsdns 无法察觉 —— 这是所有
透传型转发器的固有性质，文档必须写明。客户端（stub resolver）应在自己需要的
安全边界上决定是否信任路径上的转发器。

### 7.3 绕过缓存带来的上游压力

DNSSEC 查询全部回源。缓解：`forward.ttl` 仍可钳制应答 TTL（客户端侧缓存），
配置侧建议对 DNSSEC 规则单独指定上游池。若后续压力成为问题，再回到 §8 的
"缓存 RRSIG/NSEC/SOA"路线。

### 7.4 `skip_cache` 与 `dnssec` 的交互

两者效果一致但语义不同（前者是配置，后者是请求属性）。本提案**不合并**它们：
`skip_cache` 仍由 `groups` 阶段设置，`dnssec` 由 server 设置，二者是并列的
OR 条件。合并会让"某组跳过缓存"与"某查询是 DNSSEC"在日志/排障时不可区分。

## 8. 后续阶段（本次不做，供排期参考）

1. **UDP→TCP 截断兜底**：上游为 UDP 且应答 `TC=1` 时用同一 server 的 TCP
   地址重查（`ConnectionPool` 增加按地址族的 TCP 兜底工厂，或 `forward` 层
   失败重试）。§3.5 是当前的临时建议。
2. **DNSSEC 感知缓存**：`CacheRecord` 增加 `Rrsig`/`Nsec`/`Soa` 变体，或改为
   缓存原始 `Message`；TTL 与 RRset 完整性需要一并设计。
3. **本地验证**：接入 hickory `DnssecDnsHandle` + `TrustAnchors`（含根锚配置与
   更新），`dnssec: validate` 配置开关，bogus → SERVFAIL 且不置 AD。
4. **客户端侧 TC 处理**：超长应答按客户端 `max_payload` 截断并置 `TC=1`。

## 9. 附录：相关代码锚点

| 位置 | 说明 |
|------|------|
| `src/server.rs:38` | `MAX_DNS_SIZE = 4096`（UDP/TCP 入站上限） |
| `src/server.rs:438-501` | `handle_query`：流水线与 `msg_id` 复原 |
| `src/query.rs:40-68` | `QueryContext` 字段（`skip_cache` / `skip_balance`） |
| `src/plugins/util.rs:57` | `make_response_base`（`response_from_request` 复制 RD/CD，AD 不复制） |
| `src/plugins/util.rs:75` | `extract_cache_records`（仅 A/AAAA/CNAME/MX/TXT/HTTPS） |
| `src/plugins/util.rs:139` | `build_response_from_cache`（缓存命中应答构造） |
| `src/plugins/cache.rs:51` | `CacheRecord` 枚举 |
| `src/plugins/cache.rs:262` / `:294` | `Cache::lookup` / `Cache::write_back` |
| `src/plugins/rules.rs:820-845` | `forward_query`（upstream → resolve_cname → cf_ech → ttl） |
| `src/plugins/rules.rs:891` / `:1062` / `:1079` | `resolve_cnames` / `address_records_with_owner` / `collapse_completed_chain` |
| `src/plugins/rules.rs:836` | `cf_ech_replacement_https` 调用点 |
| `src/plugins/balance.rs:216-241` | `Balance::handle`（早退 + `max_answers` 截断） |
| `src/upstream/mod.rs:125` | `DnsRequest::new(msg.clone(), DnsRequestOptions::default())`（出站出请求） |
| `hickory-proto` `rr/record_data.rs:1010-1017` | 未开 `__dnssec` 时 `r if r.is_dnssec()` 分支被 cfg 排除，DNSSEC 类型落到 `RData::Unknown` raw-bytes 分支 → 字节级透传 |
| `hickory-proto` `rr/record_type.rs:172` | `RecordType::is_dnssec()`（RRSIG/NSEC/NSEC3/DNSKEY/DS/… 列表） |
| `hickory-proto` `rr/record_data.rs:1182-1186` | RFC 3597：新 RR 类型的 RDATA 内域名不得压缩（raw-bytes 透传安全性的协议依据；`:750` 是 TSIG 的具体引用） |
| `hickory-proto` `dnssec/tbs.rs:119` | 校验用 RRSIG `Original TTL`，与记录 TTL 无关（§3.4 依据） |
| `hickory-net` `udp/udp_client_stream.rs:140` | UDP 接收缓冲 `4096.min(max_payload())`（§3.5 依据） |
| `hickory-net` `src/dnssec/` | `DnssecDnsHandle`（§8.3 后续验证路线） |
