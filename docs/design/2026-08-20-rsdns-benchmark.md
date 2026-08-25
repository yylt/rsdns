# rsdns PR 性能基准流水线提案

> 2026-08-20 | 提案

## 1. 动机

rsdns 支持多种上游协议：UDP、TCP、DoT（DNS over TLS）、DoH（DNS over HTTPS）、DoH3（DNS over HTTP/3）、DoQ（DNS over QUIC）。不同协议的并发查询性能差异很大（连接建立、TLS 握手、HTTP/2 多路复用、QUIC 流复用等），任何涉及上游连接、连接池、转发链路的改动都可能改变这些数字。

当前 PR 流程只跑 `ci.yaml`（fmt/clippy/check/test）和 `e2e.yaml`（功能性正确性验证），没有任何性能回归防护：一个改动可能让 QPS 掉 30% 而功能测试仍然全绿。

本提案在 `.github/workflows/` 下新增 **benchmark 流水线**，在 PR 中对 rsdns 做并发性能测试，输出 **UDP / DoT / DoH / DoH3** 四种上游格式的对比数据，作为 PR 性能评审依据。

## 2. 目标与范围

### 2.1 目标

- PR 触发时自动运行 rsdns 性能基准（手动触发亦可）。
- 对同一 rsdns 二进制、同一组负载参数，分别测 **UDP / DoT / DoH / DoH3** 四种上游。
- 产出可比较的指标：**QPS、平均/最小/最大/百分位延迟（p50/p95/p99）、错误率、并发数**。
- 结果以 Markdown 摘要（PR 评论）和 JSON 原始数据（Artifact）两条途径交付。

### 2.2 范围

- 仅测 rsdns 的 **入站→上游** 全链路并发性能，即“客户端并发查询 rsdns，rsdns 实时转发到被测上游”。
- 只做**短时、粗粒度、可重复**的相对性能对比，不做精确微基准。
- 首版**不包含** DoQ/TCP 上游对比（DoQ 在 PR 测试机上的 QUIC 依赖稳定性欠佳），后续可扩展。
- 涉及 `rsdns` 源文件（`src/**`）或依赖变更的 PR 自动触发。

### 2.3 明确不做（本期）

- 不做 CI 门禁（不设置必须通过的阈值），只做报告；阈值留作后续人工评审后决策。
- 不做“基线 vs PR 分支”的跨 commit 对比（同一 runner 上顺序执行，受宿主噪声影响，仅作为参考）。
- 不引入新的 Rust/Go 测试代码，基准全部由现成 CLI 工具驱动。

## 3. 性能测试方法

### 3.1 基准工具选型

**负载生成：dnspyre**（[Tantalor93/dnspyre](https://github.com/Tantalor93/dnspyre)，v3.12.0）。

- 按 `--duration` 时长 + `--concurrency` 并发持续发压，天然模拟并发场景；
- 直接支持 **UDP/TCP、DoT（`--dot`）、DoH（`https://` 且 `--doh-protocol` 可选手动/2/3）、DoQ** 四种入站方式，一套命令即可覆盖四种协议；
- 单二进制、无运行期依赖（Go 静态编译），直接从 GitHub Releases 下载，避免在 CI 里编译工具；
- 自带直方图与 **JSON 输出**（`--json`），便于解析成摘要与 artifact；
- 支持 `--insecure`，可压测自签名的本地 DoT/DoH/DoH3 测试服务器（本流水线不依赖，公共上游场景使用真实证书）。

**DNS 服务器：rsdns 自身**（`cargo build --release --bin rsdns`），被测对象。

### 3.2 为什么是“rsdns 作为被测上游格式的转发者”

这里要区分两种测试视角：

1. **入站视角**：客户端（dnspyre）以 UDP/DoT/DoH/DoH3 访问 rsdns 的监听端口 —— 测的是 rsdns 的**入站**能力；
2. **上游视角**：客户端以 UDP 访问 rsdns，rsdns 的**上游**分别配置成 UDP/DoT/DoH/DoH3 —— 测的是 rsdns **转发到各上游协议**的能力。

用户要求的“四种格式的并发性能对比”指上游协议格式（即视角 2）。因此：

- 客户端统一用 **UDP 并发**访问 rsdns（`dnspyre --server 127.0.0.1:<port> --duration <D> --concurrency <C>`）；
- rsdns 的 `upstream` 依次配置为 `223.5.5.5`（UDP）、`tls://dns.pub`（DoT）、`https://doh.pub/dns-query`（DoH）、`h3://cloudflare-dns.com/dns-query`（DoH3，doh.pub 实测不支持 HTTP/3）；
- 四种配置**逐一**起一个 rsdns 实例、跑一轮基准、记录结果，然后进入下一种。

> 注：rsdns 监听地址支持 `udp://` 前缀（`main.rs::scheme`）。为避免与默认无前缀 UDP 混淆，流水线统一使用 `0.0.0.0:<port>` 形式。

### 3.3 为什么“去除 cache”

rsdns 的查询管线为 `hosts → cache → rules → upstream`（`server.rs::do_query`），命中缓存会直接返回、根本不触达上游。性能测试目标是**上游协议的转发能力**，不是缓存命中率，因此：

- 配置中显式写 `cache.size: 0`：moka 容量为 0 时 map 整体禁用，`get_cached` 恒 `Miss`、`put` 为空操作，从根上关闭缓存（`cache.rs::DnsCache::new`、moka `BaseCache::is_map_disabled`）；
- 被测规则再叠加 `cache: false`（`rule.rs` 中 forward 动作的 `cache` 字段），`handle_forward` 直接走 `forward_to_upstream`，不查缓存也不写缓存——双保险；
- 每个查询的域名做随机轮换（见 3.4），避免 DNS 响应的 TTL 语义或任何巧合命中干扰。

### 3.4 负载与域名设计

- 使用公开的真实域名列表作为查询集（随机轮换）：`https://raw.githubusercontent.com/Tantalor93/dnspyre/master/data/1000-domains`，覆盖多种 TLD/长度，避免单一域名带来的缓存/上游热路径偏差；
- 全部查询 qtype 固定为 `A`，统一负载特征；
- 并发 `--concurrency` 与时长 `--duration` 通过 workflow `inputs` 暴露，默认 `64` 并发、`30s`/协议，另加 5s warm-up；
- 开启 `--json` 与 `--csv`（直方图 CSV）供分析。

### 3.5 数据收集指标

| 指标 | 来源 |
|------|------|
| QPS | dnspyre JSON `qps` |
| 平均/最小/最大延迟 | dnspyre JSON `latency` 段 |
| p50 / p95 / p99 | dnspyre JSON `latency` 百分位 |
| 错误/超时计数 | dnspyre JSON `errors` / `ioTimeouts` |
| 并发数、时长、域名数 | 运行参数快照 |
| rsdns commit / binary 版本 | `rsdns --version` 输出 |
| 协议池配置（max_size 等） | 各协议对应 rsdns 配置片段 |

## 4. 流水线设计

### 4.1 文件与触发

- 文件：`.github/workflows/benchmark.yaml`
- 触发：
  - `pull_request`：`paths` 命中 `src/**`、`Cargo.toml`、`Cargo.lock`、`.github/workflows/benchmark.yaml`；
  - `workflow_dispatch`：手动运行（`inputs`：并发数、时长、上游格式过滤）。
- 并发控制：`concurrency` 按 PR 取消旧运行。

### 4.2 Job 结构

```text
benchmark (ubuntu-latest)
├─ 1. Checkout + Rust toolchain（不带 cache action）
├─ 2. Install dnspyre（下载 v3.12.0 linux_amd64 二进制）
├─ 3. Build rsdns（cargo build --release --bin rsdns，无 Swatinem cache）
└─ 4. 调用 tests/benchmark/run_rsdns_benchmark.sh
│     逐协议（UDP/DoT/DoH/DoH3）：写 rsdns.yaml → 起 rsdns → 就绪探测
│     → dnspyre 压测 → 收集 JSON/CSV → 汇总
└─ 5. 结果：PR 评论 + Job 摘要 + Artifact(JSON/CSV)
```

单 job 顺序执行四种协议，避免并发争抢共享上游带宽与宿主 CPU，保证四种协议在同一机器、同一时刻附近测得，可比性更好。

### 4.3 rsdns 被测配置（模板）

```yaml
bind:
  - address: "0.0.0.0:<PORT>"          # UDP 入站
upstream:
  bootstrap:
    servers:
      - address: 223.5.5.5
        bootstrap: true
  default:
    servers:
      - address: <UPSTREAM>            # 依次: 223.5.5.5 / tls://dns.pub / https://doh.pub/dns-query / h3://cloudflare-dns.com/dns-query
cache:
  size: 0                              # moka 容量 0 = 完全禁用缓存
rules:
  - match: "*"
    action:
      type: forward
      upstream: default
      cache: false                     # 叠加：forward 不查不写缓存
```

> `cache.size: 0`（moka 容量为 0 时 map 整体禁用，`get` 恒 miss、`put` 空操作）从根上关闭缓存；规则再叠加 `cache: false` 双保险。`hosts` 为空。bootstrap 仅用于解析 `tls://dns.pub`、`https://doh.pub/dns-query` 等域名型上游（IP 型上游无影响）。

### 4.4 单协议基准步骤（脚本内实现）

全部逻辑封装在 `tests/benchmark/run_rsdns_benchmark.sh`，供 Workflow 与本地复用：

```bash
./tests/benchmark/run_rsdns_benchmark.sh \
  --rsdns ./target/release/rsdns \
  --dnspyre <path-to-dnspyre> \
  [--domains <domain-list-file>] [--duration 30s] [--concurrency 64] \
  [--protocols udp,dot,doh,doh3] [--port 15353] [--outdir benchmark-results]
```

每协议执行：

1. 写 `rsdns-<proto>.yaml`（见 4.3 模板，`<UPSTREAM>` 按协议映射）
2. 后台起 rsdns，记录 PID
3. 就绪探测：`dnspyre --number 1 --concurrency 1` 查询 `example.com`，最多 30s
4. 正式压测：`dnspyre --duration <D> --concurrency <C> --type A --json --csv ... @<域名列表>`
5. 结束 rsdns，解析 JSON，追加 Markdown 行
6. 任一协议失败不阻断其余，失败行标记 ❌

### 4.5 输出与评审交互

- **PR 评论**：使用 `actions/github-script@v7` 把汇总表格发布为 PR 评论（每次运行更新同一条评论，避免刷屏；先删除旧的同标签评论再新建）。
- **Job 摘要**：同时把 Markdown 写到 `$GITHUB_STEP_SUMMARY`，方便在 Actions 页面直接看。
- **Artifact**：上传 `benchmark-results/`（每个协议的 JSON、CSV + 汇总 JSON），保留 7 天。
- 所有数值保留 2 位小数，延迟单位为 ms。

### 4.6 健壮性与失败处理

- 单协议失败不阻断其余协议：脚本用 `set +e` 逐协议收集，最后汇总里标记 `failed`；
- rsdns 启动做就绪探测（本地 dig/nc 或 dnspyre 预查询），超时判失败；
- 上游使用公共 DNS（223.5.5.5 / dns.pub / doh.pub），若公网不可达，失败会在汇总中体现而非挂死；
- 整体 `timeout-minutes` 设 30，防失控。

## 5. 扩展性与后续

- 可加 `TCP`、`DoQ` 上游对比（dnspyre 的 `quic://` 客户端已支持 DoQ，只是 PR runner 稳定性待验证）；
- 可加“基线对比”：同一 job 内先跑 main 分支再跑 PR，输出相对变化率（当前版本用 GitHub 上的合并结果做人工对比）；
- 若后续要设门禁，可在汇总脚本里加阈值（如 p99 相对基线劣化 > X% 则 fail）；
- 可把域名列表/负载参数抽到仓库内 `benchmark/` 目录便于复用。

## 6. 风险与限制

- **宿主噪声**：GitHub-hosted runner 是共享虚拟机，QPS/p99 存在抖动；因此本流水线定位为“相对对比 + 回归预警”，绝对值不做断言；
- **公网上游依赖**：结果受 dns.pub/doh.pub/223.5.5.5 当日网络质量影响；若需稳定基线，后续可改为本地自建权威/递归服务器；
- **DoH3 依赖 QUIC 出网**：若 runner 网络环境禁止 UDP 443，DoH3 会失败或偏低，汇总中会标注；
- **单 job 顺序执行**：四种协议各 30s+预热 ≈ 2.5 分钟净压测时间，可接受；并发执行的收益（减少时长）不抵资源争抢对可比性的损害。

## 7. 交付清单

| # | 文件 | 说明 |
|---|------|------|
| 1 | `docs/design/2026-08-20-rsdns-benchmark.md` | 本提案 |
| 2 | `tests/benchmark/run_rsdns_benchmark.sh` | 基准执行脚本（逐协议压测 + 汇总，可本地复用） |
| 3 | `.github/workflows/benchmark.yaml` | PR/手动触发的 rsdns 性能基准流水线（调用脚本，UDP/DoT/DoH/DoH3） |
