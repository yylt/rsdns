# rsdns

默认语言：中文 | [English](./README.en.md)

一个使用 Rust 实现的规则驱动独立 DNS 服务器，提供可组合的监听、上游、规则、缓存与查询日志能力

## 特性

- **监听（入站）**
  - UDP（`ip:port`）
  - TCP（`tcp://ip:port`）
  - DoT（`tls://ip:port`，DNS-over-TLS）
  - DoH（`https://ip:port`，DNS-over-HTTPS，HTTP/1.1 + HTTP/2）
  - DoH3（`h3://ip:port`，DNS-over-HTTP/3）
  - 加密监听共用顶层 `tls_cert` / `tls_key`（PEM），缺省时自动生成自签证书
- **上游（出站）**
  - UDP / TCP（原生 DNS）
  - DoT（`tls://`）
  - DoH（`https://`）
  - DoH3（`h3://`）
  - DoQ（`quic://`）
- **查询管道**：`hosts → groups → cache → rules → cloudflare → balance`，未命中规则返回 NXDOMAIN/SERVFAIL
- **规则**：`block`（NXDomain / 毒化 IP）、`cname`（重写 + 递归解析）、`forward`（转发到上游池，可选 TTL 覆盖 / resolve_cname）、`rewrite`（合成 A 记录）
- **balance（后置应答）**：`prefers` CIDR 优先级、`mode`（`round_robin` / `speed`）、`max_answers` 截断；仅 group 的 `skip_balance` 可跳过，缓存命中仍执行
- **cloudflare（独立后置应答）**：顶级 `cloudflare` 对 CF 网段内的 HTTPS/A/AAAA 应答做模板替代（`ech` / `a` / `aaaa`，各字段格式为 `domain@upstream`）；不受 group 跳过标志或 balance 开关影响，保留 DNSSEC 保护与失败回退
- **缓存**：LRU，可配置容量、TTL 范围；moka 按条目 TTL 自动过期（无 stale 服务）；仅 group 的 `skip_cache` 控制普通缓存读写
- **连接池**：共享连接、地址轮换与逐 IP 指数退避、地址族偏好
- **文件源**：`groups` / `hosts` 支持 `file://` 源，`notify` 监听文件变化自动重载
- **systemd notify**：监听器全部绑定后发送 `READY=1`（`Type=notify`）；`systemctl reload`（SIGHUP）重开查询日志，配合外部 logrotate 轮转压缩（不重载配置）
- **ui**：可选内置 Web 状态页 + Prometheus `/metrics`（`ui:` 配置段；`/` 为手机友好的 HTML 仪表盘，`/metrics` 为 Prometheus 文本）

## 构建

```bash
make build   # debug build rsdns binary（release 由 CI/release 流程负责）
# 或
cargo build --bin rsdns
```

## 运行

默认配置文件名为 `rsdns.yaml`（YAML；JSON 亦支持）：

```bash
cargo run --bin rsdns -- -c rsdns.yaml
# 或
./target/debug/rsdns --config rsdns.yaml
```

完整示例配置：`example/rsdns-all-example.yaml`；systemd 部署示例：`example/rsdns.service`；
logrotate 示例：`example/rsdns.logrotate`。

## 最小配置示例

```yaml
binds:
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"
  # - address: "tls://0.0.0.0:853"      # DoT（自动自签证书）
  # - address: "https://0.0.0.0:8443"   # DoH（HTTP/1.1 + HTTP/2）
  # - address: "h3://0.0.0.0:8443"      # DoH3（HTTP/3）

# 加密监听的证书/私钥（PEM）；两者都省略时自动生成自签证书
# tls_cert: /etc/rsdns/server.crt
# tls_key: /etc/rsdns/server.key

upstreams:
  - name: default
    servers:
      - address: 223.5.5.5
      - address: tls://dns.alidns.com

rules:
  - match: ""
    action: { type: forward, upstream: default }
```

规则 `qtype` 支持 `qtype: "A, AAAA, HTTPS"`（任一匹配），只接受大写类型名，各项允许首尾空白；不接受数字、小写或空项。省略或 `ANY` 匹配全部查询类型。旧 `balance.cloudflare` 请迁至顶级，删除 `cache.skip_balance` 和 `pool.dns_timeout` 配置。

## 加密 DNS 的连接与超时

- 每个上游复用一个多路复用连接，最多 32 个在途请求；建连串行合并，连接空闲超过 `pool.idle_timeout`（默认 30 秒）后在下次使用时替换。
- 上游组可设置 `query_timeout: 5`（正整数秒，默认 5）：包含排队、建连、请求及所有 fallback 的总预算。这会限制旧版本串行 fallback 可累计的等待时间。
- 上游组 `attempt_timeout: 2`（正整数秒，默认 2）限制每个 server 的排队、建连锁等待、建连与 DNS 请求；取其与整组剩余预算的较小值。单 server 也适用，超时后有序模式回退到下一 server，parallel 仍首个成功返回。
- 已删除 group 的 `cooldown` 配置。每个 IP 建连失败或故障连接被淘汰后按 `2 → 4 → 8 → 16 → 32` 秒退避，32 秒封顶；仅 DNS 查询成功重置，退避到期和建连成功不重置。所有地址退避时立即返回不可用，不强制探测；排队超时和主动取消不惩罚 IP。
- 每服务器 `pool.connect_timeout` 和内部固定默认 5 秒的 DNS 超时仍是阶段上限（不再支持 `pool.dns_timeout` 配置）；bootstrap 客户端也使用该 DNS 超时限制包含建连的总耗时。Hickory 内部 DoT/DoH TLS 握手另有 5 秒上限，增大外层配置不能放宽它。
- 连接关闭立即淘汰对应连接；同一连接连续三次请求超时后替换，成功或其他请求结果复位计数。取消查询不计为成功或故障。
- DoT 入站支持单连接连续查询（串行处理）；DoH3 各请求独立、有界并发。入站 DNS 请求体最多 65535 字节，超限 HTTP 返回 413。
- 加密入站限制全局 1024 个连接、1024 个在途请求、每连接 32 个请求；握手、消息读取和响应写入预算为 5 秒，DoT 查询间空闲 30 秒后关闭。HTTP 过载返回 503，DoT 关闭连接。
- H3 单次握手失败不终止监听器；依赖的 H3 accept 仍串行等待握手（最长约 5 秒），本轮未替换依赖。H3 请求头解析包含在不可安全取消的 accept 中，尚无单独读取超时；HTTP/2 也未增加每流请求头计时器。HTTP/1 请求头和 body 分别限制 5 秒，不共享一个预算。

## 开发

```bash
make ci   # fmt + clippy + check + test
```

常见 feature：

- `aws-lc-rs`（默认）
- `ring`
- `jemalloc`（默认）
- `mimalloc`

## 文档

- 架构与设计文档：[`docs/design/`](./docs/design/)
- E2E 测试说明：[`tests/e2e/README.md`](./tests/e2e/README.md)
- 基准测试脚本：[`tests/benchmark/run_rsdns_benchmark.sh`](./tests/benchmark/run_rsdns_benchmark.sh)

## 说明

本文档基于当前 `src/` 实现整理；若实现变化，请以源码为准。
