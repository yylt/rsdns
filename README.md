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
- **查询管道**：`hosts → groups → cache → rules`，未命中规则返回 NXDOMAIN/SERVFAIL
- **规则**：`block`（NXDomain / 毒化 IP）、`cname`（重写 + 递归解析）、`forward`（转发到上游池，可选 TTL 覆盖 / resolve_cname）、`rewrite`（合成 A 记录）
- **缓存**：LRU，可配置容量、TTL 范围；moka 按条目 TTL 自动过期（无 stale 服务）
- **连接池**：自适应地址轮换、故障冷却、地址族偏好
- **文件源**：`groups` / `hosts` 支持 `file://` 源，`notify` 监听文件变化自动重载
- **systemd notify**：监听器全部绑定后发送 `READY=1`（`Type=notify`）
- **metrics**：可选 Prometheus `/metrics` HTTP 端点

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

完整示例配置：`example/rsdns-all-example.yaml`；systemd 部署示例：`example/rsdns.service`。

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
