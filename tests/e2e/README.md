# rsdns E2E Tests

端到端（End-to-End）测试，验证 `rsdns` 二进制在真实网络环境中的完整链路行为。

## 技术方案

测试框架使用 **Go** 编写（`main.go`），通过 `os/exec` 启动 rsdns 子进程，构造请求并校验响应。

- 启动 rsdns 进程，使用原始 UDP DNS wire-format 查询，验证转发、拦截、缓存、hosts 等核心功能。

## 目录结构

```
tests/e2e/
├── README.md                  # 本文件
├── main.go                    # 入口 + 公共工具函数（进程管理、结果汇总）
├── go.mod                     # Go module 定义
├── run_rsdns_tests.sh         # rsdns 测试启动脚本
└── test_rsdns.go              # rsdns 全功能测试（转发/拦截/缓存/hosts/DoT/DoH/DoH3）
```

## 前置条件

| 依赖 | 用途 |
|------|------|
| **Go** ≥ 1.21 | 编译和运行测试 |
| **Cargo** | 确保 Rust 工具链可用（实际二进制需预先构建） |
| `target/debug/rsdns` 或 `target/release/rsdns` | rsdns 测试所需二进制 |
| **网络** | 需要能访问公网（223.5.5.5 等） |

## 运行方式

```bash
# 先构建二进制
cargo build --bin rsdns

# 运行全部 E2E 测试
./tests/e2e/run_rsdns_tests.sh
```

## 测试套件详解

rsdns 测试使用**原始 UDP DNS wire-format query**，不依赖系统 DNS 解析器，直接向 `127.0.0.1:<port>` 发送 DNS 请求。

### 端口分配

| 测试 | 端口 | 说明 |
|------|------|------|
| Forward | 15353 | DNS 转发 + 广告域名 poison 拦截 |
| Hosts | 15354 | hosts 静态记录生效验证 |
| Reject | 15359 | NXDOMAIN 拦截验证 |
| DoT | 15356 | DNS over TLS 上游（需 `RSDNS_UPSTREAM_DOT`） |
| DoH | 15357 | DNS over HTTPS 上游（需 `RSDNS_UPSTREAM_DOH`） |
| DoH3 | 15358 | DNS over HTTP/3 上游（需 `RSDNS_UPSTREAM_DOH3`） |
| TCP | 15360 | TCP 上游（需 `RSDNS_UPSTREAM_TCP`） |
| DoQ | 15361 | DNS over QUIC 上游（需 `RSDNS_UPSTREAM_DOQ`） |

### 测试内容

| 测试 | 验证点 |
|------|--------|
| **Forward** | `example.com` 可正常解析；`track.doubleclick.net` 返回 `0.0.0.0`（poison 拦截） |
| **Hosts** | `rsdns-test-blocked.example.com` 命中 hosts 记录，返回 `0.0.0.0` |
| **Reject** | `blocked-nxdomain.example` 返回 NXDOMAIN（无解析结果） |
| **DoT** | 通过 TLS 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **DoH** | 通过 DoH 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **DoH3** | 通过 HTTP/3 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **TCP** | 通过 TCP 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |
| **DoQ** | 通过 QUIC 上游解析 `example.com`；非匹配域名无法解析（验证分流无泄漏） |

> DoT/DoH/DoH3/TCP/DoQ 采用**分流校验**模式：配置双 upstream——`test` 指向协议上游，`default` 指向不可达地址 `127.0.0.1:19999`。规则将 `example.com` 路由到 `test`，其余走 `default`。校验匹配域名解析成功、非匹配域名解析失败，以此确认分裂未泄漏到默认路由。

### 环境变量（rsdns 可选测试）

| 变量 | 说明 | 示例 |
|------|------|------|
| `RSDNS_UPSTREAM_DOT` | DoT 上游地址（host:port） | `1.1.1.1:853` |
| `RSDNS_UPSTREAM_DOH` | DoH 上游 URL | `https://1.1.1.1/dns-query` |
| `RSDNS_UPSTREAM_DOH3` | DoH3 上游 URL | `https://1.1.1.1/dns-query` |
| `RSDNS_UPSTREAM_TCP` | TCP 上游地址 | `tcp://1.1.1.1:53` |
| `RSDNS_UPSTREAM_DOQ` | DoQ 上游地址 | `quic://1.1.1.1:853` |

未设置的协议测试自动 SKIP。
