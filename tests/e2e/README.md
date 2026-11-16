# rsdns E2E Tests

端到端（End-to-End）测试，验证 `rsdns` 二进制在真实网络环境中的完整链路行为。

## 技术方案

测试框架使用 **Go** 编写（`main.go`），通过 `os/exec` 启动 rsdns 子进程，构造请求并校验响应。

- 启动 rsdns 进程，使用原始 UDP DNS wire-format 查询，验证转发、拦截、缓存、hosts 等核心功能。
- 生成的转发组显式使用 `query_timeout: 5`（整组）和 `attempt_timeout: 2`（每 server），单位为秒；失败 IP 按 2/4/8/16/32 秒退避，不再配置 group.cooldown。

## 目录结构

```
tests/e2e/
├── README.md                  # 本文件
├── main.go                    # 入口 + 启动配置加载、结果汇总
├── config.json                # 默认上游、测试范围和各协议上游
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
| **DoT** | 通过 TLS 上游解析 `example.com`；空解析结果判为失败 |
| **DoH** | 通过 DoH 上游解析 `example.com`；空解析结果判为失败 |
| **DoH3** | 通过 HTTP/3 上游解析 `example.com`；空解析结果判为失败 |
| **TCP** | 通过 TCP 上游解析 `example.com`；空解析结果判为失败 |
| **DoQ** | 通过 QUIC 上游解析 `example.com`；空解析结果判为失败 |

> DoT/DoH/DoH3/TCP/DoQ 使用 `test` 协议上游解析 `example.com`，要求返回至少一个 IP；不再发起额外的未匹配域名查询。配置中的 `default` 仍指向不可达地址 `127.0.0.1:19999`。

### 启动配置

默认读取 `tests/e2e/config.json`（直接运行 Go runner 时，需在 `tests/e2e` 目录执行）。可通过 `./test_runner -config other.json` 或 `RSDNS_E2E_CONFIG=other.json ./tests/e2e/run_rsdns_tests.sh` 指定其他文件；脚本先切换到 `tests/e2e`，相对路径以该目录为基准。

| 字段 | 说明 |
|------|------|
| `default_upstream` | 普通测试和协议测试的 bootstrap 上游；协议测试的 default 仍固定为不可达地址（不再主动查询该路径） |
| `tests` | 要运行的测试名数组：`Forward`、`Hosts`、`Reject`、`DoT`、`DoH`、`DoH3`、`TCP`、`DoQ` |
| `upstreams` | 按协议类型配置测试上游地址；支持 `DoT`（`tls://`）、`DoH`（`https://`）、`DoH3`（`h3://`）、`TCP`（`tcp://`）、`DoQ`（`quic://`） |

选中的协议测试没有配置对应上游时自动 SKIP。默认配置未启用 DoQ 上游；需要测试时在 `upstreams` 中加入 `"DoQ": "quic://..."`。
