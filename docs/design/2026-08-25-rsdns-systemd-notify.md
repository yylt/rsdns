# rsdns 新增 systemd notify：通知 systemd 服务已 ready

> 2026-08-25 | 提案

## 1. 动机

rsdns 以 systemd service 方式部署时，Type=simple 的服务在进程启动后立即被视为
"active"，此时 DNS 监听端口可能尚未就绪，依赖 rsdns 的上游服务可能发起查询而失败。
通过 sd_notify 协议（`$NOTIFY_SOCKET`）向 systemd 发送 `READY=1`，可以精确表达
"服务已就绪" 这一状态，配合 `Type=notify` 让 systemd 在 rsdns 真正 ready 后才
推进依赖关系（`After=` / `Requires=`）。

## 2. 目标 / 非目标

### 目标

- 启动时在所有 UDP/TCP 监听器与可选 metrics 端点都**绑定成功**后，通过
  `$NOTIFY_SOCKET` 发送 `READY=1`，通知 systemd 服务已就绪。
- 作为进程内通知（`sd_notify(3)` 风格），不依赖外部 `systemd-notify` 命令。
- 在非 systemd 环境（无 `NOTIFY_SOCKET`）下静默跳过，不影响普通运行。

### 非目标

- 不做 watchdog（`WATCHDOG=1` / `WATCHDOG_USEC`）——本提案只覆盖启动就绪通知，
  服务本身无需要看门狗守护的故障恢复逻辑。
- 不做 stop/status 通知（`STOPPING=1` / `STATUS=`），systemd `Type=notify` 服务
  退出即视为停止，无需额外通知。
- 不为 xray-rs 主程序添加该能力（仅 rsdns；主程序如需可另行提案）。

## 3. 方案

### 3.1 通知实现：轻量 `sd_notify` 模块

按 AGENTS.md 的"简洁"原则，不新增第三方 crate（`libsystemd` / `sd-notify` /
`notify-rust` 等），直接通过 Unix datagram socket 实现 sd_notify 协议：

- 读取环境变量 `NOTIFY_SOCKET`；为空则直接返回（非 systemd 环境）。
- 解析 socket 路径：`@name` 为 Linux 抽象命名空间 socket（`std::os::unix::net::
  SocketAddr::from_abstract_name`，把 `@` 替换为 `\0`）；`/path` 为文件系统
  socket（`from_pathname`）。
- 创建 Unix datagram socket，`connect` + `send` 一次完成（无需监听应答）。
- 失败仅记 warning 日志，不视为致命错误（通知失败不应阻断 DNS 服务）。

`sd_notify` 是 **blocking** 的 POSIX socket 操作，放在 async 任务里会阻塞 worker；
ready 通知在绑定阶段之后、进入事件循环之前调用一次，使用 `std::os::unix::net::
UnixDatagram`（非 tokio），此时仍在 `run()` 的同步段，无阻塞问题。

### 3.2 ready 时机

`main.rs::run()` 中，在**所有 listener 绑定成功之后**发送 `READY=1`：

```
初始化 pipeline / upstreams（启动期解析）
  → 绑定所有 binds[]（UDP + TCP）
  → 可选 metrics 端点绑定
  → 发送 READY=1          ← 新增
  → 进入事件循环（join 监听任务）
```

- 顺序：先绑 metrics 再通知（metrics 也是 rsdns 对外服务面的一部分，端口占用
  失败时应视为未 ready）。
- 任一 listener 绑定失败：返回错误，进程退出，systemd 视服务失败——**不发送**
  `READY=1`（与 sd_notify 语义一致）。

### 3.3 绑定失败处理（重构）

现状 `run()` 把每个监听器 spawn 成独立任务，绑定失败只打 error 日志、进程继续跑
（可用性未知）。为配合 ready 语义，把**绑定与事件循环分离**：

- 先同步绑定全部 listener（UDP socket / TCP listener + metrics listener）；
- 绑定成功后再 spawn 各自的 accept 循环任务；
- 任一绑定失败 → 返回错误，`main` 退出非零。

`server.rs` 相应拆分：`bind_udp_dual_stack` / `bind_tcp_dual_stack` 已是独立的
私有方法，新增公开的 `bind_udp(addr)` / `bind_tcp(addr)` 返回已绑定的
`UdpSocket` / `TcpListener`，并把现有 `serve_udp` / `serve_tcp` 改为接收已绑定
socket 的 accept 循环。

## 4. 配置与示例

- 无需新增配置项（`NOTIFY_SOCKET` 由 systemd 注入，非用户配置）。
- `example/` 增加 `example/rsdns.service` 供部署参考：

```ini
[Unit]
Description=rsdns DNS server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/rsdns --config /etc/rsdns/rsdns.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## 5. 涉及文件

| 文件 | 改动 |
|---|---|
| `src/notify.rs`（新） | `sd_notify_ready()` 函数：`NOTIFY_SOCKET` 检测 + Unix datagram 发送 |
| `src/main.rs` | `mod notify;`；`run()` 重构为"先绑定、后通知、再事件循环"；绑定失败返回错误 |
| `src/server.rs` | 拆分 `bind_udp` / `bind_tcp`（返回已绑定 socket）与 accept 循环 |
| `example/rsdns.service`（新） | 示例 systemd unit（`Type=notify`） |

依赖变更：无新增依赖（`std::os::unix::net::UnixDatagram` 即可，无需 `libc`）。

## 6. 测试

- `notify.rs` 单测：
  - `NOTIFY_SOCKET` 未设置 → 函数直接返回 Ok（不 panic、不发送）；
  - 抽象 socket 路径 `@name` 解析为 `\0name`；
  - 指向临时文件路径的 `NOTIFY_SOCKET` → 返回 Err（由调用方记 warning）。
- `make ci`（fmt + clippy + check + test）通过；`make build-rsdns`（debug）通过。

## 7. 风险与权衡

- **阻塞 send**：ready 通知是进程启动阶段的一次性阻塞调用，Unix datagram send
  到 systemd 本地 socket 不会阻塞（缓冲区即时写入），无性能影响。
- **通知失败不致命**：非 systemd 环境（无 `NOTIFY_SOCKET`）直接跳过；有 socket
  但发送失败仅 warning——DNS 服务本身照常运行。
- **行为变化**：任一监听器绑定失败时进程改为退出非零（原来只记日志继续跑）。
  对 systemd 部署这是期望语义（`Restart=on-failure` 可自动重启）；对非 systemd
  部署，绑定失败退出也是更可观测的行为。
