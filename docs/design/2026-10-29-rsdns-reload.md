# rsdns 支持 systemctl reload：重开查询日志，轮转交给 logrotate

> 2026-10-29 | 提案（已实现）

## 1. 动机

生产部署希望用外部 `logrotate` 管理查询日志（按天/按大小轮转、gzip 压缩、
保留份数）。`logrotate` 的标准姿势是「轮转 → `postrotate` 里让进程重开日志
文件」：

```conf
/var/log/rsdns/query.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl reload rsdns >/dev/null 2>&1 || true
    endscript
}
```

当前 rsdns 有两个阻碍：

1. **没有 reload 入口**：无 SIGHUP 处理，`systemctl reload rsdns` 无从生效；
   进程始终持有 `query.log` 的旧文件描述符，`logrotate` 一旦 `create` 新文件，
   后续日志全部写进已重命名/已压缩的旧 inode（丢日志）。
2. **内置轮转与 logrotate 重叠**：`log.directory` 的 `{dir}:{maxsize}:{numfile}`
   会自己按大小 gzip 归档（`query.log.N.gz`），与外部 `logrotate` 的压缩归档
   叠加，语义混乱、保留策略不可控。

## 2. 目标 / 非目标

### 目标

- `kill -HUP` / `systemctl reload rsdns` 触发**重开查询日志**：重新
  `open(dir/query.log)`（`create + append`），使 `logrotate` 的 rename +
  `create` 模式生效。
- 移除内置的按大小 gzip 轮转，压缩/保留全部交给 `logrotate`。
- reload 失败（重开文件失败）**不影响服务**：记 error，继续写旧句柄。

### 非目标

- **不做配置热重载**：SIGHUP 只重开日志，不重读 rsdns.yaml。规则/上游/缓存等
  变更仍需重启进程。
- 不做 `Type=notify-reload`（`RELOADING=1` / `READY=1` 双通知）：Debian 12 的
  systemd 252 不支持该类型；本提案的 `systemctl reload` 语义是「HUP 已投递」。
- 不做 `copytruncate` 模式支持（会丢行且需截断），不做 `SIGTERM` 优雅停机改造。

## 3. 方案

### 3.1 查询日志：只写文件，不再自己轮转

`log.directory` 语义收敛为**纯目录路径**：

```yaml
log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns'
```

- 只追加写 `dir/query.log`（`create(true) + append(true)`，目录不存在时
  `create_dir_all`）。
- 删除：`RotatingFileSink`、`gzip_file`、归档编号扫描、`prune`；以及
  `config.rs` 里的 `LogDirectory` / `parse_log_directory_checked` /
  `parse_size` / `DEFAULT_LOG_*` 常量与对应单测。
- `Cargo.toml` 移除 `flate2`（全仓仅 logs 使用）。
- **旧格式显式报错**：`directory` 含 `:` 时 `QueryLogger::new` 返回
  `InvalidInput`，启动失败并提示「内置轮转已移除，改用外部 logrotate，填纯目录
  路径」。静默把 `/var/log/rsdns:5m:5` 当目录名去 `create_dir_all` 会把日志
  悄悄写到错误位置，宁可在启动时失败（与 `rules` 配置错误致命化的既有风格一致）。
- 并发模型不变：行级 `tokio::sync::Mutex<fs::File>`，异步写入不阻塞 worker。

### 3.2 SIGHUP → 重开文件

`main.rs::run` 末尾的「等任意 listener 退出」改为 `tokio::select!`：

```rust
let mut sighup = signal(SignalKind::hangup())?;
loop {
    tokio::select! {
        _ = sighup.recv() => match server.reopen_logs().await {
            Ok(()) => info!("SIGHUP: query log reopened"),
            Err(e) => error!("SIGHUP: failed to reopen query log: {}", e),
        },
        joined = tasks.join_next() => {
            if let Some(Err(e)) = joined { error!("listener task panicked: {}", e); }
            break;
        }
    }
}
```

重开流程（`DirectorySink::reopen`）：

1. 先 `open(dir/query.log)` 拿到新句柄（先开新文件；失败则旧句柄原样保留、
   返回 error，服务继续写旧文件）；
2. 再取写入锁替换句柄 —— 锁只覆盖一次赋值，不覆盖 `open`，避免重开期间
   阻塞查询日志写入。

stdout 模式（未配置 `directory`）下 `reopen` 是空操作。

### 3.3 部署示例

`example/rsdns.service` 增加：

```ini
ExecReload=/bin/kill -HUP $MAINPID
```

新增 `example/rsdns.logrotate`（`compress` + `postrotate systemctl reload`）。

## 4. 配置与示例

```yaml
log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns'   # 仅目录；轮转/压缩由 logrotate 完成
```

```bash
systemctl reload rsdns        # SIGHUP：重开 query.log
kill -HUP "$(pidof rsdns)"    # 非 systemd 环境等价
```

运行期目录内容（由 logrotate 维护）：

```text
/var/log/rsdns/query.log          # 当前写入（reload 后重建）
/var/log/rsdns/query.log.1        # 上一次轮转（delaycompress，下次压缩）
/var/log/rsdns/query.log.2.gz
```

## 5. 涉及文件

| 文件 | 改动 |
|---|---|
| `src/plugins/logs.rs` | 删除轮转/gzip；`DirectorySink`（`dir/query.log` 追加 + `reopen`）；`directory` 含 `:` 报错；`Logs::reopen`；单测改为追加/reopen 语义 |
| `src/server.rs` | `DnsServer::reopen_logs` 暴露给 main |
| `src/main.rs` | `select!` 等 SIGHUP 与 listener 退出；SIGHUP 调 `server.reopen_logs()` |
| `src/config.rs` | `LogConfig.directory` 文档改为纯目录；删除 `LogDirectory`/`parse_log_directory_checked`/`parse_size`/`DEFAULT_LOG_*` 及其测试 |
| `example/rsdns.service` | `ExecReload=/bin/kill -HUP $MAINPID` |
| `example/rsdns.logrotate`（新） | logrotate 配置示例 |
| `example/rsdns-all-example.yaml` | `log.directory` 注释更新 |
| `README.md` / `README.en.md` | 特性 + 部署说明（reload 只重开日志、logrotate 示例） |
| `Cargo.toml` / `Cargo.lock` | 移除 `flate2` |
| `docs/design/2026-08-27-rsdns-querylog-rotate.md` | 顶部标注「内置轮转已被移除」 |

## 6. 测试

- `plugins/logs.rs`（`#[tokio::test]`）：
  - `test_directory_sink_appends_lines`：两次写入按序追加进 `dir/query.log`，
    不产生任何归档文件；
  - `test_reopen_after_logrotate_rename`：写入 → `rename` 成 `query.log.1` →
    `reopen` → 再写，新 `query.log` 只含新行，`query.log.1` 内容不变；
  - `test_reopen_failure_keeps_old_handle`：目录被普通文件占住 → `reopen`
    返回 Err，旧句柄继续可写；
  - `test_rotating_spec_is_rejected`：`directory: '/var/log/rsdns:5m:5'` →
    `InvalidInput`，错误信息含 `logrotate`。
- 删除原 5 个轮转相关单测（gzip 归档 / 编号 / 保留份数 / 恢复编号 / 空文件）。
- `make ci`（fmt + clippy + check + test）通过；`make build`（debug）通过。

## 7. 风险与权衡

- **reload 不重载配置**：改规则/上游仍需重启。这是有意的范围收敛：SIGHUP 只
  承担 logrotate 的重开职责，不引入 pipeline 重建、缓存/连接池失效与指标重复
  注册的复杂度。
- **reload 失败静默**：`ExecReload` 只发信号，失败体现在日志里（`error!`），
  `systemctl reload` 仍返回 0；文档写明「reload 结果看日志」。
- **旧配置格式不再兼容**：`directory: dir:5m:5` 启动即报错，错误信息给出修正
  方法。属于有意的破坏性变更，README 中标注。
- **轮转瞬间可能丢行**：reload 与 `logrotate` 的 create + 压缩之间存在极小
  窗口，可能有一两行写进已重命名的文件（`delaycompress` 缓解）。这是 `create`
  模式的固有语义；`copytruncate` 会丢行且需截断，不采用。
