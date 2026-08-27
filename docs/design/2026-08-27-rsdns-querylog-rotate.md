# rsdns 查询日志：写入目录 + 大小轮转 + gzip 压缩

> 2026-08-27 | 提案

## 1. 动机

当前 `log:` 配置只支持 `format`，查询日志始终写入 stdout（见
`docs/design/2025-08-07-rsdns-logging.md` 的现状回写）。生产部署需要：

- 把查询日志落到磁盘目录，便于持久化与采集；
- 单文件大小达到上限后自动轮转（gzip 压缩归档，继续写新文件），避免日志
  无限增长撑爆磁盘。

## 2. 目标 / 非目标

### 目标

- 新增日志目录配置，支持日志写入指定目录下的滚动文件。
- 按 `{dir}:{maxsize}:{numfile}` 三元组格式配置：`dir` = 输出目录，
  `maxsize` = 单个日志文件的大小上限，`numfile` = 保留的日志文件数量
  （含当前写入文件）。
- 当前文件达到 `maxsize` 后：将其 gzip 压缩归档，并创建新的日志文件继续
  写入。
- 默认 `" /var/log/rsdns:5m:5"`（不带空格）：`dir=/var/log/rsdns`，
  `maxsize=5m`（5 MiB），`numfile=5`。

### 非目标

- 不做基于时间（日期/小时）的轮转，只做大小轮转。
- 不做日志删除策略之外的配额管理（磁盘水位、配额限制等）。
- 不改动模板/占位符/字段渲染逻辑。

## 3. 方案

### 3.1 配置格式

`log:` 段新增 `directory` 字段（可选）。沿用项目现有的 `"<窗口>:<次数>:<
冷却>"` 式紧凑三元组风格（upstream 的 `cooldown`），格式：

```
{dir}:{maxsize}:{numfile}
```

- `dir`：输出目录，不存在则自动创建（递归 `create_dir_all`）。
- `maxsize`：大小阈值，支持单位后缀 `k`/`K`/`m`/`M`（KB/MB，十进制，即
  `m` = 1_000_000 字节）与 `g`/`G`（GB）；裸数字视为字节。
- `numfile`：保留文件数（含当前写入文件，≥ 1）。

`directory` 也可以只给目录路径（不带 `:maxsize:numfile`），此时轮转参数
使用默认值 `5m` 与 `5`。

示例：

```yaml
log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns:5m:5'   # 显式轮转参数

log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns'        # 只给目录 → 5m / 5 个
```

缺省 `directory` 时行为不变（stdout）。显式设置后查询日志写入目录。

### 3.2 文件命名与轮转

固定主文件名 `query.log`，轮转后压缩为 `query.log.1.gz`、`query.log.2.gz`、
…… 编号越大越旧：

- 启动时：创建/截断 `dir/query.log`（追加写入）。
- 写入累计达到 `maxsize`：当前文件先 `flush`+`sync`，然后整体 gzip 压缩为
  `dir/query.log.1.gz`，原文件截断并继续追加；原有 `query.log.N.gz` 编号
  +1 顺移，超过 `numfile-1` 个归档（即编号 > `numfile-1`）时删除。
- 例如 `:5m:5`：保留 `query.log` + `query.log.1.gz` … `query.log.4.gz`
  共 5 个文件，更旧归档删除。

启动时若已存在 `query.log.1.gz` 等归档，直接沿用（不重命名、不删除）；
仅对**当前写入周期内新产生的**归档执行编号顺移与淘汰，避免把历史归档
挤掉。恢复计数从磁盘现有归档的最大编号 +1 开始（基于 `query.log.N.gz`
的文件名扫描，无需维护元数据文件）。

压缩流式边写边压：从当前文件头读到尾，经 `flate2` GzEncoder 逐块写入
`.gz`，不整体载入内存；压缩完成后再截断原文件。归档文件名带写入时的
时间戳，避免同名覆盖竞态（同一 `maxsize` 内多次轮转不会丢文件）。

### 3.3 并发模型

沿用现有"行级写出"模型：`QueryLogger` 内部持有 `Arc<Mutex<...>>`，
每次查询渲染一行后写写入器，写满阈值即触发轮转。目录模式全部走
`tokio::fs`（目录创建、行写入、read_dir / rename / remove 均异步，不阻塞
tokio worker），互斥用 `tokio::sync::Mutex`；`flate2` GzEncoder 是同步
API，gzip 压缩放到 `spawn_blocking` 中流式执行（边读边压，不整体载入
内存）。原 stdout 路径保持 `AsyncWriteExt` 不变。

启动阶段（`main.rs::run`）创建目录并打开初始文件，失败则启动报错退出；
运行期轮转失败（磁盘满等）记 error 并继续写当前文件，不让日志故障
影响 DNS 服务。`directory` 解析失败（如 `:5m:5` 前缺目录段）记 warning
并按默认目录处理，避免日志配置拖垮启动。只给目录路径（不含
`:maxsize:numfile`）按默认 `5m` / `5` 处理。

## 4. 示例

```yaml
# 默认格式：/var/log/rsdns:5m:5（5 MiB 轮转，保留 5 个文件）
log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns:5m:5'

# 只给目录：轮转参数用默认 5m / 5 个
log:
  format: '{remote}:{port} {name} [{type}] {rcode} {action} {duration}'
  directory: '/var/log/rsdns'
```

轮转后目录内容：

```text
/var/log/rsdns/query.log        # 当前写入
/var/log/rsdns/query.log.1.gz   # 最近归档
/var/log/rsdns/query.log.2.gz
/var/log/rsdns/query.log.3.gz
/var/log/rsdns/query.log.4.gz
```

## 5. 涉及文件

| 文件 | 改动 |
|---|---|
| `src/config.rs` | `LogConfig` 增加 `directory: Option<String>`；`parse_log_directory()` 解析 `{dir}:{maxsize}:{numfile}`（默认 `" /var/log/rsdns:5m:5"`），含 `maxsize` 单位后缀解析 |
| `src/plugins/logs.rs` | `QueryLogger` 增加目录写入分支：行级 `Mutex` 写入 + 大小累计 + 轮转（gzip 归档/编号顺移/淘汰）；stdout 路径不变 |
| `src/main.rs` | 启动时创建日志目录并打开初始文件（失败即报错退出） |
| `example/rsdns-all-example.yaml` | `log:` 段补充 `directory` 示例与说明 |
| `Cargo.toml` | 新增依赖 `flate2`（默认特性：std zlib，纯 Rust 实现） |

## 6. 测试

- 单元测试（`logs.rs`，`#[tokio::test]`）：
  - `parse_log_directory`：默认值、`k`/`m`/`g` 单位、裸数字、非法输入
    （缺段、`numfile=0`、目录为空、`maxsize=0`）→ 报错/回退默认；
  - 轮转逻辑：写入超过 `maxsize` 后产生 `.1.gz`、当前文件被截断、
    归档计数正确、超过 `numfile-1` 的旧归档被删除；
  - gzip 解压后内容与轮转前文件一致。
- `make ci`（fmt + clippy + check + test）通过；`make build`（debug）通过。

## 7. 风险与权衡

- **阻塞压缩**：轮转触发时在 `spawn_blocking` 中压缩当前文件，量级为单个
  5 MiB 文件的压缩，秒级以内；期间 DNS 查询日志行短暂排队，不影响解析
  主路径（行级 Mutex 短临界区，且压缩不占用 tokio worker）。
- **日志故障不致命**：运行期轮转失败记 error 继续写，不影响 DNS 服务
  可用性；但启动时目录创建/初始文件打开失败会报错退出（日志目录不可用
  是部署配置错误，早失败比静默丢日志更可观测）。
- **配置错误回退默认**：`directory` 解析失败时记 warning 并按默认
  `"/var/log/rsdns:5m:5"` 处理，避免因日志配置拖垮启动；若用户显式
  配置目录却解析失败，仍可定位（warning 指明原始串）。
- **归档上限**：`numfile` 同时约束归档数量与磁盘占用（最坏约
  `numfile × maxsize × 压缩比`），超限归档在轮转时删除。
