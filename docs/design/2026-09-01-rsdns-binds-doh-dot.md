# rsdns inbound DoT / DoH / DoH3 监听能力

> 2026-09-01 | 提案

## 1. 动机

当前 `binds[]` 只支持明文 DNS 监听：`"ip:port"`（UDP）与
`"tcp://ip:port"`（TCP）。在公网或跨不可信网络部署时，明文 53 端口容易被
窃听/篡改，客户端没有机会走加密 DNS（DoT / DoH / DoH3）。

`rsdns` 已有完整的上游加密链路（DoT/DoH/DoH3/DoQ，见
`src/upstream/factory.rs`），但**入站**只支持明文。本次为 `binds[]` 新增
`tls://`（DoT）、`https://`（DoH，HTTP/1.1 + HTTP/2）与 `h3://`（DoH3，
HTTP/3）三种监听协议，使 rsdns 可以作为加密 DNS 服务端
（forwarder/recursor）对外提供服务，配合 `rules` 的 forward/block/cname
全链路复用。

## 2. 目标 / 非目标

### 目标

- `binds[]` 支持五种协议：UDP（现状）、TCP（现状）、`tls://`（DoT）、
  `https://`（DoH，HTTP/1.1 + HTTP/2）、`h3://`（DoH3，HTTP/3）。
- 与上游各 scheme（`tls://`、`https://`、`h3://`）写法完全一致。
- TLS 证书/密钥**显式可配置**（顶层 `tls_cert` / `tls_key`，PEM 文件
  路径），并提供自签证书开箱即用（默认自动生成）。
- DoH 同一端口同时支持 HTTP/1.1 与 HTTP/2（RFC 8484 两种版本）。
- DoT/DoH/DoH3 查询走与 UDP/TCP 完全相同的查询流水线
  （logs → hosts → groups → cache → rules → speed），查询日志、缓存、
  指标全部复用。
- 复用现有 `bind_tcp_listener` 的 IPv6 双栈绑定逻辑；UDP 类（DoH3 的
  QUIC）复用 `bind_udp` 的 IPv6 双栈逻辑。
- DoH 与 DoH3 共享同一份 HTTP 请求处理逻辑（RFC 8484：`POST
  /dns-query` + `GET ?dns=` base64url），只是传输层不同。

### 非目标

- 不做 DoQ（`quic://`）的入站监听（DoQ 不是标准 DoH 传输，且与 DoH3
  共享 QUIC 底层；如需可后续追加）。
- 不做客户端认证（mTLS）、证书自动轮换重载、ACME 自动签发。
- 不改动任何上游 / rules / cache 逻辑。

## 3. 方案

### 3.1 配置格式

沿用现有 `binds[]` 数组与 `address` 字符串风格，按 scheme 前缀区分协议：

```yaml
binds:
  - address: "0.0.0.0:53"             # UDP（现状）
  - address: "tcp://0.0.0.0:53"       # TCP（现状）
  - address: "tls://0.0.0.0:853"      # DoT（新增）
  - address: "https://0.0.0.0:8443"   # DoH，HTTP/1.1 + HTTP/2（新增）
  - address: "h3://0.0.0.0:8443"      # DoH3，HTTP/3（新增）
```

- 无前缀 = UDP；`tcp://` = TCP；`tls://` = DoT；`https://` = DoH；
  `h3://` = DoH3。其余前缀（如 `quic://`）解析失败，按启动错误处理。
- DoH/DoH3 的路径固定为 `/dns-query`（RFC 8484 约定路径），不支持在
  bind 地址中自定义路径；配置了路径则启动报错。

### 3.2 TLS 证书配置（顶层 `tls_cert` / `tls_key`）

```yaml
tls_cert: /etc/rsdns/server.crt   # PEM 证书（可含证书链）
tls_key:  /etc/rsdns/server.key   # PEM 私钥（PKCS#8 或 RSA/EC）
```

- **显式配置**：提供 `tls_cert` + `tls_key` 时加载 PEM 文件（`cert` 可含
  中间证书链；`key` 支持 PKCS#8/RSA/EC）。文件缺失、PEM 解析失败、证书
  与私钥不匹配均为**启动错误**（退出非零，配合 systemd notify 不发
  READY）。
- **默认自签**：两者都缺省时，为所有 DoT/DoH/DoH3 bind 自动生成 ECDSA
  P-256 自签证书（有效期 1 年，SAN 覆盖 `localhost` 与常用内网/回环
  IP），仅内存保存、不落盘，每次启动重新生成。
- 只配了其中一个（`tls_cert` 有而 `tls_key` 无，或反之）→ 启动错误。
- 同一份 `rustls::ServerConfig` 供 DoT（`TlsAcceptor`）、DoH（hyper
  auto h1/h2）、DoH3（quinn/h3）三套服务共用。

### 3.3 解析与装配（main.rs）

`main.rs` 中 `run()` 的监听装配改为按 scheme 分派：

```
for bind in &config.binds {
    match parse_bind(&bind.address)? {
        Udp(addr) => udp_binds.push(...)   // 现状
        Tcp(addr) => tcp_binds.push(...)   // 现状
        Tls(addr) => tls_binds.push(...)   // 新增：TCP listener
        Doh(addr) => doh_binds.push(...)   // 新增：TCP listener
        Doh3(addr) => doh3_binds.push(...) // 新增：UDP socket
    }
}
```

- TLS 证书配置在绑定之前解析（`tls::server_config(&config)`），三套服务
  共用同一个 `Arc<rustls::ServerConfig>`。
- 保持现有“先全部绑定、任一失败即退出”的语义：新增协议任一绑定失败也
  同样整体失败退出。
- 新增三个并发 accept 循环：`server.serve_dot(...)`、
  `server.serve_doh(...)`、`server.serve_doh3(...)`。

### 3.4 证书加载/自签（src/common/tls.rs）

`src/common/tls.rs` 现有 `default_tls_client_config()`（客户端 TLS）。新增
服务端部分：

- `load_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>, String>`
  — 用 `rustls_pemfile` 解析 PEM，`rustls::ServerConfig::builder()` 装配
  （使用与客户端一致的 crypto provider），并校验证书与私钥匹配。
- `generate_self_signed() -> Result<(Vec<u8>, Vec<u8>), String>` — 用
  `rcgen` 生成 ECDSA P-256 自签证书（`rcgen` 已在 `Cargo.toml` 中，目前
  无代码使用，正好用于此处）。SAN 包含 `localhost` 与常用内网/回环 IP；
  有效期 1 年；每次启动重新生成。
- `server_config(config: &Config) -> Result<Arc<rustls::ServerConfig>, String>`
  — 读顶层 `tls_cert`/`tls_key`：都提供则加载，都缺省则自签，只提供一个
  报错。无任何 DoT/DoH/DoH3 bind 时不调用，避免无谓生成。

### 3.5 DoT 服务循环（server.rs）

新增 `serve_dot(listener, tls_config, addr)`：

- accept 循环复用 `serve_tcp` 的骨架（`bind_tcp_listener` 已处理 IPv6
  双栈 + backlog）。
- 每个连接用 `tokio_rustls::TlsAcceptor::from(tls_config)` 做 TLS 握手，
  失败记录日志并关闭连接（不 panic、不影响其他连接）。
- 握手成功后按 RFC 1035 的 TCP 长度前缀（2 字节）读取 DNS 消息，调用
  `handle_query(data, src, "tls")`，回包同样带长度前缀。

`QueryContext::proto` 当前是 `&'static str`（"udp"/"tcp"），新增
`"tls"`、`"doh"`、`"doh3"` 三个取值；查询日志 `{proto}` 与
`rsdns_logs_queries_total{proto=...}` 指标自动获得新值，无需改渲染代码。

### 3.6 DoH 服务循环（server.rs，HTTP/1.1 + HTTP/2）

新增 `serve_doh(listener, tls_config, addr)`：

- accept + TLS 握手同 DoT（`tokio_rustls::TlsAcceptor`）。
- 握手后的字节流交给 **`hyper_util::server::conn::auto::Builder`**
  （已随现有 `server-auto` feature 启用）：自动嗅探 HTTP/2 preface，
  **同一端口、同一 TLS 连接上同时支持 HTTP/1.1 与 HTTP/2**，无需按
  ALPN 分派。
- 请求处理逻辑（`handle_doh_request`，DoH 与 DoH3 共用）：
  - `POST /dns-query`，`Content-Type: application/dns-message`：body 为
    DNS 消息 → `handle_query(body, src, "doh")` → 应答回
    `Content-Type: application/dns-message`。
  - `GET /dns-query?dns=<base64url 无 padding>`：按 RFC 8484 解码查询
    参数 → 同上；应答也回 `application/dns-message`。
  - 其余路径 404；`Content-Type` 不符 415。

### 3.7 DoH3 服务循环（server.rs，HTTP/3）

新增 `serve_doh3(socket, tls_config, addr)`：

- 复用 hickory-net 自带的 `hickory_net::h3::H3Server`
  （`with_socket_and_tls_config(socket, tls_config)`，源码已确认存在：
  `hickory-net-0.26.1/src/h3/h3_server.rs`）。当前 feature 组合
  （`h3-aws-lc-rs`）已把 `quinn` / `h3` / `h3-quinn` 编译进构建
  （`cargo tree` 已确认），无需新增依赖。
- UDP socket 用现有 `bind_udp`（IPv6 双栈逻辑复用）。
- 循环：`H3Server::accept()` → `H3Connection::accept()` → 逐请求解析出
  `Request<()>` + `RequestStream` → 提取 body / `?dns=` → 与 DoH 共用
  `handle_doh_request` 的请求语义（proto 标 `"doh3"`）→ 写回
  `RequestStream`。
- 同一份 `rustls::ServerConfig` 经 `QuicServerConfig::try_from` 转换给
  quinn（hickory 的 `H3Server` 内部已处理）。

### 3.8 错误与回退

- 无效 bind scheme（如 `quic://`）→ 启动错误（`parse_bind` 返回 `Err`），
  沿用现有“任一绑定失败整体退出”语义。
- DoH/DoH3 路径非 `/dns-query` → 启动错误。
- `tls_cert`/`tls_key` 只提供一个、文件缺失、解析失败或不匹配 →
  启动错误。
- TLS 握手失败 / HTTP 请求非法 / QUIC 连接错误：记录日志、关闭该连接，
  不影响监听循环与其他连接。

## 4. 配置变更影响

| 位置 | 变更 |
|------|------|
| `src/config.rs` | `BindConfig` 保持 `address: String` 不变（scheme 在解析期识别）；`Config` 新增顶层可选字段 `tls_cert: Option<String>`、`tls_key: Option<String>`（`#[serde(default)]`，与 `binds`/`upstreams` 同层级，不落入 `plugin_sections`） |
| `src/main.rs` | `parse_bind` 按 scheme 返回枚举；`run()` 增加 tls/doh/doh3 绑定与 accept 任务 |
| `src/common/tls.rs` | 新增服务端 `ServerConfig` 加载 + 自签生成 |
| `src/server.rs` | 新增 `serve_dot` / `serve_doh` / `serve_doh3`；`DnsServer` 持有 `Arc<ServerConfig>` |
| `src/query.rs` | `proto` 文档注释补充 `"tls"` / `"doh"` / `"doh3"` 取值（字段类型不变） |
| `Cargo.toml` | 新增 `tokio-rustls` 直接依赖（`server-auto` 已含 `http2`，DoH h1/h2 无需新增 feature）；`rcgen` 由“未使用”转为实际使用 |
| `example/rsdns-all-example.yaml` | binds 注释与示例补充 DoT/DoH/DoH3 条目与 `tls_cert`/`tls_key` |
| `README.md` | 监听协议说明更新 |

## 5. 测试

- **config**：`parse_bind` 对 `tls://`/`https://` 的解析与枚举分派；非法
  scheme 报错；`tls_cert`/`tls_key` 缺省/显式/只提供一个的解析。
- **common::tls**：自签证书生成成功且能被 rustls 加载为 `ServerConfig`；
  显式 PEM 加载成功；坏 PEM / 证书私钥不匹配 / 只提供一个报错。
- **server**：
  - `serve_dot`：`TlsAcceptor` 握手后按长度前缀收发 DNS 消息（单测构造
    内存 TLS 连接）。
  - `serve_doh`：`POST /dns-query`、`GET ?dns=` 路由与 404/415 分支；
    **同一连接上 HTTP/1.1 与 HTTP/2 各验证一次**（auto builder）。
  - `serve_doh3`：hickory `H3Server` 可绑定并 accept 连接（单测以
    `h3://127.0.0.1:0` 起服，用 hickory `H3ClientStream` 回环查询）。
- **query**：`proto` 新取值不影响现有渲染（现有 `{proto}` 测试仍通过）。

E2E（`tests/e2e`，参考现有 `TestRsdnsDoT`/`TestRsdnsDoH` 的写法）：
- 起一个 DoT bind（自签证书），用支持自签的客户端（如 `kdig +tls` /
  `dog`）验证 `example.com` 可解析、未匹配域名不泄漏到默认上游。
- 起一个 DoH bind，分别用 `curl --http1.1` 与 `curl --http2`
  `-H 'content-type: application/dns-message'` POST 验证。

## 6. 兼容性

- `binds` 现有写法（`ip:port`、`tcp://ip:port`）完全不变。
- `tls_cert`/`tls_key` 是新增顶层可选键，不配置时行为与现状一致（无
  加密 bind 则不生成证书）。
- 查询流水线、rules、cache、upstream 均无改动。
