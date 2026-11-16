# AGENTS.md

## Lint & Test

```bash
make ci      # run fmt + clippy + check + test
```

- `make ci` 是本地完整校验入口（fmt → clippy → check → test），改动后必须通过。
- 不主动做 smoke test / 构建二进制验证；只需通过 `make ci`。
- E2E 位于 `tests/e2e/`，入口为 `./tests/e2e/run_rsdns_tests.sh`，需预先构建 rsdns 二进制。默认读取 `tests/e2e/config.json`，通过 `RSDNS_E2E_CONFIG` 或 runner 的 `-config` 指定 JSON 配置（`default_upstream`、`tests`、`upstreams`）；旧的 `RSDNS_UPSTREAM_*` 环境变量不再生效。脚本切换到 `tests/e2e/` 后读取配置，相对路径以该目录为基准。
- `.github/workflows/e2e.yaml` 生成独立的临时 JSON 配置，默认解析 / bootstrap 和 DoT、DoH、DoH3、TCP 上游均使用 `1.1.1.1`，不覆盖本地默认配置；DoQ 未配置上游时自动 SKIP。

## Architecture (high-signal)

- **Single crate**. `src/main.rs` is the DNS binary entry; modules live directly under `src/` (`config.rs`, `server.rs`, `query.rs`, `metrics.rs`, `notify.rs`, `plugins/`, `upstream/`, `common/`). `common/` holds helpers split out of the original `xray-rs` proxy codebase (`rslog`, `domain_trie`, `tls`, `bind`).
- **Config format**: YAML by default (`.yaml`/`.yml`), JSON also supported. Config struct at `src/config.rs:Config`.
- **Listeners (inbound)**: UDP (`ip:port`) and TCP (`tcp://ip:port`), configured via `binds[]`.
- **Upstream protocols (outbound)**: plain UDP/TCP, DoT (`tls://`), DoH (`https://`), DoH3 (`h3://`), DoQ (`quic://`).
- **Query pipeline** (`server.rs:handle_query`): fixed stages `hosts → groups → cache → rules`; `upstream` is **not** a stage — it is assembled at startup into `upstream::Upstreams` (a concrete type holding the named groups) and held directly by the `rules` stage for forward/cname; fallback returns NXDOMAIN/SERVFAIL.
  - **Cache records**: A, AAAA, CNAME, MX, TXT, and HTTPS are cached. NXDOMAIN is negatively cached. Hosts and block responses are never cached.
- **Rules**: ordered by priority. Actions: `block` (NXDomain or poison IP), `cname` (rewrite + recursive resolve), `forward` (named upstream pool, optional TTL override).
- **Cache**: LRU with configurable capacity, TTL clamping; per-entry TTL via moka `Expiry` — expired entries are evicted automatically (no stale serving; upstream failure → SERVFAIL).
- **Connection pool**: one shared connection per server, serialized connection establishment, per-IP exponential backoff (2/4/8/16/32s), per-address-family preference; group query_timeout (default 5s) and per-server attempt_timeout (default 2s).

## 配置同步

- 每次修改配置字段、层级、默认值或语义时，必须同步检查并更新 `.github/workflows/` 和 `tests/` 下的配置文件、脚本内嵌配置及生成配置的逻辑；不能只改源码或 `example/` 示例。
- 对应配置示例、测试断言与使用文档也必须同步，确保 CI、测试和本地示例使用一致的配置格式与语义。

## Rules

- **No annotation bypasses**: Do not suppress warnings/errors with `#[allow(...)]`, `#[cfg(...)]` hacks, or other annotation-based workarounds. Fix the root cause instead.
- **先思考** — 明确假设。如有疑问，先问。
- **简洁** — 最少代码。不为单次使用引入抽象。不添加未请求的功能。
- **精确** — 只动必须改的。保持现有风格。只删自己留下的孤儿代码。
- **目标驱动** — 先定义成功标准。验证后再声明完成。
- **提案先行** — 任何重大修改（新增功能、API 变更、架构调整等）必须先提交提案文档到 `docs/design/` 进行审阅，审阅通过后再进行实现。
