# rsdns

Default language: English | [中文](./README.md)

A rule-driven standalone DNS server implemented in Rust, with composable listeners, upstreams, rules, caching, and query logging. Originally the DNS binary inside the [xray-rs](https://github.com/yylt/xray-rs) project, now extracted into its own repository.

## Features

- **Listeners (inbound)**
  - UDP (`ip:port`)
  - TCP (`tcp://ip:port`)
- **Upstreams (outbound)**
  - UDP / TCP (plain DNS)
  - DoT (`tls://`)
  - DoH (`https://`)
  - DoH3 (`h3://`)
  - DoQ (`quic://`)
- **Query pipeline**: `hosts → groups → cache → rules → cloudflare → balance`; unmatched queries fall back to NXDOMAIN/SERVFAIL
- **Rules**: `block` (NXDomain or poison IP), `cname` (rewrite + recursive resolve), `forward` (named upstream pool, optional TTL override / resolve_cname), `rewrite` (synthesized A record)
- **balance (post-pass)**: `prefers` CIDR priority, `mode` (`round_robin` / `speed`), `max_answers` cap; only group `skip_balance` bypasses it, not cache hits
- **cloudflare (independent post-pass)**: top-level `cloudflare` substitutes HTTPS/A/AAAA answers inside the built-in CF ranges (`ech` / `a` / `aaaa`, each using `domain@upstream`); independent of group skip flags and balance configuration, retaining DNSSEC guards and failure fallback
- **Cache**: LRU with configurable capacity and TTL clamping; per-entry TTL expiry via moka (no stale serving)
- **Connection pool**: shared connections, address rotation, per-IP exponential backoff, address-family preference
- **File sources**: `groups` / `hosts` support `file://` sources, auto-reloaded on change via `notify`
- **systemd notify**: sends `READY=1` once all listeners are bound (`Type=notify`); `systemctl reload` (SIGHUP) reopens the query log so an external logrotate can rotate/compress it (configuration is not reloaded)
- **ui**: optional built-in web status page + Prometheus `/metrics` (`ui:` config section; `/` is a mobile-friendly HTML dashboard, `/metrics` is the Prometheus text endpoint)

## Build

```bash
make build   # debug build rsdns binary (release is owned by CI/release)
# or
cargo build --bin rsdns
```

## Run

The default config file is `rsdns.yaml` (YAML; JSON also supported):

```bash
cargo run --bin rsdns -- -c rsdns.yaml
# or
./target/debug/rsdns --config rsdns.yaml
```

Full example config: `example/rsdns-all-example.yaml`; systemd deployment example: `example/rsdns.service`;
logrotate example: `example/rsdns.logrotate`.

## Minimal config example

```yaml
binds:
  - address: "0.0.0.0:53"
  - address: "tcp://0.0.0.0:53"

upstreams:
  - name: default
    servers:
      - address: 223.5.5.5
      - address: tls://dns.alidns.com

rules:
  - match: ""
    action: { type: forward, upstream: default }
```

Rule `qtype` accepts comma-separated uppercase names, e.g. `"A, AAAA, HTTPS"` (OR match), with surrounding whitespace allowed. Numbers, lowercase names and empty items are invalid. Missing or `ANY` matches all types. Move old `balance.cloudflare` to top-level `cloudflare`; remove `cache.skip_balance` and `pool.dns_timeout`. Group `skip_cache` alone controls ordinary cache lookup/write-back; internal DNS transport timeouts retain their 5s default.

## Upstream budgets and backoff

- Group `query_timeout` defaults to 5 seconds for the entire query and all fallback attempts.
- Group `attempt_timeout` defaults to 2 seconds per server (positive integer), including capacity/connection-lock waiting, connection establishment and DNS exchange, bounded by the remaining group budget. Applies even to a single server and in parallel mode.
- Group `cooldown` is removed. Each IP backs off for 2, 4, 8, 16, then at most 32 seconds on connection failure or faulty-connection eviction. Only a successful DNS request resets backoff, not connection establishment or backoff expiry. If all IPs back off, fail fast to group fallback. Queue timeouts and cancellation do not penalize IPs.
- One shared connection per server and the connection-establishment lock remain; disconnects evict immediately, three consecutive request timeouts evict, and losing parallel queries are cancelled without failure attribution.

## Development

```bash
make ci   # fmt + clippy + check + test
```

Common features:

- `aws-lc-rs` (default)
- `ring`
- `jemalloc` (default)
- `mimalloc`

## Documentation

- Architecture and design docs: [`docs/design/`](./docs/design/)
- E2E test notes: [`tests/e2e/README.md`](./tests/e2e/README.md)
- Benchmark script: [`tests/benchmark/run_rsdns_benchmark.sh`](./tests/benchmark/run_rsdns_benchmark.sh)

## Notes

This documentation is derived from the current `src/` implementation. If the implementation changes, treat the source code as authoritative.
