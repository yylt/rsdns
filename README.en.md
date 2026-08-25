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
- **Query pipeline**: `hosts → groups → cache → rules`; unmatched queries fall back to NXDOMAIN/SERVFAIL
- **Rules**: `block` (NXDomain or poison IP), `cname` (rewrite + recursive resolve), `forward` (named upstream pool, optional TTL override / resolve_cname), `rewrite` (synthesized A record)
- **Cache**: LRU with configurable capacity and TTL clamping; per-entry TTL expiry via moka (no stale serving)
- **Connection pool**: adaptive address rotation, cooldown on failure, address-family preference
- **File sources**: `groups` / `hosts` support `file://` sources, auto-reloaded on change via `notify`
- **systemd notify**: sends `READY=1` once all listeners are bound (`Type=notify`)
- **metrics**: optional Prometheus `/metrics` HTTP endpoint

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

Full example config: `example/rsdns-all-example.yaml`; systemd deployment example: `example/rsdns.service`.

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
