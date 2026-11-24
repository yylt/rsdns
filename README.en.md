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
- Group `cooldown` is removed. Each IP backs off for 2, 4, 8, 16, then at most 32 seconds on connection failure or faulty-connection eviction. Only a valid DNS response other than SERVFAIL/REFUSED resets backoff, not connection establishment or backoff expiry. If all IPs back off, fail fast to group fallback. Queue/connection-lock wait timeouts and cancellation do not penalize IPs.
- Every SERVFAIL/REFUSED response triggers fallback to other servers in the group: serial/random/roundrobin try the next server, while parallel keeps waiting for another server. No additional DNS resend is made within the same server attempt. If all servers fail or the group budget expires, forward returns SERVFAIL, not the last REFUSED, without trying subsequent rules.
- One shared connection per server and the connection-establishment lock remain. Disconnects evict and back off immediately. Within one connection generation, DNS exchange timeouts, SERVFAIL and REFUSED share a consecutive-failure counter in completion order; 3 consecutive failures evict the connection and back off its IP:port. Other valid responses (including NXDOMAIN, empty NoError and FORMERR) reset the counter and address backoff. Cancellation and queue/lock wait timeouts do not count; late results from an old generation do not affect current connection health.

## Upstream metrics

The built-in UI's upstream section and `/metrics` expose complementary counters:

| Metric | Meaning |
|--------|---------|
| `rsdns_upstream_response_failures_total{upstream,proto,rcode}` | Counts every SERVFAIL/REFUSED actually received during a server attempt; `rcode` is limited to `SERVFAIL` / `REFUSED`. Later successful group fallback does not hide the failure. Actual failure responses from old generations still count without affecting current health. `upstream` retains the pool identity; no IP/domain labels are added. |
| `rsdns_upstream_rcode_total{upstream,rcode}` | Valid DNS responses finally returned by the group, not individual server responses. |
| `rsdns_upstream_error_total{upstream,kind}` | Final group failures; successful fallback does not increment this counter. |

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
