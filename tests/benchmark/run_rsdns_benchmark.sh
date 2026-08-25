#!/usr/bin/env bash
# rsdns 性能基准脚本
#
# 对 rsdns 做并发性能测试，对比 UDP / TCP / DoT / DoH / DoH3 / DoQ 多种上游格式；
# 每个上游用 dnspyre 分别以 UDP 与 TCP 两种客户端传输（--tcp）访问 rsdns，
# 并在表头/表格中标注每个上游的实际地址。
# 设计文档: docs/design/2026-08-20-rsdns-benchmark.md
#
# 用法:
#   ./tests/benchmark/run_rsdns_benchmark.sh \
#       --rsdns <path-to-rsdns-binary> \
#       --dnspyre <path-to-dnspyre-binary> \
#       [--domains <domain-list-file>] \
#       [--duration 30s] [--concurrency 32] \
#       [--protocols udp,dot,doh,doh3] \
#       [--port 15353] [--outdir benchmark-results]
#
# 输出:
#   <outdir>/result-<proto>-<udp|tcp>.json   dnspyre 原始 JSON
#   <outdir>/result-<proto>-<udp|tcp>.csv    dnspyre 直方图 CSV
#   <outdir>/results.json                    汇总 JSON
#   stdout 打印 Markdown 摘要表格
#
# 说明:
#   - 通过 cache.size: 0（moka 容量 0 = map 整体禁用）彻底关闭缓存，
#     规则再叠加 cache: false 双保险；查询路径不触达缓存。
#   - rsdns 同时监听 UDP 与 TCP（同端口），dnspyre 分别用 UDP / TCP（--tcp）
#     客户端传输测试；上游依次切换各种协议。
#   - 任一协议失败不影响其余协议，失败行标记 ❌。

set -euo pipefail

RSDNS_BIN=""
DNSPYRE_BIN=""
DOMAINS_FILE=""
DURATION="30s"
CONCURRENCY="32"
PROTOCOLS="doh,doh3,udp,tcp,dot,quic"
PORT="15353"
OUTDIR="benchmark-results"
# dnspyre 客户端传输：UDP（默认）与 TCP（--tcp）
CLIENT_TRANSPORTS="udp tcp"

usage() {
  sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

# 返回各上游协议对应的上游地址（供表头/表格展示）
# dns.alidns.com, 1.1.1.1
upstream_of() {
  case "$1" in
    udp)  echo "udp://1.1.1.1" ;;
    tcp)  echo "tcp://1.1.1.1" ;;
    dot)  echo "tls://1.1.1.1" ;;
    doh)  echo "https://1.1.1.1/dns-query" ;;
    doh3) echo "h3://1.1.1.1/dns-query" ;;
    quic) echo "quic://1.1.1.1:853" ;;
    *)    echo "" ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --rsdns) RSDNS_BIN="$2"; shift 2 ;;
    --dnspyre) DNSPYRE_BIN="$2"; shift 2 ;;
    --domains) DOMAINS_FILE="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --protocols) PROTOCOLS="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --outdir) OUTDIR="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$RSDNS_BIN" ] || { echo "error: --rsdns required" >&2; usage; }
[ -n "$DNSPYRE_BIN" ] || { echo "error: --dnspyre required" >&2; usage; }
[ -x "$RSDNS_BIN" ] || { echo "error: rsdns binary not executable: $RSDNS_BIN" >&2; exit 1; }
[ -x "$DNSPYRE_BIN" ] || { echo "error: dnspyre binary not executable: $DNSPYRE_BIN" >&2; exit 1; }

if [ -n "$DOMAINS_FILE" ]; then
  [ -f "$DOMAINS_FILE" ] || { echo "error: domain list not found: $DOMAINS_FILE" >&2; exit 1; }
  QUERY_ARG="@$DOMAINS_FILE"
else
  # 默认查询集：公开真实域名列表，覆盖多种 TLD/长度
  QUERY_ARG="example.com"
fi

mkdir -p "$OUTDIR"
PROTO_LIST="$(echo "$PROTOCOLS" | tr ',' ' ')"

# 打印表头
{
  echo "## rsdns benchmark 结果"
  echo ""
  echo "- rsdns: \`$RSDNS_BIN\`"
  echo "- 并发: \`$CONCURRENCY\`, 时长/上游/传输: \`$DURATION\`"
  if [ -n "$DOMAINS_FILE" ]; then
    echo "- 负载: dnspyre / @$DOMAINS_FILE, qtype=A, 缓存已禁用"
  else
    echo "- 负载: dnspyre / example.com, qtype=A, 缓存已禁用"
  fi
  echo "- dnspyre 客户端传输: UDP 与 TCP（--tcp）分别压测"
  echo ""
  echo "| 上游协议 | 上游地址 | 客户端传输 | QPS | 平均(ms) | p50(ms) | p95(ms) | p99(ms) | 最大(ms) | IO错误 | DNS错误 | 状态 |"
  echo "|---------|---------|-----------|-----:|--------:|--------:|--------:|--------:|---------:|-------:|--------:|------|"
}

ROW_JSON='{}'
for proto in $PROTO_LIST; do
  upstream="$(upstream_of "$proto")"
  if [ -z "$upstream" ]; then
    echo "::warning::unknown protocol $proto, skipped" >&2
    continue
  fi

  cfg="$OUTDIR/rsdns-$proto.yaml"
  cat > "$cfg" <<YAML
binds:
  - address: "0.0.0.0:${PORT}"
  - address: "tcp://0.0.0.0:${PORT}"
upstreams:
  - name: bootstrap
    servers:
      - address: 223.5.5.5
  - name: default
    servers:
      - address: ${upstream}
        pool:
          prefer_family: ipv4
cache:
  size: 0
rules:
  - action:
      type: forward
      upstream: default
      cache: false
YAML

  echo "::group::benchmark $proto (upstream=$upstream)" >&2
  "$RSDNS_BIN" --config "$cfg" > "$OUTDIR/rsdns-$proto.log" 2>&1 &
  RSDNS_PID=$!

  # 就绪探测：最多 30s，每 1s 一次（UDP）
  READY=0
  for _ in $(seq 1 30); do
    if "$DNSPYRE_BIN" --server "127.0.0.1:${PORT}" \
         --number 1 --concurrency 1 --type A \
         --json --silent example.com >/dev/null 2>&1; then
      READY=1
      break
    fi
    sleep 1
  done

  if [ "$READY" -ne 1 ]; then
    echo "::error::$proto rsdns 未就绪" >&2
    kill "$RSDNS_PID" 2>/dev/null || true
    wait "$RSDNS_PID" 2>/dev/null || true
    ROW_JSON=$(echo "$ROW_JSON" | jq --arg p "$proto" '.[$p] = {"status":"failed"}')
    printf "| %s | %s | - | - | - | - | - | - | - | - | - | ❌ |\n" "$proto" "$upstream"
    echo "::endgroup::" >&2
    continue
  fi

  # 同一上游分别用 UDP / TCP 客户端传输压测
  for transport in $CLIENT_TRANSPORTS; do
    transport_flag=()
    [ "$transport" = "tcp" ] && transport_flag=(--tcp)
    suffix="$proto-$transport"
    set +e
    "$DNSPYRE_BIN" \
      --server "127.0.0.1:${PORT}" \
      --duration "$DURATION" \
      --concurrency "$CONCURRENCY" \
      --type A \
      --json \
      --csv "$OUTDIR/result-$suffix.csv" \
      "${transport_flag[@]}" \
      $QUERY_ARG > "$OUTDIR/result-$suffix.json" 2>"$OUTDIR/dnspyre-$suffix.err"
    RC=$?
    set -e

    if [ "$RC" -ne 0 ] || ! jq -e . "$OUTDIR/result-$suffix.json" >/dev/null 2>&1; then
      echo "::error::$suffix dnspyre 失败 (rc=$RC): $(tail -2 "$OUTDIR/dnspyre-$suffix.err" || true)" >&2
      ROW_JSON=$(echo "$ROW_JSON" | jq --arg p "$proto" --arg t "$transport" '.[$p][$t] = {"status":"failed"}')
      printf "| %s | %s | %s | - | - | - | - | - | - | - | - | ❌ |\n" "$proto" "$upstream" "$transport"
      continue
    fi

    # dnspyre --json 字段: queriesPerSecond, latencyStats.{minMs,meanMs,maxMs,p50Ms,p95Ms,p99Ms},
    # totalIOErrors, totalErrorResponses
    R=$(jq -r '
      [.queriesPerSecond,
       .latencyStats.meanMs, .latencyStats.p50Ms, .latencyStats.p95Ms, .latencyStats.p99Ms,
       .latencyStats.maxMs, .totalIOErrors, .totalErrorResponses] | @tsv
      ' "$OUTDIR/result-$suffix.json")
    read -r QPS AVG P50 P95 P99 MAX IOERR DNSERR <<< "$R"
    printf "| %s | %s | %s | %.1f | %.2f | %.2f | %.2f | %.2f | %.2f | %s | %s | ✅ |\n" \
      "$proto" "$upstream" "$transport" "$QPS" "$AVG" "$P50" "$P95" "$P99" "$MAX" "$IOERR" "$DNSERR"

    ROW_JSON=$(echo "$ROW_JSON" | jq --arg p "$proto" --arg t "$transport" \
      --arg qps "$QPS" --arg avg "$AVG" --arg p50 "$P50" --arg p95 "$P95" --arg p99 "$P99" \
      --arg max "$MAX" --arg io "$IOERR" --arg dns "$DNSERR" \
      '.[$p][$t] = {"status":"ok","qps":($qps|tonumber),"avg_ms":($avg|tonumber),"p50_ms":($p50|tonumber),"p95_ms":($p95|tonumber),"p99_ms":($p99|tonumber),"max_ms":($max|tonumber),"io_errors":($io|tonumber),"dns_errors":($dns|tonumber)}')
  done

  kill "$RSDNS_PID" 2>/dev/null || true
  wait "$RSDNS_PID" 2>/dev/null || true
  echo "::endgroup::" >&2
done

echo "$ROW_JSON" | jq . > "$OUTDIR/results.json"
{
  echo ""
  echo "原始数据见 \`$OUTDIR/\`（results.json / result-*.json / result-*.csv）"
}
