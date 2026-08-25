#!/bin/bash
set -euo pipefail

echo "=========================================="
echo "rsdns E2E Tests"
echo "=========================================="
echo ""

echo "Checking dependencies..."
if ! command -v go &> /dev/null; then
    echo "Error: Go not installed"
    exit 1
fi

if ! command -v cargo &> /dev/null; then
    echo "Error: Cargo not installed"
    exit 1
fi

echo "✓ Dependencies OK"
echo ""

cd "$(dirname "$0")"

echo "Building test runner..."
go build -o test_runner . || exit 1
echo "✓ Test runner built"
echo ""

echo "Starting rsdns tests..."
echo "  RSDNS_UPSTREAM_UDP  = ${RSDNS_UPSTREAM_UDP:-1.1.1.1}"
echo "  RSDNS_UPSTREAM_DOT  = ${RSDNS_UPSTREAM_DOT:-<unset>}"
echo "  RSDNS_UPSTREAM_DOH  = ${RSDNS_UPSTREAM_DOH:-<unset>}"
echo "  RSDNS_UPSTREAM_DOH3 = ${RSDNS_UPSTREAM_DOH3:-<unset>}"
echo "  RSDNS_UPSTREAM_TCP  = ${RSDNS_UPSTREAM_TCP:-<unset>}"
echo "  RSDNS_UPSTREAM_DOQ  = ${RSDNS_UPSTREAM_DOQ:-<unset>}"
echo "=========================================="
./test_runner -v

EXIT_CODE=$?

rm -f test_runner
exit $EXIT_CODE
