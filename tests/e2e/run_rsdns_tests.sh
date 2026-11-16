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

echo "Starting rsdns tests with ${RSDNS_E2E_CONFIG:-config.json}..."
echo "=========================================="
./test_runner -v -config "${RSDNS_E2E_CONFIG:-config.json}"

EXIT_CODE=$?

rm -f test_runner
exit $EXIT_CODE
