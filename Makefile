.PHONY: build fmt test check clippy ci

build:
	cargo build --bin rsdns

fmt:
	cargo fmt

test:
	cargo test

check:
	cargo build

clippy:
	cargo clippy --all-targets -- -D warnings

ci: fmt clippy check test
	@echo "CI: all checks passed"
