.PHONY: build check test lint fmt fmt-check audit fuzz-smoke run clean

build:
	cargo build

check:
	cargo check

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

audit:
	cargo audit

fuzz-smoke:
	cargo +nightly fuzz run import -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run nmap_xml -- -runs=1000 -max_len=16384
	cargo +nightly fuzz run parsing -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run sanitize -- -runs=1000 -max_len=4096

run:
	cargo run -- --help

clean:
	cargo clean
