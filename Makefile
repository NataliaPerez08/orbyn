.PHONY: build check test lint fmt fmt-check run clean

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

run:
	cargo run -- --help

clean:
	cargo clean