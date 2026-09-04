.PHONY: build check test lint run clean

build:
	cargo build

check:
	cargo check

test:
	cargo test

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

run:
	cargo run -- serve

clean:
	cargo clean