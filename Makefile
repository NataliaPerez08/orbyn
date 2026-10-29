.PHONY: build check test lint fmt fmt-check audit fuzz-smoke bench run clean windows-smoke windows-scan-smoke

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

bench:
	scripts/bench.sh

fuzz-smoke:
	cargo +nightly fuzz run import -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run nmap_xml -- -runs=1000 -max_len=16384
	cargo +nightly fuzz run parsing -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run sanitize -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run netbox_origin -- -runs=1000 -max_len=4096
	cargo +nightly fuzz run device_output -- -runs=1000 -max_len=8192
	cargo +nightly fuzz run structural -- -runs=1000 -max_len=4096

run:
	cargo run -- --help

# Functional tests for the Windows executable. Cross-compiles the GNU target
# (mingw) and runs scripts/windows-smoke.sh under Wine. On Windows, point
# ORBYN_WINE= at the native .exe instead.
windows-smoke:
	cargo build --release --target x86_64-pc-windows-gnu
	ORBYN_EXE=target/x86_64-pc-windows-gnu/release/orbyn.exe scripts/windows-smoke.sh

# Functional discovery tests: the real native sweep against live listeners and
# the local segments (loopback CIDR + eth0 /24). Slower than windows-smoke
# (~2 min for the /24); needs python3 for the target listeners.
windows-scan-smoke:
	cargo build --release --target x86_64-pc-windows-gnu
	ORBYN_EXE=target/x86_64-pc-windows-gnu/release/orbyn.exe scripts/windows-scan-smoke.sh

clean:
	cargo clean
