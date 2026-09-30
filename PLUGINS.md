# Plugin / collector SDK

Orbyn is a single Rust crate. A **plugin** is a collector you write in Rust
and link into the CLI at compile time — there is no dynamic module loading
(dylibs). The SDK is the public, documented surface you implement.

## The collector contract

Implement `orbyn::collectors::Collector`:

```rust
use async_trait::async_trait;
use anyhow::Result;
use orbyn::collectors::{Collector, ScanTarget};
use orbyn::domain::Observation;

struct MyCollector;

#[async_trait]
impl Collector for MyCollector {
    fn name(&self) -> &'static str {
        "my-collector"
    }

    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>> {
        // fetch facts, normalize them, return observations
        todo!()
    }
}
```

See `examples/custom_collector.rs` for a complete, runnable example.

## Rules a collector must follow

- **Read-only**: never modify the target system.
- **Typed output**: return normalized `orbyn::domain::Observation`s. Never
  touch the database; the store persists observations.
- **Validated, scoped targets**: accept a `ScanTarget` produced by
  `orbyn::collectors::validate_target`. Unrestricted scopes (`0.0.0.0/0`) are
  rejected by the validator.
- **Args, never shell**: if you shell out to a tool (nmap, ssh, curl, …),
  pass targets/options as process argument vectors, never as a shell string.
- **No secrets in logs/args**: use `orbyn::collectors::credentials::CredentialProfile`
  (agent / identity files) for authentication; Orbyn stores no credentials.

## The normalization vocabulary

Every collector reduces its facts to the shared domain model:

- `Asset`, `Service`, `Interface`, `Capacity`, `Filesystem`,
  `RunningService`, `Connection`, `Dependency`.

Assessment, the dependency graph, exporters (Ansible/Terraform/NetBox) and the
CLI all operate on these types, so a new collector is automatically compatible
with the rest of Orbyn.

## Wiring a collector into the CLI

Add a variant to `DiscoveryCollector` in `src/main.rs` and construct your type
in the `match collector { ... }` of the `discover` command. Bulk sources (like
NetBox) get their own subcommand instead of a `--collector` flag.

## Cloud and platform adapters

Cloud providers do not use the `Collector` trait (whose `scan` is per-target).
They implement the separate, read-only `orbyn::integrations::cloud::CloudAdapter`
contract: `fetch()` returns a `CloudInventory` (normalized assets, interfaces,
services, capacity, filesystems plus `CloudProvenance`). Proxmox VE
(`orbyn proxmox import`) and AWS (`orbyn aws import`) are the first adapters.
The shared `CurlClient` handles the curl boundary, timeouts, response caps and
retries; request headers (including credentials) are streamed on stdin. New
providers follow the Proxmox adapter and add a subcommand that calls
`fetch_inventory()` and persists through the CLI's `persist_cloud_inventory`.
