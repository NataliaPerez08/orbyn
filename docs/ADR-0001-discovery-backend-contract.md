# ADR-0001 — Discovery backend contract

**Status:** Accepted · **Date:** 2026-10-13 · **Context:** ROADMAP_V2 v1.4 (Sprint 0 output)

## Decision

The existing `Collector` trait (`src/collectors/types.rs`) **is** the discovery
backend contract. We ratify it unchanged and add implementations behind it
instead of introducing a parallel `DiscoveryBackend` abstraction:

```rust
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: &ScanTarget) -> Result<Vec<Observation>>;
}
```

- **Selector:** the existing `--collector` CLI enum is the scanner selector;
  v1.4 adds a `native` variant. No separate `--scanner` flag.
- **Target validation:** `validate_target_with_policy` stays the single entry
  point for scope policy (IPv4 /16, IPv6 /48 floors, `--allow-large-cidr`
  override). Backends may refuse targets they cannot handle (e.g. native
  refuses oversized CIDR expansions) but never widen scope policy.
- **Normalization:** backends return `Observation`s; they never write to the
  store. The job model (`src/app/discovery.rs`) owns concurrency, rate
  limiting, partial-failure persistence and redaction for all backends.
- **Parity rule:** nmap remains the default collector until the native backend
  demonstrates parity **for Orbyn's use cases** (host liveness, TCP port
  state, service identification — see BASELINE_AUDIT.md §2) via recorded
  lab comparisons. Parity is per-feature, never "all of Nmap".

## Consequences

- A new backend is one file + one enum variant + tests; no core changes.
- Differences (banner-only depth, connect-based liveness) are documented
  behavior, surfaced per-feature in the parity matrix, not silent gaps.
- Nmap retirement (ROADMAP_V2 "exact conditions") is decided by the parity
  matrix, not by this ADR.
