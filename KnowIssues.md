# Known Issues

This file tracks known problems, limitations and deferred work detected while
developing Orbyn. Items are grouped by area. Severity hints: **bug** (wrong
behavior), **gap** (missing feature/limitation), **quality** (data or UX).

---

## Security & credentials

1. **NetBox token temp file can leak on error paths** — `bug` ~~FIXED~~
   The token is now streamed to curl through stdin (`-H @-`); no temp header
   file is written on any platform, so there is no file that could leak.
   (Resolved in `src/integrations/netbox.rs`.)

2. **No central secret redaction** — `gap` ~~FIXED~~
   A `Redactor` replaces known secret values (NetBox token, SNMP community)
   before they are written to logs, stderr, or persisted job records; the
   discovery and NetBox error paths are wired through it. (Resolved in
   `src/redact.rs` + `src/main.rs`.)

3. **Password authentication unsupported by design** — `gap`
   SSH/Windows collectors only support agent / identity-file auth
   (`CredentialProfile`). Password-based environments must front auth with
   `ssh-agent`. Intentional, but worth knowing.

4. **`--no-verify` disables TLS verification** — `quality` ~~FIXED~~
   Using it now prints a prominent warning that TLS verification is disabled
   and only trusted self-signed instances should be targeted. (Resolved in
   `src/main.rs`.)

5. **Token file permissions only restricted on Unix** — `quality` ~~FIXED~~
   Obsolete: the NetBox token is passed to curl through stdin (`-H @-`) and no
   token temp file is written, so file-permission differences cannot apply.
   (Resolved in `src/integrations/netbox.rs`.)

6. **SNMP community string visible in `snmpwalk` argv** — `gap`
   `src/collectors/snmp.rs` passes `-c <community>` as a process argument, so any
   local process (or `ps` output) can read it. The `Redactor` keeps it out of
   logs/DB, but argv exposure remains. (From THREAT_MODEL.md, R-1: switch to
   `snmpwalk -c @FILE` so the string never enters the argument list.)

---

## Correctness & data quality

6. **Dependency edges are order-dependent** — `bug` ~~FIXED~~
   Every `store_observations` batch (and `store.reconcile_dependencies`)
   re-derives edges from all recorded connections against the full asset
   inventory in one SQL pass, so an edge appears even when the target asset
   only lands in the inventory later in the same run. (Resolved in
   `src/store/sqlite.rs`.)

7. **EOL OS table is static** — `quality`
   `src/assessment/rules.rs` hardcodes the EOL table. OSes reach end-of-life
   continuously; a stale table silently produces stale `os.eol` findings.
   Consider data-driven rules or a clear cadence for updating
   `RULES_VERSION`.

8. **Capacity merge keeps stale values** — `bug` ~~FIXED~~
   `store_observations` now overwrites every measured capacity field with the
   latest observation: a field a later scan no longer detects is recorded as
   NULL ("unknown now") instead of silently keeping the stale value. (Resolved
   in `src/store/sqlite.rs`.)

9. **SNMP `sysDescr` stored as OS name** — `quality`
   The SNMP collector puts the full `sysDescr` string into `os_name`
   (e.g. `"Cisco IOS Software, IOSv"`). Noisy for classification/reporting.

10. **`classify_device` substring heuristics can misfire** — `quality`
    `src/collectors/classify.rs` uses loose `contains` matches (e.g. `"ios"`,
    vendor substrings). Conservative but can mislabel uncommon devices.

11. **`normalize_mac` is not strict** — `quality` ~~FIXED~~
    `domain::normalize_mac` now returns `Option<String>`: `None` when the input
    does not contain exactly 12 hex digits. Callers (`Interface::new`,
    `interface_id`, the Nmap collector) drop invalid MACs instead of persisting
    non-canonical values. (Resolved in `src/domain/mod.rs` +
    `src/collectors/nmap.rs`.)

12. **`ss`/`netstat` process parsing is format-specific** — `quality`
    `ssh.rs` `first_quoted` assumes net-snmp-like `users:(("name",pid=…,fd=…))`.
    BusyBox and other `ss` variants may not parse.

13. **Ansible exporter does not sanitize host names** — `bug` ~~FIXED~~
    `render_ansible_inventory` now applies `sanitize_name` to host names as
    well as group names, so a hostname with whitespace no longer breaks the INI
    line. (Resolved in `src/integrations/ansible.rs`.)

14. **Duplicate hostnames resolve arbitrarily** — `quality`
    `get_asset_by_hostname` uses `COLLATE NOCASE` and returns the first match;
    two assets sharing a hostname yield an arbitrary result.

15. **Mermaid node-id sanitization can collide** — `quality`
    `mermaid_node_id` replaces non-alphanumerics with `_`, so distinct ids
    (`10.0.0.1` vs `10_0_0_1`) can collapse to the same node label.

16. **DNS evidence is shallow and unbounded** — `gap`
    `deps dns` forward-resolves each hostname serially via `spawn_blocking`
    (`getaddrinfo`), no explicit timeout beyond the resolver, no CNAME-chain
    handling, and matches assets by exact hostname only.

---

## Feature gaps & deferred work

17. **Native WinRM transport** — `gap` (deferred)
    Windows host collection ships via PowerShell over OpenSSH; a native
    WS-Man/WinRM adapter remains unimplemented (ROADMAP/BACKLOG).

18. **vCenter collector/importer** — `gap` (deferred)
    Requires a SOAP/session client; intentionally deferred to a follow-up.

19. **Metric samples are not persisted** — `gap`
    `store_observations` logs `"observation type not yet persisted"` for
    `Observation::MetricSample`. CPU/RAM utilization and right-sizing are v1.2.

20. **NetBox import is minimal** — `gap`
    Only devices + virtual-machines (primary IP) are imported. Interfaces/MACs
    (`dcim/interfaces`), `ipam/ip-addresses` (dns_name) and export-to-NetBox are
    not implemented.

21. **Import drops interfaces/services** — `gap`
    `orbyn import` (JSON/CSV) only imports assets; interfaces and services that
    `orbyn export` emits are silently discarded on round-trip.

22. **`export --format table` removed** — `quality`
    v1.1 narrowed `export` to `json|csv|ansible|terraform`; the old `table`
    form is gone (a small breaking change vs v0.5).

23. **Ansible YAML inventory unsupported** — `gap`
    Only the INI inventory format is exported.

24. **Terraform export is a locals map only** — `gap`
    `os_name`/`os_version`/`first_seen`/`last_seen` are not included, and there
    is no `import`-block generation.

25. **No PostgreSQL backend** — `gap`
    The `Store` trait exists but only `SqliteStore` is implemented.

26. **No CI pipeline** — `gap` ~~FIXED~~
    `.github/workflows/ci.yml` runs `fmt`, `clippy -D warnings`, `build`,
    `test` and a release build on push/PR; `.github/workflows/release.yml`
    publishes tag builds with checksums.

---

## Performance & scale

27. **N+1 queries in assess/export** — `quality`
    `assessment_input` and `export` loop assets and issue per-asset list calls
    (`list_services`, `list_filesystems`, `get_capacity`, `list_connections`).
    Fine locally, slow on large inventories.

28. **NetBox `?limit=0` loads everything at once** — `quality`
    No pagination/`next` handling; large NetBox instances load fully into
    memory and may hit server limits.

29. **Discovery is single-shot, no concurrency** — `gap`
    One target per run; no parallel collectors, scheduling, or rate limiting.

---

## CLI & miscellaneous

30. **`annotate` cannot unset environment/owner/criticality** — `gap`
    `AssetAnnotations` treats `None` as "keep", so there is no way to clear a
    value; only tags are removable via `--remove-tag`.

31. **Job outcome only stores asset/service counts** — `quality`
    `finish_job` persists `assets_found`/`services_found`; filesystem, running
    service and connection counts appear in the CLI summary but are not stored.

32. **E2E tests are Unix-only** — `quality`
    The fake collector binaries are bash scripts and the E2E tests are
    `#[cfg(unix)]`; Windows development has no automated coverage.

33. **Naming inconsistency for host services** — `quality` ~~FIXED~~
    The `running_services` table column was labeled "Unit" while the domain
    type is `RunningService` and the command is `host-services`. The header is
    now "Service". (Resolved in `src/output/mod.rs`.)

34. **Import with duplicate IPs is last-wins** — `quality` ~~FIXED~~
    `persist_imported_assets` now deduplicates rows by IP (first occurrence
    wins) via `orbyn::import::deduplicate` and warns about skipped duplicates.
    (Resolved in `src/import.rs` + `src/main.rs`.)

35. **Magic strings for DNS evidence** — `quality`
    DNS edges use `proto: "dns"` / `port: 0` and are excluded via literal
    `evidence_source != "dns"` in `dep.hub`, `dep.unconfirmed` and grouping.
    Fragile if more evidence kinds need the same treatment.
