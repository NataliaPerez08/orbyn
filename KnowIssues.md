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

6. **SNMP community string visible in `snmpwalk` argv** — `gap` ~~FIXED~~
   The collector now writes a short-lived `0600` `snmp.conf` in a `0700`
   directory and points `snmpwalk` at it through `SNMPCONFPATH`; the community
   never enters the process arguments. (Resolved in `src/collectors/snmp.rs`.)

---

## Correctness & data quality

6. **Dependency edges are order-dependent** — `bug` ~~FIXED~~
   Every `store_observations` batch (and `store.reconcile_dependencies`)
   re-derives edges from all recorded connections against the full asset
   inventory in one SQL pass, so an edge appears even when the target asset
   only lands in the inventory later in the same run. (Resolved in
   `src/store/sqlite.rs`.)

7. **EOL OS table is static** — `quality` ~~FIXED~~
   The table now lives in `src/assessment/eol_os.csv` (data, not code),
   embedded at build time and parsed with loud failure on malformed input;
   the `EOL table version` evidence is derived from the file itself. The
   update cadence is documented in CONTRIBUTING.md and enforced by a unit
   test that fails when the version is more than six months old.
   (Resolved in `src/assessment/rules.rs` + `src/assessment/eol_os.csv`.)

8. **Capacity merge keeps stale values** — `bug` ~~FIXED~~
   `store_observations` now overwrites every measured capacity field with the
   latest observation: a field a later scan no longer detects is recorded as
   NULL ("unknown now") instead of silently keeping the stale value. (Resolved
   in `src/store/sqlite.rs`.)

9. **SNMP `sysDescr` stored as OS name** — `quality` ~~FIXED~~
   The raw `sysDescr` banner is kept in its own `sys_descr` field (migration
   `0006_sys_descr.sql`), and `os_name` is derived via
   `derive_os_from_sysdescr()`: known vendor/OS families map to concise names
   (e.g. `"Cisco IOS"`, `"Juniper Junos"`) and unrecognized banners fall back
   to the first comma-separated segment, trimmed and capped at 80 characters.
   (Resolved in `src/collectors/snmp.rs` + `src/domain/mod.rs`.)

10. **`classify_device` substring heuristics can misfire** — `quality` ~~FIXED~~
    Short needles now match on word boundaries through `contains_word()`
    (`"ios"` no longer fires inside `"bios"`/`"radios"`), and short vendor
    names get a word-boundary check on `descr` in addition to the substring
    match. (Resolved in `src/collectors/classify.rs`.)

11. **`normalize_mac` is not strict** — `quality` ~~FIXED~~
    `domain::normalize_mac` now returns `Option<String>`: `None` when the input
    does not contain exactly 12 hex digits. Callers (`Interface::new`,
    `interface_id`, the Nmap collector) drop invalid MACs instead of persisting
    non-canonical values. (Resolved in `src/domain/mod.rs` +
    `src/collectors/nmap.rs`.)

12. **`ss`/`netstat` process parsing is format-specific** — `quality` ~~FIXED~~
    The parser accepts the known row shapes with fixture coverage: `ss`
    `ESTAB`/`ESTABLISHED` with and without `users:` process metadata,
    `LISTEN`/`UNCONN` rows from `ss` builds that ignore the state filter,
    plain `netstat -tn`, and the `netstat -p` process column in both the
    BusyBox `pid/prog` and net-tools `pid/prog:name` forms (`-` unavailable),
    including bare-IPv6 and IPv4-mapped endpoints. (Resolved in
    `src/collectors/ssh.rs`.)

13. **Ansible exporter does not sanitize host names** — `bug` ~~FIXED~~
    `render_ansible_inventory` now applies `sanitize_name` to host names as
    well as group names, so a hostname with whitespace no longer breaks the INI
    line. (Resolved in `src/integrations/ansible.rs`.)

14. **Duplicate hostnames resolve arbitrarily** — `quality` ~~FIXED~~
    `get_asset_by_hostname` now orders duplicate case-insensitive matches by
    stable asset id before returning one, making resolution deterministic.

15. **Mermaid node-id sanitization can collide** — `quality` ~~FIXED~~
    Mermaid IDs retain a readable sanitized prefix and append an encoding of
    the original id, so distinct ids cannot collapse after sanitization.

16. **DNS evidence is shallow and unbounded** — `gap` ~~FIXED~~
    Resolution keeps the five-second timeout, de-duplication and the
    64-address cap, and the evidence is no longer shallow: `dig +short`
    (when available, with a `getaddrinfo` fallback for hosts only present in
    local sources) captures CNAME chains, so a hostname aliasing another
    asset's hostname produces an edge even when the final addresses are
    unmanaged; reverse (PTR) resolution of each asset IP adds IP-based
    matching. All matching is exact and case-insensitive, edges stay
    low-confidence and deduplicated per asset pair. (Resolved in
    `src/collectors/dns.rs` + `src/main.rs`.)

---

## Feature gaps & deferred work

17. **Native WinRM transport** — `gap` (deferred)
    Windows host collection ships via PowerShell over OpenSSH; a native
    WS-Man/WinRM adapter remains unimplemented (ROADMAP/BACKLOG).

18. **vCenter collector/importer** — `gap` (deferred)
    Requires a SOAP/session client; intentionally deferred to a follow-up.

19. **Metric samples are only collected on demand** — ~`gap`~ **FIXED**
    ~`store_observations` logs `"observation type not yet persisted"` for
    `Observation::MetricSample`. CPU/RAM utilization and right-sizing are v1.2.~
    Snapshot sampling ships as part of discovery (3 samples per SSH probe);
    `orbyn metrics` aggregates avg/p95/p99/peak with a confidence label.
    Periodic *scheduling* of metric collection remains a follow-up.

20. **NetBox import is minimal** — `gap` ~~FIXED~~
    `orbyn netbox import` now also pulls `dcim/interfaces` and
    `virtualization/interfaces` (name, MAC, MTU, enabled) plus
    `ipam/ip-addresses`, attaching each assigned IP to its interface and
    using `dns_name` as the hostname fallback for devices NetBox does not
    name. Export-to-NetBox stays out by design: Orbyn is read-only against
    NetBox (it is a source of truth, not a target). (Resolved in
    `src/integrations/netbox.rs`.)

21. **Import drops interfaces/services** — `gap` ~~FIXED~~
    `orbyn import` now round-trips full exports: the CSV path parses the
    `#interfaces` and `#services` worksheets alongside `#assets`, and the
    JSON path accepts the `{"assets": [...], "interfaces": [...],
    "services": [...]}` object emitted by `orbyn export --format json`.
    `asset_id` references in IP form resolve to the canonical asset id, and
    interface/service rows referencing an asset that is neither part of the
    import nor already in the inventory are skipped with a warning instead
    of failing. (Resolved in `src/import.rs` + `src/main.rs`.)

22. **`export --format table` removed** — `quality`
    v1.1 narrowed `export` to `json|csv|ansible|terraform`; the old `table`
    form is gone (a small breaking change vs v0.5).

23. **Ansible YAML inventory unsupported** — `gap` ~~FIXED~~
    `orbyn export --format ansible-yaml` renders the same grouped inventory
    as the INI format in Ansible's YAML layout
    (`all.children.<group>.hosts`), sharing the grouping code so the two
    formats cannot drift. (Resolved in `src/integrations/ansible.rs`.)

24. **Terraform export is a locals map only** — `gap` ~~FIXED~~
    The `locals` map now carries every supported metadata field
    (`os_name`, `os_version`, `first_seen`, `last_seen`), and
    `--tf-import <resource-type>` scaffolds one `import` block per asset
    (Terraform >= 1.5) addressed `<type>.<host>`, with the provider
    resource id left as a visible TODO placeholder. (Resolved in
    `src/integrations/terraform.rs`.)

25. **No PostgreSQL backend** — `gap`
    ~~FIXED~~
    `PostgresStore` (`src/store/postgres.rs`) implements the full `Store`
    contract over `sqlx`'s PostgreSQL driver: `--db`/`ORBYN_DB` accept any
    `postgres://`/`postgresql://` URL (filesystem paths keep selecting
    SQLite), the schema lives in `migrations/postgres/` and is applied
    automatically on open, and row decoding is shared with SQLite through
    `src/store/rows.rs`. TLS is negotiated when the server offers it
    (`?sslmode=require` enforces it). Coverage: `tests/postgres_store.rs`
    runs a six-test suite (round-trip of every observation kind, bulk reads,
    dependency confirm/remove, annotations, jobs/audit, metric limits)
    against a live database when `ORBYN_PG_TEST_URL` is set, and CI runs it
    against a `postgres:16` service container.

26. **No CI pipeline** — `gap` ~~FIXED~~
    `.github/workflows/ci.yml` runs `fmt`, `clippy -D warnings`, `build`,
    `test` and a release build on push/PR; `.github/workflows/release.yml`
    publishes tag builds with checksums.

---

## Performance & scale

27. **N+1 queries in assess/export** — `quality` ~~FIXED~~
    The store gained bulk reads (`list_all_services`,
    `list_all_interfaces`, `list_all_filesystems`, `list_all_capacities`,
    `list_all_connections`): one query per table instead of one per asset.
    `assess` and `export` use them; per-asset reads remain for the
    single-asset commands. (Resolved in `src/store/sqlite.rs`.)

28. **NetBox `?limit=0` loads everything at once** — `quality` ~~FIXED~~
    Imports now follow paginated `next` links with page, record and response
    size limits. (Resolved in `src/integrations/netbox.rs`.)

29. **Discovery is single-shot, no concurrency** — `gap` ~~FIXED~~
    `--target` is repeatable and targets run on a bounded worker pool:
    `--concurrency N` (default 4) caps parallel scans and `--rate-limit N`
    paces launches per second. One job records every target; observations
    from successful targets persist even when others fail (the job is then
    Failed with the per-target errors). (Resolved in `src/main.rs`.)

---

## CLI & miscellaneous

30. **`annotate` cannot unset environment/owner/criticality** — `gap` ~~FIXED~~
    `orbyn annotate --unset <field>` (repeatable: environment | owner |
    criticality) clears annotation fields; unsetting wins over setting the
    same field in one invocation. (Resolved in `src/store/traits.rs` +
    `src/store/sqlite.rs`.)

31. **Job outcome only stores asset/service counts** — `quality` ~~FIXED~~
    Discovery jobs now persist `filesystems_found`,
    `running_services_found` and `connections_found` alongside
    assets/services (migration `0007`), and `orbyn jobs` renders them in
    table and CSV output. (Resolved in `src/domain/mod.rs` +
    `src/store/sqlite.rs`.)

32. **E2E tests are Unix-only** — `quality` ~~FIXED~~
    CI now runs a `windows-latest` job (`build` + `test`): the shell-script
    E2E fakes compile empty on Windows, while the unit and store smoke
    suites provide automated Windows coverage. Full E2E parity would need
    PowerShell fakes and stays out of scope. (Resolved in
    `.github/workflows/ci.yml` + `tests/common/mod.rs`.)

33. **Naming inconsistency for host services** — `quality` ~~FIXED~~
    The `running_services` table column was labeled "Unit" while the domain
    type is `RunningService` and the command is `host-services`. The header is
    now "Service". (Resolved in `src/output/mod.rs`.)

34. **Import with duplicate IPs is last-wins** — `quality` ~~FIXED~~
    `persist_imported_assets` now deduplicates rows by IP (first occurrence
    wins) via `orbyn::import::deduplicate` and warns about skipped duplicates.
    (Resolved in `src/import.rs` + `src/main.rs`.)

35. **Magic strings for DNS evidence** — `quality` ~~FIXED~~
    `domain::EvidenceKind` is now the single point of truth for the
    evidence values Orbyn produces (`active-connections`, `dns`, `manual`),
    and `Dependency::evidence_kind()` replaces the scattered
    `evidence_source != "dns"` / `proto == "dns"` literals in assessment
    rules, grouping and rendering. The reconcile SQL literal is pinned to
    the canonical value by a test. (Resolved in `src/domain/mod.rs`.)

---

## Security review findings

36. **NetBox pagination URL validation is prefix-based** — `bug`, **high**
    ~~FIXED~~
    `next` URLs are now parsed with a strict origin grammar
    (`src/integrations/netbox.rs::url_origin`: http/https only, no
    userinfo, reg-name or bracketed IPv6 hosts, normalized default ports)
    and must match the base URL's exact origin — `https://netbox.example.com.evil`
    and `https://netbox.example.com@evil` no longer pass. The base `--url`
    itself is validated the same way at client construction. Regression
    coverage: hostile-`next` unit tests plus an E2E test asserting the
    hostile URL is never requested.

37. **Sequential subprocess pipe reads can deadlock** — `bug`, **high**
    ~~FIXED~~
    All subprocess call sites (nmap, ssh, snmpwalk, curl) now run through
    `src/process.rs::run_captured`: stdout and stderr are read (and the
    optional stdin payload written) concurrently via `tokio::join!`, one
    timeout bounds the complete process lifecycle, and the child is killed
    and reaped on expiry. Nmap gained a 1800 s default timeout, overridable
    with `ORBYN_NMAP_TIMEOUT_SECS`. Regression coverage: a stderr-flood
    child that deadlocked the old code now completes, and a hanging child
    is killed at the timeout.

38. **Secrets can be exposed in Orbyn's own argv** — `gap`, **medium**
    ~~FIXED~~
    `--community` now falls back to `ORBYN_SNMP_COMMUNITY` through clap
    (matching `--token`), both flags accept the literal `-` to read one line
    from stdin so credentials can be kept off the command line entirely, and
    the discovery path registers CLI/stdin-supplied values with the
    `Redactor` before persisting or printing job failures. E2E coverage:
    stdin-sourced secrets reach the collectors (`snmp.conf`, curl
    `Authorization` header) and never appear in output or child argv; a
    failing walk proves CLI values are redacted.

39. **SNMP temporary configuration can survive abrupt termination** —
    `quality`, **low**
    ~~FIXED~~
    The first SNMP walk of a process removes stale `orbyn-snmp-<uuid>`
    directories (best effort): exact-name match, current-user ownership on
    Unix, and an age gate of one hour — far above the 30 s walk timeout — so
    a concurrently running Orbyn never loses its live config. Unit coverage:
    stale directories are removed, fresh ones survive, and unrelated names
    are untouched.
