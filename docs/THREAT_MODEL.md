# Threat model

Scope: the Orbyn CLI (`orbyn` binary, crate `0.6.x`) as described in
`ARCHITECTURE.md`. This is a **single-user, local-first CLI**; it has no server,
no remote surface and no multi-user store. The document says *what* could go
wrong, *where* the trust boundaries are, and which countermeasures are already
in place versus which are open recommendations.

Method: STRIDE per trust boundary, plus a data-flow map. Reviewed for the v1.0
release on 2026-09-20.

---

## 1. Trust boundaries and data flows

```text
                        ┌────────────────────────────────────────────┐
   operator (human) ──► │  A  CLI / env / config (.env, args, stdin)  │
                        └───────────────┬────────────────────────────┘
                                        │ targets, creds (in-memory only)
                        ┌───────────────▼────────────────────────────┐
                        │                orbyn process                 │
                        │  collectors → normalization → store/assess   │
                        └───┬──────────────┬──────────────┬──────────┬─┘
                            │              │              │          │
              B subprocess  │   C resolver │   D local    │  E output│
              (nmap/snmpwalk│   (DNS via   │   persistence│ (stdout, │
              /ssh/curl)    │   getaddrinfo│   SQLite db) │  stderr, │
              └→ remote     │              │              │  exports)│
                 hosts/API  │              │              │          │
```

- **Boundary A — operator input**: `--db`, `--target`, annotations, import
  stdin, environment variables (`ORBYN_*`), and the optional `.env` file.
- **Boundary B — external tools & remotes**: `nmap`, `snmpwalk`, `ssh`, `curl`,
  `dig` (paths configurable via `ORBYN_*_BIN`); remote SNMP agents, SSH servers
  and the NetBox HTTP API. Their stdout/stderr is parsed into observations.
- **Boundary C — system resolver**: `orbyn deps dns` resolves hostnames via
  `dig +short` when available (capturing CNAME chains and PTR records) and
  falls back to `getaddrinfo` (blocking pool) otherwise. Hostnames are only
  passed to `dig` as argv elements when they cannot be mistaken for options.
- **Boundary D — persistence**: the SQLite database file plus job audit rows.
- **Boundary E — output**: stdout tables/JSON/CSV, stderr logs, exporter output
  files, Mermaid graphs.

Assets that matter:

| Asset | Where it lives |
|---|---|
| Discovery/import credentials (NetBox/Prometheus/Zabbix tokens, SNMP community, WinRM password, Proxmox token, AWS access/secret/session keys, Huawei AK/SK) | process memory; env & `.env`; temporary restricted config during SNMP execution; signed headers or stdin config streamed to curl |
| SSH identity (path only, never key bytes) | `CredentialProfile.identity_file` |
| Inventory truth (assets, services, deps, annotations) | SQLite db + stdout exports |
| Audit history (jobs, mutating operations, failures, reasons) | SQLite db |
| Scan scope authorized by the operator | target args on the command line |

---

## 2. STRIDE analysis by boundary

### A — Operator input (env, args, stdin)

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| A-1 Attacker with write access to `~/.bashrc`, env or `.env` redirects `ORBYN_NMAP_BIN`/`ORBYN_SSH_BIN`/… to a malicious binary | Tampering | Higher than it looks: every collector binary path is env-driven. Whoever controls env controls what runs — with the operator's stored credentials (ssh-agent, keys). | Documented; binaries run as the invoking user. **Residual**: no path pinning/allow-list. Operator must protect their shell environment and PATH. |
| A-2 A `--target` containing shell metacharacters triggers command injection | RCE | Addressed by design: targets are passed as **argument vectors** to `Command::new(...)`; no shell string is ever built. The only shell-free string is the fixed `LINUX_PROBE` constant. | Present: args not shell (`nmap.rs:57`, `ssh.rs`, `snmp.rs:175`, `netbox.rs:192`). Old-style `sh -c` absent. |
| A-3 A malicious import CSV/JSON injects fields (hostnames, tags) that break queries or exports | Tampering/DoS | CSV/JSON parsing never concatenates SQL; store uses parameterized `sqlx` queries. | Present: parameterized SQL everywhere in `store/sqlite.rs`. |
| A-4 Secrets in env leak into error messages / job audit rows | Information disclosure | NetBox token and SNMP community are registered into `Redactor` (`src/redact.rs`) and scrubbed before logging or persisting job failures; discovery also registers CLI/stdin-supplied values so no sourcing path is left unredacted. | Present but **value-based**: any secret not pre-registered is not redacted. Keep the redactor fed from the same env vars and flags the collectors consume. |
| A-5 `.env` file stored with secrets ends up world-readable in a repo backup | Information disclosure | `.env` is git-ignored (`.gitignore`). | Present. **Residual**: file-mode hardening of `.env` is left to the OS/operator. |
| A-6 Secrets passed as `--token`/`--community`/`--winrm-password`/`--secret-key`/`--session-token` are visible in Orbyn's own argv (process inspection, shell history) | Information disclosure | All these flags fall back to env vars (`ORBYN_NETBOX_TOKEN`, `ORBYN_SNMP_COMMUNITY`, `ORBYN_WINRM_PASSWORD`, `ORBYN_PROMETHEUS_TOKEN`, `ORBYN_ZABBIX_TOKEN`, `ORBYN_PROXMOX_TOKEN`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `HUAWEICLOUD_SDK_SK`) and accept `-` to read one line from stdin, so credentials can be kept off the command line entirely; explicitly supplied CLI values are registered with the redactor. The WinRM password reaches `curl` through a stdin config file (`-K -`); AWS/Huawei signatures and the other tokens/headers travel to `curl` on stdin, never through argv. | Resolved in Phase 6; E2E coverage verifies stdin-sourced secrets reach the collectors and never appear in output or child argv (including the WinRM, Prometheus, AWS and Huawei flows). |

### B — External tools and remotes (lowest trust)

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| B-1 A compromised nmap/curl/ssh binary runs arbitrary code as the operator | RCE | These tools run with the operator's privileges and their **ssh-agent** and key material reachable. | Supply-chain reality for any CLI that shells out. Recommendations: install these tools from the OS package manager; run discovery from a dedicated low-privilege user whose ssh-agent only exposes the needed keys. |
| B-2 A malicious/Northbound NetBox server (or on-path attacker) feeds crafted JSON that deserializes into extreme or hostile records | Tampering/DoS | `serde_json` parse is bounded; fields are normalized. | Present: typed structs, paginated requests and response-size/record limits. **Residual**: `--no-verify` disables TLS hostname verification with an explicit warning (`main.rs`). |
| B-3 A remote SSH host returns poisoned output (e.g. `df`/`systemctl`/`ss` lines) | Tampering | Parsed into typed fields; numbers validated; every observation is reconciled against validated targets. | Present: parsers are tolerant + tests. **Residual**: additional BusyBox fixtures remain in KnowIssues. |
| B-4 Community string is visible in the `snmpwalk` argument list | Information disclosure | No: the community is written to a short-lived restricted `snmp.conf` selected through `SNMPCONFPATH`; it is not passed as argv. | Resolved in Phase 1; regression coverage verifies the process arguments contain neither the secret nor `-c`. |
| B-5 On-path attacker observes NetBox traffic with `--no-verify` | Spoofing/Elevation | Token is sent over TLS; `--no-verify` skips verification. | Mitigated: loud warning; default verifies. **Residual**: operator decision. |
| B-6 SSH host-key verification bypass | Spoofing/Elevation | `StrictHostKeyChecking=accept-new` is set (`ssh.rs`): keys are pinned after first connect (TOFU), later connects verify against `known_hosts`. DoS surface is limited by `ConnectTimeout=10` and a 60 s probe timeout. | Present: TOFU. **Residual**: a first-connect MITM is possible when `known_hosts` is empty; document an operator `ssh_config` (managed `KnownHostsFile`) for high-security environments. |
| B-7 A malicious NetBox server points pagination `next` at an attacker origin (`https://netbox.example.com.evil/`, `https://netbox.example.com@evil/`) to harvest the API token | Spoofing/Elevation | `next` URLs are parsed under a strict origin grammar (`url_origin`: http/https only, userinfo forbidden, default ports normalized) and must match the base URL's exact origin; the base `--url` is validated the same way at construction. | Resolved: hostile-`next` regression tests (unit + E2E asserting the URL is never requested). |
| B-8 A child tool (nmap/ssh/snmpwalk/curl) floods or blocks a pipe and hangs Orbyn forever (no timeout reached, no EOF) | DoS | All subprocess call sites run through `src/process.rs::run_captured`: stdout/stderr read (and stdin written) concurrently, one timeout bounds the complete lifecycle, the child is killed and reaped on expiry; nmap has a 1800 s default (`ORBYN_NMAP_TIMEOUT_SECS`). | Resolved: stderr-flood and hanging-child regression tests. |
| B-9 A SIGKILL skips the post-walk cleanup and leaves the SNMP community on disk in the temp `snmp.conf` | Information disclosure | The file is `0600` inside a `0700` directory; on the first SNMP walk of a process, stale `orbyn-snmp-<uuid>` directories (current-user owned on Unix, untouched for over an hour) are removed best effort. | Resolved in Phase 6; unit coverage for stale/fresh/unrelated directories. **Residual**: a window of up to the age threshold remains after a crash. |
| B-10 The WinRM transport leaks the Basic-auth password or is stalled by a hostile endpoint | Information disclosure / DoS | HTTPS only (5986 default), so credentials never travel in cleartext; the password is held in memory for the run, streamed to `curl` through a stdin config (`-K -`), never in argv, registered with the redactor and stripped from child env. Each WS-Man request has a 60 s timeout and bounded capture; the receive loop is capped (16 rounds) and the shell is deleted best-effort. `--winrm-insecure` (TLS skip) is an explicit operator opt-in mirroring `--no-verify`, with the same prominent warning. | Present: unit + E2E coverage (fake WS-Man endpoint) asserts the password reaches curl only through stdin and never appears in argv or output. **Residual**: `--winrm-insecure` with a self-signed lab certificate is an operator decision. |
| B-11 A malicious Prometheus server feeds crafted `query_range` JSON (endless matrices, hostile `instance` labels, junk points) to poison utilization windows or exhaust memory | Tampering / DoS | The bearer token travels via curl stdin (`-H @-`), never argv; the base `--url` is validated under the strict origin grammar (no userinfo). Responses are bounded (16 MiB, 60 s, 50k points/query); points that do not parse are skipped and counted, the `resultType` must be `matrix`, and series map onto assets only through an exact IP/hostname match of the `instance` label — unmatched series are reported, never guessed. Imported samples are idempotent (unique index on asset+instant), so a replayed window cannot duplicate evidence. | Present: unit + E2E coverage (fake Prometheus endpoint) asserts bounded parsing, instance mapping, idempotent re-import and secret handling. **Residual**: `--no-verify`/plain-HTTP endpoints are operator decisions (warned). |

### C — System resolver

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| C-1 DNS spoofing injects false dependency edges in `deps dns` | Spoofing/Tampering | Edges are **low-confidence (0.4)** and unconfirmed by design; they are excluded from grouping and can be `confirm`ed/removed. | Present: conservative confidence model. **Residual**: DNS evidence stays advisory, never authoritative. |

### D — Local persistence

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| D-1 A second local user reads the SQLite db (inventory is sensitive) | Information disclosure | SQLite file inherits the operator's umask; default path is `./data/orbyn.db`. | Present: documented. **Residual**: no encrypted-at-rest store; operator should keep the db private (chmod/dir perms). |
| D-2 The db file is corrupted/missing and `sqlx` auto-migrates blindly | Integrity/DoS | Migrations are compile-time embedded and idempotent; `PRAGMA foreign_keys=ON`. | Present. |
| D-3 A job audit row leaks a redacted secret in cleartext | Information disclosure | `finish_job` stores only the redacted error string. | Present: redactor applied at the write boundary (`main.rs`). |
| D-4 The PostgreSQL backend leaks the connection password (URL in argv/env, plaintext on the wire) | Information disclosure / Spoofing | Orbyn stores no database credentials; the operator-supplied URL is the only secret carrier. A URL without a password falls back to `ORBYN_PG_PASSWORD`/`PGPASSWORD` (libpq-style) so the credential need not appear in argv; a URL that embeds one warns at runtime and the value is registered with the redactor. TLS is negotiated when offered (`sslmode=prefer` default) and enforceable with `?sslmode=require`; sqlx error messages do not echo the password. | Present. **Residual**: an operator who still embeds the password in the URL keeps it in argv — use the env fallback, a least-privilege role, and certificate or password-file authentication for remote databases. |

### E — Output

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| E-1 Exported JSON/CSV/Ansible/Terraform files contain sensitive inventory committed to a repo | Information disclosure | Exports are plaintext by design. | Documented. **Residual**: operator must not commit exports; CI/secret-scanning is the operator's responsibility. |
| E-2 Logs on stderr leak a token via an unregistered value (e.g. a NetBox URL containing a token) | Information disclosure | Redactor only knows pre-registered values; URL-embedded tokens are out of scope. | Present: redactor. URL credentials (`user:pass@host`) are now forbidden input in NetBox URLs (see B-7); redacting `Authorization`-style substrings remains open. |

---

## 3. Highest-risk component

The **collector boundary (A + B)** is where capability (credentials, scanning,
network reach) meets untrusted input. Secure-coding rules that gate review:

1. Targets → argument vectors, never shell strings.
2. No `sh -c`; binary paths are the only external code executed.
3. Secrets exist in process memory only; redact before any write boundary.
4. Scope is validated (`0.0.0.0/0` rejected; prefixes below /16 IPv4 or
   /48 IPv6 require `--allow-large-cidr`) before any tool runs.
5. Collectors are read-only.
6. No credential storage (ssh-agent / key files referenced by path only).

---

## 4. Open recommendations (residual risk)

| ID | Recommendation | Effort |
|---|---|---|
| R-1 | Pass the SNMP community through a `0600` temporary `snmp.conf` selected via `SNMPCONFPATH` instead of argv | Resolved in Phase 1 |
| R-2 | Surface an SSH policy for probes in docs (managed `KnownHostsFile` for high-security envs, `IdentitiesOnly=yes` to limit agent-key negotiation) | Small |
| R-3 | Reject `--no-verify` when a custom CA/certificate pin is feasible; keep the prominent warning otherwise | Small |
| R-4 | Treat URL credentials (`https://user:pass@host`) as forbidden target/URL input | Resolved: `url_origin` rejects userinfo in NetBox base and pagination URLs |
| R-5 | NetBox pagination + response-size cap to bound malformed/large responses | Resolved in Phase 1 |
| R-6 | Publish build provenance (reproducible release artifacts + checksums) for the release workflow | Resolved and verified for the tagged `v1.0.2` release |
| R-7 | RustSec `rsa` Marvin advisory | Resolved: the PostgreSQL backend compiles `rsa` through SQLx, and the locked `rsa` 0.9.10 is patched (the advisory affects < 0.9.0); the audit job keeps watching for regressions |
| R-8 | SSH probes accept unknown host keys on first connection (TOFU, audit OY-17) | Accepted residual: reasonable for a discovery tool; a `--strict-host-key` mode is a small future follow-up. High-security environments should pre-seed a managed `known_hosts` |
| R-9 | `--no-verify` disables NetBox TLS verification (audit OY-18) | Accepted residual: exists by design for self-signed instances with a prominent warning; consider expiring it in favor of `--ca-bundle` |
| R-10 | `orbyn import` reads files/stdin without a size cap (audit OY-19) | Resolved: a 64 MiB byte cap is enforced in `read_capped` (`src/import.rs`) with a clear error |
| R-11 | Windows: the temporary `snmp.conf` relies on per-user `%TEMP%` ACLs (audit OY-20) | Accepted residual: risk is low (per-user directory); explicit ACL hardening is a small future follow-up |
| R-12 | Informativas de la auditoría (OY-21–OY-27): secretos sin zeroize y `Debug` de `DbTarget`, eco de terminal al leer secretos por stdin, carrera benigna en la limpieza stale, audit trail sin anti-tamper, `export --output` sobrescribe, escapes ANSI/OSC de hostnames hostiles en terminales antiguos, consultas DNS derivadas del inventario | Documentadas en `SECURITY_AUDIT.md`; ninguna es explotable sin un escenario adicional de compromiso local o de terminal. **OY-26 mitigado en 2026-10-03**: el render de tablas elimina secuencias de control C0/C1 y ESC en el límite de salida (`terminal_safe`/`render_table`), reduciendo el residual a flujos fuera de tablas |

## 5. Review checklist

Before merging a change in `src/collectors/`, `src/integrations/`, `src/config.rs`
or `src/redact.rs`, confirm:

- [ ] Targets and options reach subprocesses as argument vectors, never a shell string.
- [ ] Any new subprocess runs through `process::run_captured` (concurrent pipes, lifecycle timeout, kill on expiry).
- [ ] No new binary is invoked without documenting why and its trust posture.
- [ ] A new secret source is registered in `Redactor::from_env`.
- [ ] Cloud provider signatures/tokens (AWS SigV4, Huawei AK/SK) reach `curl` on stdin, never argv.
- [ ] No credential is written to the db, a temp header file, an export, or a log.
- [ ] Output redaction covers the new error path (job audit + stderr).
- [ ] Any new HTTP surface verifies TLS by default and warns loudly otherwise.
- [ ] Scope validation still rejects unrestricted targets.
