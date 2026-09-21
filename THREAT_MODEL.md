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
- **Boundary B — external tools & remotes**: `nmap`, `snmpwalk`, `ssh`, `curl`
  (path configurable via `ORBYN_*_BIN`); remote SNMP agents, SSH servers and
  the NetBox HTTP API. Their stdout/stderr is parsed into observations.
- **Boundary C — system resolver**: `orbyn deps dns` resolves hostnames via
  `getaddrinfo` (blocking pool).
- **Boundary D — persistence**: the SQLite database file plus job audit rows.
- **Boundary E — output**: stdout tables/JSON/CSV, stderr logs, exporter output
  files, Mermaid graphs.

Assets that matter:

| Asset | Where it lives |
|---|---|
| Discovery/import credentials (NetBox token, SNMP community) | process memory; env & `.env`; argv of `snmpwalk` |
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
| A-4 Secrets in env leak into error messages / job audit rows | Information disclosure | NetBox token and SNMP community are registered into `Redactor` (`src/redact.rs`) and scrubbed before logging or persisting job failures. | Present but **value-based**: any secret not pre-registered is not redacted. Keep the redactor fed from the same env vars the collectors consume. |
| A-5 `.env` file stored with secrets ends up world-readable in a repo backup | Information disclosure | `.env` is git-ignored (`.gitignore`). | Present. **Residual**: file-mode hardening of `.env` is left to the OS/operator. |

### B — External tools and remotes (lowest trust)

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| B-1 A compromised nmap/curl/ssh binary runs arbitrary code as the operator | RCE | These tools run with the operator's privileges and their **ssh-agent** and key material reachable. | Supply-chain reality for any CLI that shells out. Recommendations: install these tools from the OS package manager; run discovery from a dedicated low-privilege user whose ssh-agent only exposes the needed keys. |
| B-2 A malicious/Northbound NetBox server (or on-path attacker) feeds crafted JSON that deserializes into extreme or hostile records | Tampering/DoS | `serde_json` parse is bounded; fields are normalized. | Present: typed structs only. **Residual**: no pagination/large-response cap (#28 in KnowIssues); `--no-verify` disables TLS hostname verification with an explicit warning (`main.rs`). |
| B-3 A remote SSH host returns poisoned output (e.g. `df`/`systemctl`/`ss` lines) | Tampering | Parsed into typed fields; numbers validated; every observation is reconciled against validated targets. | Present: parsers are tolerant + tests. **Residual**: parser robustness is ongoing (#12 in KnowIssues). |
| B-4 Community string is visible in the `snmpwalk` argument list | Information disclosure | Yes: `-c <community>` is passed as argv (`snmp.rs:178`). Redactor hides it from logs/DB, but any local process (or `ps`) can read argv. | Present: redaction. **Recommendation**: switch to `snmpwalk -c @FILE` (community from a 0600 file) so the string never appears in argv — tracked in KnowIssues. |
| B-5 On-path attacker observes NetBox traffic with `--no-verify` | Spoofing/Elevation | Token is sent over TLS; `--no-verify` skips verification. | Mitigated: loud warning; default verifies. **Residual**: operator decision. |
| B-6 SSH host-key verification bypass | Spoofing/Elevation | `StrictHostKeyChecking=accept-new` is set (`ssh.rs`): keys are pinned after first connect (TOFU), later connects verify against `known_hosts`. DoS surface is limited by `ConnectTimeout=10` and a 60 s probe timeout. | Present: TOFU. **Residual**: a first-connect MITM is possible when `known_hosts` is empty; document an operator `ssh_config` (managed `KnownHostsFile`) for high-security environments. |

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

### E — Output

| Threat | STRIDE | Assessment | Mitigation |
|---|---|---|---|
| E-1 Exported JSON/CSV/Ansible/Terraform files contain sensitive inventory committed to a repo | Information disclosure | Exports are plaintext by design. | Documented. **Residual**: operator must not commit exports; CI/secret-scanning is the operator's responsibility. |
| E-2 Logs on stderr leak a token via an unregistered value (e.g. a NetBox URL containing a token) | Information disclosure | Redactor only knows pre-registered values; URL-embedded tokens are out of scope. | Present: redactor. **Recommendation**: also redact `Authorization`-style substrings and treat `*@*` URL creds as forbidden input. |

---

## 3. Highest-risk component

The **collector boundary (A + B)** is where capability (credentials, scanning,
network reach) meets untrusted input. Secure-coding rules that gate review:

1. Targets → argument vectors, never shell strings.
2. No `sh -c`; binary paths are the only external code executed.
3. Secrets exist in process memory only; redact before any write boundary.
4. Scope is validated (`0.0.0.0/0` rejected) before any tool runs.
5. Collectors are read-only.
6. No credential storage (ssh-agent / key files referenced by path only).

---

## 4. Open recommendations (residual risk)

| ID | Recommendation | Effort |
|---|---|---|
| R-1 | Pass the SNMP community via a `0600` header/file (`snmpwalk -c @FILE`) instead of argv | Small |
| R-2 | Surface an SSH policy for probes in docs (managed `KnownHostsFile` for high-security envs, `IdentitiesOnly=yes` to limit agent-key negotiation) | Small |
| R-3 | Reject `--no-verify` when a custom CA/certificate pin is feasible; keep the prominent warning otherwise | Small |
| R-4 | Treat URL credentials (`https://user:pass@host`) as forbidden target/URL input | Small |
| R-5 | NetBox pagination + response-size cap to bound malformed/large responses | Medium |
| R-6 | Publish build provenance (reproducible release artifacts + checksums) for the release workflow | Resolved and verified for the tagged `v1.0.2` release |
| R-7 | RustSec `rsa` Marvin advisory | Accepted exception: `rsa` is an optional, unused SQLx backend dependency in the lockfile; no fixed release exists. Revisit if backend features change. |

## 5. Review checklist

Before merging a change in `src/collectors/`, `src/integrations/`, `src/config.rs`
or `src/redact.rs`, confirm:

- [ ] Targets and options reach subprocesses as argument vectors, never a shell string.
- [ ] No new binary is invoked without documenting why and its trust posture.
- [ ] A new secret source is registered in `Redactor::from_env`.
- [ ] No credential is written to the db, a temp header file, an export, or a log.
- [ ] Output redaction covers the new error path (job audit + stderr).
- [ ] Any new HTTP surface verifies TLS by default and warns loudly otherwise.
- [ ] Scope validation still rejects unrestricted targets.
