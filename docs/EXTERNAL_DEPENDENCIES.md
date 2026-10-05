# External executable dependencies

Engineering review of the external executables Orbyn invokes at runtime
(v1.1 plan, Priority 6). For licensing and redistribution see
[`third-party.md`](third-party.md); for crate dependencies see
`cargo audit` / `cargo deny` in CI. This document records a decision for
each tool: **KEEP**, **REPLACE**, or **INVESTIGATE**.

## How tools are invoked today (shared contract)

Every external tool runs under the same rules, and any replacement must
preserve them:

- **argv vectors, never shell strings** — targets and arguments are passed
  as `std::process::Command` args; there is no `sh -c` anywhere.
- **Bounded execution** — every subprocess runs through
  `src/process.rs::run_captured`: a timeout plus stdout/stderr capture
  caps, so a hostile or flooding tool cannot exhaust the operator's memory.
- **Secrets never in argv** — the SNMP community travels in a 0600
  `snmp.conf`, the WinRM password is streamed to curl as a config file on
  stdin (`-K -`), API tokens travel inside request bodies on curl stdin
  (`--data-binary @-`). Known secret values are registered with the
  redactor before any error is logged or persisted.
- **Test seams** — each tool is overridable via `ORBYN_<TOOL>_BIN`
  (`ORBYN_NMAP_BIN`, `ORBYN_SNMP_BIN`, `ORBYN_SSH_BIN`, `ORBYN_CURL_BIN`,
  `ORBYN_DIG_BIN`); the end-to-end suites drive the real binary against
  script fakes through these.
- **Operator-installed, never bundled** — missing tools fail with a
  contextual error (e.g. "is net-snmp-utils installed?"), never a download.

## Decisions

| Tool | Decision | One-line rationale |
|---|---|---|
| nmap | **KEEP** | The value is the scan/fingerprint engine; reproducing it is out of scope. |
| snmpwalk | **INVESTIGATE** | Native SNMP is not mature enough yet; replacement is optional and evidence-gated. |
| ssh | **KEEP** | A native SSH client would add a large security-sensitive surface for no measured benefit. |
| curl | **INVESTIGATE** | Largest surface and the best available win, but secret handling and caps must be preserved exactly. |
| dig | **INVESTIGATE** | Already optional; the nearest candidate for full elimination. |

## nmap — KEEP

Invoked as `nmap -oX - -sV --no-stylesheet <target>`; the XML stream is
parsed by `quick-xml` into typed observations (unit-tested against
fixtures and fuzzed via the `nmap_xml` target).

- **Implementation complexity of replacement:** enormous — porting a
  scanner and service/version fingerprinting engine is a multi-year
  project, not a consolidation task.
- **Feature completeness:** Orbyn's value here *is* nmap's engine; the
  adapter is a thin, typed XML reader.
- **Security impact:** scope validation happens before invocation; the
  adapter never interpolates target strings.
- **Cross-platform:** operator-installed on both platforms Orbyn supports;
  not bundled, so Nmap's license (NPSL) never touches Orbyn's Apache-2.0
  distribution.
- **Operational dependency:** acceptable — nmap is a standard operator tool
  and the collector is one of five, not a prerequisite for the product.

## snmpwalk — INVESTIGATE (replacement optional)

Invoked for two walks per host (system subtree, interface table) with the
community in a 0600 `snmp.conf` (never argv; stale temp dirs are cleaned
up best-effort).

- **Implementation complexity:** a native SNMP client means BER encoding,
  MIB handling and retry semantics; Rust SNMP crates exist but are young.
- **Security impact:** the current design already solves the hard part —
  the community string never touches argv, the environment, or logs.
- **Reliability evidence required:** per the plan, replacement requires
  evidence that it improves deployment or reliability (e.g. real devices
  where net-snmp's availability or text output is a problem). No such
  evidence exists today.
- **Decision:** stay on net-snmp until that evidence appears; revisit the
  native crates then.

## ssh — KEEP

One process per host probe; key-based auth (ssh-agent or identity file),
no stored credentials. The Windows collector reuses the same transport
(`ssh.exe` with a PowerShell probe).

- **Implementation complexity:** a native client (e.g. `russh`) means
  re-implementing auth flows, key formats and host-key verification — a
  large, security-sensitive surface.
- **Security impact:** OpenSSH is the most audited SSH implementation in
  existence; Orbyn inherits that for free and keeps zero secret-handling
  code (keys stay in the agent/file).
- **Cross-platform:** OpenSSH ships with Windows 10+ and every server
  Linux distribution; `ORBYN_SSH_BIN` covers nonstandard setups.
- **Operational benefit of replacement:** none measured — the process-per-
  probe cost is bounded by the discovery rate limiter, not the binary.

## curl — INVESTIGATE

The largest external surface: every HTTP integration (NetBox, Prometheus,
Zabbix, WinRM, all six cloud adapters) goes through the shared plumbing in
`src/http.rs` (status-code capture, retry policy) on top of `run_captured`
(timeouts, response caps). Secrets ride in request bodies or config files
on curl's stdin.

A Rust HTTP client (e.g. `reqwest` on the rustls stack sqlx already
compiles in) would give: one fewer runtime dependency, typed errors,
direct timeout/TLS control, and identical behavior on every platform
(curl.exe availability on Windows is good but not guaranteed on older
builds). Binary cost is roughly +1–2 MiB against a 13.5 MiB binary.

**Migration requirements (hard constraints):**

1. Secret handling must be preserved *exactly*: tokens and passwords in
   request bodies/config, never in URLs, argv, logs or persisted errors;
   redactor registration before any error path.
2. Response caps and timeouts must remain enforced per call (the
   `run_captured` guarantees move into the client configuration).
3. The retry policy in `src/http.rs` is the right seam: the executor under
   it can be swapped without touching the six integrations.
4. The `ORBYN_CURL_BIN` fake-curl end-to-end suites must be replaced by an
   equivalent mock at the new seam — the tests are the proof of (1) and
   (2), so they move with the code, not away from it.

**Decision:** investigate with a prototype behind the `src/http.rs` seam.
Do not migrate integrations one by one around the seam — that would leave
two secret-handling paths to audit.

## dig — INVESTIGATE (nearest elimination)

Already optional: `src/collectors/dns.rs` uses `dig +short` for CNAME
chains and PTR names when available and safe (`dig_safe_hostname` guards
option injection), and falls back to the system resolver (`getaddrinfo`)
otherwise. Losing dig today costs only CNAME-chain and PTR evidence.

- **Implementation complexity:** small — CNAME chains and PTR records need
  DNS wire-format queries (the stdlib resolver cannot expose them), which
  is a few hundred lines or one focused crate (`hickory-resolver`-class).
- **Security impact:** strictly positive — one fewer subprocess and one
  fewer injection surface to guard.
- **Cross-platform:** removes a tool that is awkward to get on Windows.
- **Decision:** investigate a native resolver for CNAME/PTR only, keep
  `getaddrinfo` as the fallback, and delete the dig path once the
  end-to-end DNS suites pass against the native path. This is the
  recommended first replacement if any is done.

## Revisit triggers

- **snmpwalk:** a supported device/OS where net-snmp is unavailable or its
  output parsing is unreliable, or a mature, audited Rust SNMP crate.
- **curl:** the `src/http.rs` prototype demonstrating preserved guarantees
  with acceptable binary cost.
- **dig:** native CNAME/PTR resolution landing in the DNS collector.
- **ssh / nmap:** no trigger — revisit only with a concrete operational
  failure the external tool cannot handle.
