# Security

Infrastructure discovery is security-sensitive. Orbyn inspects networks and
hosts using credentials; careful handling of those capabilities is required.

## Authorized use only

Orbyn must only be run against infrastructure the operator is authorized to
scan and inspect. The operator is responsible for ensuring the required
authorization exists in their environment. Orbyn provides no remote attestation
or authorization service and must not be used as one.

## Design rules

- Read-only operations by default. Collectors must not modify target systems.
- Explicit scoped targets. Unrestricted scans such as `0.0.0.0/0` are rejected,
  and CIDR scopes wider than IPv4 `/16` or IPv6 `/48` require the explicit
  `--allow-large-cidr` opt-in.
- Targets are passed to subprocesses as argument vectors, never interpolated
  through a shell.
- Credentials are never exposed through CLI or API output and are never
  logged.
- Secret flags (`--token`, `--community`) can be kept off the command line:
  both fall back to environment variables (`ORBYN_NETBOX_TOKEN`,
  `ORBYN_SNMP_COMMUNITY`) and accept the literal `-` to read one line from
  stdin. Values supplied explicitly on the command line trigger a runtime
  warning (they are visible in `ps` and shell history) and are registered
  with the redactor so they cannot leak into errors, logs or job records.
- Orbyn avoids storing credentials whenever possible. The v0.3 host-level
  collectors store **no credentials at all**: authentication is delegated to
  ssh-agent or a user-referred identity file through a credential profile
  (login user, port, key path). If password-based collection is ever added,
  those credentials must be encrypted at rest in an explicit credential
  profile and never passed through CLI arguments or logs.
- Collectors run with minimum privileges.
- Discovery jobs produce audit records for reuse or review.
- API tokens (NetBox) are streamed to `curl` through stdin (`-H @-`), never
  written to a temporary file or exposed through process arguments, logs, or
  CLI output.
- The SNMP community travels to `snmpwalk` through a short-lived `0600`
  `snmp.conf` inside a `0700` directory; directories left behind by abruptly
  terminated runs are removed (best effort, current-user owned, age-gated)
  on the first SNMP walk of a process.
- Dependency audits run through RustSec. The former `RUSTSEC-2023-0071`
  exception for `rsa` is resolved: the PostgreSQL backend compiles `rsa`
  through SQLx, and the locked `rsa` 0.9.10 carries the upstream fix (the
  advisory affects versions below 0.9.0).
- The PostgreSQL backend connects with the credentials in the URL the
  operator provides; Orbyn stores no database credentials itself. A URL
  without a password falls back to `ORBYN_PG_PASSWORD` (or the standard
  `PGPASSWORD`) so the credential stays out of argv; a URL that embeds a
  password warns at runtime and the value is registered with the redactor.
  TLS is negotiated when the server offers it (`sslmode=prefer` by default)
  and can be enforced with `?sslmode=require`.
- Captured subprocess output is capped per run (16 MiB stdout, 1 MiB
  stderr; the remainder is drained and discarded), so a hostile device
  streaming endless output cannot exhaust the operator's memory. Truncated
  collector output fails the job with an explicit error instead of parsing
  a partial payload.
- Child processes never inherit Orbyn's secret-bearing environment
  variables (`ORBYN_SNMP_COMMUNITY`, `ORBYN_NETBOX_TOKEN`, `ORBYN_DB`):
  a hijacked collector binary cannot read them from its own environment.

## Reporting a vulnerability

For now, report security issues privately to the maintainers via the issue
tracker using a draft/private issue, or by opening a GitHub security advisory
against this repository. Do not include credentials or live scan output in
public reports.

## Threat model

A STRIDE-based threat model is maintained in
[`THREAT_MODEL.md`](THREAT_MODEL.md). The highest-risk component is the
**collector boundary**: it interacts with user-provided targets, external
binaries, remote hosts and credentials. Code review of collectors, subprocess
argument handling (argument vectors, never shell strings) and log redaction are
the priority review areas, and every change to `src/collectors/`,
`src/integrations/`, `src/config.rs` or `src/redact.rs` should pass the review
checklist there.
