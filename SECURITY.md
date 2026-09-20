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
- Explicit scoped targets. Unrestricted scans such as `0.0.0.0/0` are rejected
  unless deliberately and explicitly enabled by an operator.
- Targets are passed to subprocesses as argument vectors, never interpolated
  through a shell.
- Credentials are never exposed through CLI or API output and are never
  logged.
- Orbyn avoids storing credentials whenever possible. The v0.3 host-level
  collectors store **no credentials at all**: authentication is delegated to
  ssh-agent or a user-referenced identity file through a credential profile
  (login user, port, key path). If password-based collection is ever added,
  those credentials must be encrypted at rest in an explicit credential
  profile and never passed through CLI arguments or logs.
- Collectors run with minimum privileges.
- Discovery jobs produce audit records for reuse or review.
- API tokens (NetBox) are written to a `0600` temporary header file and passed
  to `curl` as `-H @file`, never as process arguments, logs, or CLI output.

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