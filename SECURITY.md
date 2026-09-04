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
- Orbyn avoids storing credentials whenever possible. When credential storage
  becomes necessary (v0.3 SSH/WinRM collectors), credentials must be encrypted
  at rest and stored in an explicit credential profile.
- Collectors run with minimum privileges.
- Discovery jobs produce audit records for reuse or review.

## Reporting a vulnerability

For now, report security issues privately to the maintainers via the issue
tracker using a draft/private issue, or by opening a GitHub security advisory
against this repository. Do not include credentials or live scan output in
public reports.

## Threat model

A formal threat model is planned (see BACKLOG.md). The highest-risk component
is the collector boundary: it interacts with user-provided targets and
credentials. Code review of collectors, subprocess argument handling, and
log redaction are the priority review areas.