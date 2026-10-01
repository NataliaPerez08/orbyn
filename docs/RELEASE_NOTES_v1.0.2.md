# Orbyn v1.0.2

## Current capabilities

Orbyn is a command-line infrastructure inventory and discovery tool. The
release includes:

- scoped Nmap, SNMP, SSH, and WinRM discovery
- SQLite and PostgreSQL persistence with migrations
- inventory queries, dependency evidence, audit records, and CSV/JSON output
- NetBox, Prometheus, Zabbix, Proxmox, AWS, Huawei Cloud, OpenStack, GCP, and
  Azure integrations
- Ansible and Terraform exports
- Linux, macOS, and Windows release artifacts with SHA-256 checksums

## External requirements

Collectors invoke independently installed tools when used: Nmap, Net-SNMP's
`snmpwalk`, OpenSSH's `ssh`, `curl`, and optionally `dig`. These tools are not
bundled with Orbyn. See [`INSTALL.md`](INSTALL.md) for installation details.

## Known limitations

- Discovery must be run only against authorized systems.
- Some integrations require provider-specific credentials and API access.
- SSH host-key discovery uses the documented TOFU behavior unless the operator
  supplies a managed host-key policy.
- `--no-verify` remains available for self-signed NetBox deployments and should
  only be used when the operator accepts the TLS risk.

## Security

Do not scan or inspect systems without authorization. Credentials are intended
to be supplied through environment variables or stdin where supported and are
not persisted by Orbyn.

## License

Orbyn is released under the Apache License 2.0. Incorporated Rust dependencies
and external software retain their respective licenses. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
