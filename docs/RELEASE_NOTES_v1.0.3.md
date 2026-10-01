# Orbyn v1.0.3

## Changes

- Added explicit dependency license and source policy checks with `cargo-deny`.
- Added third-party notices for incorporated Rust crates and external tools.
- CI now enforces formatting, tests, release builds, RustSec, license, and
  source audits.
- Release archives include `LICENSE` and `THIRD_PARTY_NOTICES.md` and are
  inspected before upload.

## Current capabilities

Orbyn provides scoped discovery, inventory persistence, dependency evidence,
audit records, CSV/JSON output, cloud and inventory integrations, and Ansible
and Terraform exports. See the README for the supported command surface.

## External requirements

Collectors invoke independently installed Nmap, Net-SNMP's `snmpwalk`,
OpenSSH's `ssh`, `curl`, and optionally `dig`. These tools are not bundled.
See [`INSTALL.md`](INSTALL.md).

## Security and limitations

Use Orbyn only against systems you are authorized to assess. Credentials are
not persisted. Some integrations require provider-specific credentials and API
access. SSH host-key discovery retains the documented TOFU behavior, and
`--no-verify` remains available for self-signed NetBox deployments.

## License

Orbyn is released under Apache-2.0. Incorporated dependencies and external
software retain their respective licenses. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
