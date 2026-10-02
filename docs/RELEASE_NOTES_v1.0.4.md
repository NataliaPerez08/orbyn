# Orbyn v1.0.4

## Changes

- **Cloud SKU matching** (`orbyn sku-match --provider aws|azure|gcp
  --cores <n> --ram-mb <m>`): converts a right-sizing baseline into candidate
  instance types (smallest fit first) from curated AWS EC2, Azure VM and GCP
  machine-type catalogs. Kept separate from the vendor-neutral `rs.*` rules;
  on-demand pricing is deliberately not embedded.
- **Migration waves** (`orbyn waves`): orders the inventory into low/medium/
  high-risk waves with the reasoning behind every placement exposed, keeps
  application groups together, and honors manual `--pin <asset>=<wave>` /
  `--exclude <asset>` constraints.
- **Fuzzing hardening**: seven cargo-fuzz targets now run in CI. A real crash
  was found and fixed (`split_http_status` on a lossy multi-byte tail) and
  pinned with a regression test and corpus seed.
- **Security**: `cargo audit` is clean after a yanked-`yoke-derive` bump;
  `cargo deny` passes advisories, bans, licenses and sources. Threat model and
  security-audit docs updated with the post-audit hardening notes.
- **Packaging**: release archives already ship `LICENSE` and
  `THIRD_PARTY_NOTICES.md`; the release pipeline builds, inspects and smoke
  tests both Linux and Windows artifacts before upload.

## Current capabilities

Orbyn provides scoped discovery, inventory persistence, dependency evidence,
audit records, CSV/JSON output, cloud and inventory integrations, Ansible and
Terraform exports, migration assessment, right-sizing, SKU matching and
migration-wave planning. See the README for the supported command surface.

## External requirements

Collectors invoke independently installed Nmap, Net-SNMP's `snmpwalk`,
OpenSSH's `ssh`, `curl`, and optionally `dig`. These tools are not bundled.
See [`INSTALL.md`](INSTALL.md).

## Security and limitations

Use Orbyn only against systems you are authorized to assess. Credentials are
not persisted. Some integrations require provider-specific credentials and API
access. SSH host-key discovery retains the documented TOFU behavior, and
`--no-verify` remains available for self-signed NetBox deployments. SKU
catalogs are a curated subset; wave plans are an ordered suggestion, not a
calendar.

## License

Orbyn is released under Apache-2.0. Incorporated dependencies and external
software retain their respective licenses. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).