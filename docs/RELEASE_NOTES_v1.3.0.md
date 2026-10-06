# Orbyn v1.3.0

This release ships the three capability milestones of the v1.1–v1.3 roadmap:
application intelligence, the migration planner, and target & cost
intelligence. All three are covered by deterministic fixtures, golden
snapshots and end-to-end tests; `cargo audit` is clean.

## Changes

- **Application intelligence (v1.1)**: applications are first-class persisted
  entities, inferred from dependency evidence with per-member confidence and
  explainable evidence records (`orbyn applications discover|list|show|
  explain`). Manual curation (`create`, `add`, `remove`) overrides inference,
  and removed inferred members are tombstoned so re-discovery cannot re-add
  them. `graph --application` scopes the edge view to one application,
  `graph --applications` renders the application-level graph, and
  `assess --application` rolls findings up to one application. Wave planning
  runs on persisted applications and warns when an application in an earlier
  wave depends on one in a later wave.
- **Migration planner (v1.2)**: `orbyn plan <application>` produces a
  migration plan — a readiness score (0–100, separate from complexity, every
  factor explainable), a deterministic strategy recommendation
  (`rehost`, `replatform`, `refactor`, `retain`, `retire`, or `unknown` when
  the evidence is insufficient — never fabricated certainty), targets sized
  from the capacity allocation with optional provider instance types,
  blockers, assumptions and the wave assignment. Plans are persisted as
  audited artifacts with full provenance (rule and model versions, snapshot
  reference). `orbyn plan --all` plans every application against one shared
  wave plan; `orbyn bundle <application>` writes a self-contained handoff
  directory (inventory, dependencies, assessment, sizing, migration plan and
  a manifest recording every rule version).
- **Target & cost intelligence (v1.3)**: provider-neutral, versioned catalogs
  under `data/catalogs/` with capability data (`TargetSku`) and pricing data
  (`TargetPrice`) strictly separate, embedded at build time so plans are
  reproducible. `orbyn targets compare <application>` scores every provider
  with a fit score built from eight explainable inputs (capacity fit,
  managed-service compatibility, architecture, migration complexity,
  dependency compatibility, region availability, pricing completeness, data
  confidence) and an estimated monthly baseline where every component is
  labeled `known | estimated | not_calculated` — an unknown component never
  silently becomes zero. `orbyn targets recommend <application>` picks the
  best fit and names an alternative with the "why X instead of Y" evidence;
  price never automatically determines the recommendation. `orbyn catalog
  update` reports the embedded catalog versions (offline default).
- **SKU matching migrated**: the curated AWS, Azure and GCP instance-type
  catalogs moved from static arrays into the versioned catalog files;
  `orbyn sku-match` keeps its exact CLI as a thin wrapper over the catalog
  data.
- **Determinism**: golden fixtures now cover the dependency graph,
  assessment, export, application explain, migration plan, target comparison
  and recommendation outputs; the suite runs 23 test targets.

## Current capabilities

Orbyn provides scoped discovery, inventory persistence, dependency evidence,
audit records, CSV/JSON output, cloud and inventory integrations, Ansible and
Terraform exports, migration assessment, right-sizing, SKU matching,
migration-wave planning, application intelligence, migration planning with
bundles, and multi-cloud target comparison. See the README for the supported
command surface.

## External requirements

Collectors invoke independently installed Nmap, Net-SNMP's `snmpwalk`,
OpenSSH's `ssh`, `curl`, and optionally `dig`. These tools are not bundled.
See [`INSTALL.md`](INSTALL.md).

## Security and limitations

Use Orbyn only against systems you are authorized to assess. Credentials are
not persisted. Some integrations require provider-specific credentials and API
access. SSH host-key discovery retains the documented TOFU behavior, and
`--no-verify` remains available for self-signed NetBox deployments. Catalogs
are a curated subset and their prices are curated on-demand list prices —
estimates, never quotes; providers without a catalog (Huawei Cloud,
OpenStack) report `not_calculated` instead of guessed numbers. Wave plans are
an ordered suggestion, not a calendar; storage and managed-database cost
components are labeled `not_calculated` until pricing data exists.

## License

Orbyn is released under Apache-2.0. Incorporated dependencies and external
software retain their respective licenses. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
