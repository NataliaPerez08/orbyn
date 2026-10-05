# Orbyn — Implementation Plan v1.1 → v1.3

> **Companion to:** `Orbyn — Roadmap v1.1 to v1.3.md`
> **Starting point:** v1.0.4 codebase, as mapped below. All file references verified against the current tree.

## Guiding rule

Every new score carries `{decision, confidence, evidence, version}`.

The codebase already contains all four idioms to copy:

| Idiom | Existing precedent |
|---|---|
| Versioned rule id | `RULES_VERSION = "0.8.0"` stamped into every report (`src/assessment/mod.rs:23,195`) |
| Evidence records | `Finding { rule_id, severity, message, evidence: Vec<String> }` (`src/assessment/mod.rs:27–34`) |
| Explainable reasons | `WaveAsset.reasons` (`src/waves/mod.rs:26–33`) |
| Confidence fields | `Dependency.confidence: f32` (`src/domain/mod.rs:219`), `SampleConfidence` (`src/metrics/mod.rs:74–92`) |

Cross-version requirements from the roadmap apply to every phase: explainability, determinism, local-first, vendor neutrality behind adapters, read-only planning, no fabricated certainty (`UNKNOWN` / `INSUFFICIENT_EVIDENCE` / `NOT_CALCULATED` over unreliable recommendations).

---

## Phase 1 — v1.1 Application Intelligence

### 1.1 Domain model + persistence (migration 0010)

- **Domain types** in `src/domain/mod.rs`:
  - `Application { id, name, source, confidence, created_at, updated_at }`
  - `ApplicationMember { application_id, asset_id, confidence, evidence }`
  - `ApplicationEvidence { source, weight, description }`
  - `AppSource` enum: `Inferred | Manual | Imported`
- **Migration pair** `migrations/0010_applications.sql` + `migrations/postgres/0010_applications.sql` (follow the `0005_audit_events.sql` shape: TEXT ids, RFC3339 TEXT timestamps in SQLite):
  - `applications` (id TEXT PK, name UNIQUE, source, confidence REAL, created_at, updated_at)
  - `application_members` (PK application_id + asset_id, confidence REAL, evidence JSON, FKs)
  - `ALTER TABLE asset_connections ADD COLUMN observation_count INTEGER NOT NULL DEFAULT 1` — upsert increments it. This supplies the "observations: 823" repeated-connection evidence the roadmap shows.
- **Store layer**:
  - `ApplicationRow` / `ApplicationMemberRow` in `src/store/rows.rs`; extend `ConnectionRow` to decode `observation_count`.
  - Trait methods on `Store` (`src/store/traits.rs`): `create_application`, `list_applications`, `get_application`, `add_member`, `remove_member`, `replace_inferred_members`.
  - Implementations in **both** `src/store/sqlite.rs` and `src/store/postgres.rs`.
- Update `tests/schema_migrations.rs`: expected tables (lines 50–63), indexes (75–91), migration count 9→10 (line 162).

### 1.2 Inference engine — new `src/applications/` module

- `mod.rs`: `pub const INFERENCE_VERSION: &str = "application-inference/v1"` (mirrors the `RULES_VERSION` pattern); pure function `infer(snapshot) -> Vec<InferredApplication>`.
- **Reuse the snapshot** assembled by `src/app/assessment.rs:11–28` (assets, dependencies, connections, services already loaded in bulk) — no new store reads.
- `signals.rs` — per-pair signal extraction:

  | Signal | Weight |
  |---|---|
  | Manual dependency | very strong |
  | Runtime connection (scaled by observation_count) | strong |
  | Shared backend neighborhood | medium |
  | Known service combos (HTTP→PostgreSQL, HTTP→Redis, Tomcat→Oracle, app→broker) | medium |
  | Matching owner | medium |
  | Matching tag / cloud-account tag | weak–medium |
  | Matching environment | weak |
  | DNS alias | weak |
  | Same subnet | very weak |

- `weights.rs` — versioned weight table (const).
- **Metadata never forms a group alone** (roadmap requirement): grouping runs on strong/medium signals only; weak signals boost confidence within existing groups.
- **Grouping**: reuse union-find from `src/assessment/grouping.rs:17–100`; then score each member (weighted signal sum) and record evidence per member.
- **Determinism**: lexicographic unions, stable ids, stable sort orders — identical evidence produces identical grouping.
- **Naming**: dominant shared hostname prefix or owner tag → name; otherwise stable `app-N` (current grouping behavior). Manual naming via `orbyn applications create`.
- **Manual precedence**: `replace_inferred_members` upserts only inferred rows; a manual member pins the asset out of re-inference.

### 1.3 CLI — `orbyn applications`

- `ApplicationsAction` enum (Discover / List / Show / Explain / Create / Add / Remove) beside `DepsAction` (`src/cli/args.rs:415`). `merge` deferred — roadmap marks it optional.
- `src/cli/commands/applications.rs` + dispatch arm in `src/main.rs:23–154`; orchestration `src/app/applications.rs` (register in `src/app/mod.rs`).
- Mutations (create/add/remove) wrapped in audit events via `begin_audit` / `finish_audit_result` (`src/app/mod.rs:56–99`).
- Renderers in `src/output/mod.rs` (table/json/csv); `explain` prints members + per-member confidence + evidence + `INFERENCE_VERSION`.
- Extend the stable-commands test (`src/cli/args.rs:845–884`).

### 1.4 Graph integration

- `orbyn graph --application <name>`: filter edges to member assets (extend handler `src/cli/commands/dependencies.rs:51–70`, args at `src/cli/args.rs:348–357`).
- `orbyn graph --applications`: application-level graph — nodes = applications, edges = member dependency edges crossing application boundaries. Mermaid + json/csv (extend `output::mermaid`, `src/output/mod.rs:841–863`).

### 1.5 Application-level assessment

- `orbyn assess --application <name>`: run the existing engine unchanged, filter findings to member assets, roll up in the app layer:
  - complexity (avg asset score + band), risk
  - asset/dependency counts, high findings, warnings
  - dependency hubs, external deps, unconfirmed deps
  - right-sizing readiness
- No engine change — rollup computed from the existing `AssessmentReport`.

### 1.6 Waves on real applications

- `plan_waves` (`src/waves/mod.rs:83–102`) swaps its unit source: persisted applications when present, ephemeral groups as fallback.
- Pins already move whole groups (`src/waves/mod.rs:149–157`); add cross-wave inter-application dependency warnings.

### 1.7 Tests (v1.1 exit criteria)

- Deterministic unit fixtures in `src/applications/` (synthetic inventory → expected groups/confidence/evidence).
- Golden test extension (`tests/golden.rs` pattern): import fixture → `applications discover` → `explain` snapshot; regenerate with `ORBYN_GOLDEN_UPDATE=1`.
- `tests/e2e_applications.rs` on the existing fake-binary harness (`tests/common/mod.rs`).

---

## Phase 2 — v1.2 Migration Planner

### 2.1 Domain + persistence (migration 0011)

- `migration_plans` table: id, application_id, created_at, provenance (inventory snapshot ref, rules/inference/sizing/catalog versions), strategy, confidence.
- Plan detail (targets, blockers, assumptions) stored as JSON columns — a plan is a reproducible artifact, not a query target.
- Domain types: `MigrationPlan`, `MigrationTarget`, `MigrationRecommendation`, `MigrationBlocker` (INFO/WARNING/BLOCKER), `MigrationAssumption`; reuse `MigrationWave` from waves.
- Store methods: `save_plan`, `list_plans`, `get_plan` (same dual-backend recipe as 1.1; `schema_migrations.rs` count 10→11).

### 2.2 Readiness model — new `src/planning/` module

- `readiness.rs`: readiness 0–100, **separate from complexity**. Factors per roadmap:
  inventory completeness, dependency confidence, application confidence, metrics window quality (via existing `SampleConfidence`), ownership metadata, capacity information, unsupported software, unconfirmed/external dependencies.
- `READINESS_VERSION` const; every factor emits `{factor, delta, evidence}` — explainable like findings.

### 2.3 Blockers + strategies

- `strategy.rs`: deterministic rules → `REHOST | REPLATFORM | REFACTOR | RETAIN | RETIRE | UNKNOWN`, each with confidence, rationale, evidence, alternatives.
- `UNKNOWN` when evidence is insufficient — never fabricated certainty.
- `STRATEGY_VERSION` const; pure functions over the same snapshot (rules never read the store, per `src/assessment/rules.rs:1–9`).

### 2.4 CLI — `orbyn plan`

- `orbyn plan <application> [--target aws|azure|gcp|huawei|openstack] [--explain] [--format]`
- `--target` affects recommendations only, never the discovered evidence.
- `orbyn plan --all`: waves over applications; applications stay together unless overridden; cross-wave dependency warnings.
- `--explain`: why-strategy + why-wave (pattern: `WaveAsset.reasons`).

### 2.5 Bundle — `orbyn bundle <application> [--target]`

- Emit `<app>-migration/` containing: inventory.json/csv, applications.json, dependencies.json/mmd, assessment.json, sizing.json, migration-plan.json/md, manifest.json.
- Manifest records all rule versions + provenance so the bundle is reproducible and auditable.
- Reuse existing renderers; generation is read-only.

### 2.6 Tests

- Readiness/strategy determinism fixtures, golden plan snapshot, e2e plan/bundle.

---

## Phase 3 — v1.3 Target & Cost Intelligence

### 3.1 Provider-neutral catalog — new `src/targets/` module

- `TargetSku { provider, region, sku, cpu, memory, architecture, storage, capabilities }` and `TargetPrice { provider, region, sku, currency, hourly_price, pricing_model, observed_at, source }` — **capability data and pricing data kept separate** (roadmap requirement).
- `TargetProvider` adapter trait: AWS/Azure/GCP first (migrate the static catalogs in `src/sku/mod.rs`; keep `sku-match` working as a thin wrapper).
- Huawei/OpenStack arrive as catalog data with no engine change — vendor neutrality by construction; the core domain contains no provider-specific assumptions.
- Versioned local catalog files under `data/catalogs/` with metadata: provider, region, retrieved_at, catalog_version, source, currency.
- `orbyn catalog update` refreshes catalogs (offline default; optional online pricing APIs behind the adapter — online access never required for core discovery/assessment).
- Plans pin a catalog version in the manifest; stale or unknown pricing is never used silently.

### 3.2 Application-level target matching + fit score

- `matching.rs`: per-asset SKU fit (cpu, ram, architecture, storage, OS, virtualization, database requirements) + application-level constraints (network, dependencies, availability, migration strategy).
- Fit score per provider from roadmap inputs: capacity fit, managed-service compatibility, architecture compatibility, migration complexity, dependency compatibility, region availability, pricing completeness, data confidence.
- `TARGET_FIT_VERSION` const; explainable (+/− reasons).

### 3.3 Cost engine

- `cost.rs`: estimated monthly baseline — initial scope compute, storage, managed database.
- Every component labeled `known | estimated | not_calculated` — unknown components never silently become zero.
- Cost confidence (HIGH/MEDIUM/LOW) from pricing completeness + component coverage.
- `COST_MODEL_VERSION` const.

### 3.4 CLI

- `orbyn targets compare <application>`: multi-provider table (compute/database/storage/estimated, fit, migration risk) + json/csv.
- `orbyn targets recommend <application>`: recommended + alternative with "why X instead of Y" evidence; **price never automatically determines the recommendation**.
- `--format json/csv` on all new commands; schemas versioned and documented.

### 3.5 Tests

- Pinned-catalog fixture tests (deterministic match/cost), fit explainability fixtures, golden compare/recommend output, e2e.

---

## Cross-cutting

- New version consts stamped into all output + bundle manifest: `application-inference/v1`, `READINESS_VERSION`, `STRATEGY_VERSION`, `TARGET_FIT_VERSION`, `COST_MODEL_VERSION`.
- Both migration dialects (`migrations/` + `migrations/postgres/`) updated together, 1:1.
- All mutations audited; planning and analysis remain read-only; local-first preserved.
- Docs updated per release: `ARCHITECTURE.md` module map + mkdocs pages.

## Verification (each phase)

```bash
make fmt-check && make lint && make test
cargo audit
```

Roadmap exit criteria are mapped to concrete tests before a version is declared done.

## Risks / notes

- `asset_connections` upsert changes touch the hottest write path (`Store::store_observations`, `src/store/sqlite.rs:199–418`) — the `observation_count` increment must stay inside the existing transaction.
- Postgres mirror must stay 1:1 with SQLite migrations.
- Huawei/OpenStack have no SKU data today — v1.2 `--target huawei|openstack` returns `UNKNOWN` / `NOT_CALCULATED` rather than fabricated numbers, which the roadmap explicitly prefers.
- `docs/ORBYN_V1_1_CONSOLIDATION_PLAN.md` is an unrelated, completed refactor milestone — do not confuse it with the roadmap's v1.1.

## Execution order

Each phase is independently shippable and follows the roadmap's recommended order:

```text
1.1 domain model + migration 0010
  → 1.2 inference engine
  → 1.3 CLI + confidence/explainability
  → 1.4–1.5 graph + application assessment
  → 1.6 waves
  → v1.1 exit criteria
  → 2.2 readiness
  → 2.3 strategies
  → 2.4 planner
  → 2.6 wave integration
  → 2.5 bundles
  → v1.2 exit criteria
  → 3.1 provider-neutral catalog
  → 3.2 pricing model + matching
  → 3.3 cost engine
  → 3.4 compare/recommend + explainability
  → v1.3 exit criteria
```
