# Orbyn — Roadmap v1.1 → v1.3

> **Starting point:** v1.0.4  
> **Theme:** From infrastructure discovery to migration intelligence.

## Vision

Orbyn already discovers infrastructure, normalizes inventory, maps dependencies, evaluates migration complexity, collects utilization metrics, performs right-sizing, matches cloud SKUs, and generates migration waves.

The next development cycle should focus on combining those capabilities into higher-level answers.

The goal is to evolve Orbyn from:

> **“What infrastructure exists?”**

to:

> **“What applications exist, how do they depend on each other, and how should they be migrated?”**

The progression is:

```text
Infrastructure
      │
      ▼
   Assets
      │
      ▼
Dependencies
      │
      ▼
┌─────────────────────────┐
│ v1.1                    │
│ Application Intelligence│
└────────────┬────────────┘
             ▼
      Applications
             │
             ▼
┌─────────────────────────┐
│ v1.2                    │
│ Migration Planner       │
└────────────┬────────────┘
             ▼
      Migration Plans
             │
             ▼
┌─────────────────────────┐
│ v1.3                    │
│ Target & Cost           │
│ Intelligence            │
└────────────┬────────────┘
             ▼
 Target recommendations
 + cost comparisons
```

---

# v1.1 — Application Intelligence

## Goal

Automatically infer logical applications from Orbyn's existing inventory and dependency evidence.

Today Orbyn understands:

```text
Asset A
Asset B
Asset C

A → B
B → C
```

v1.1 should allow Orbyn to infer:

```text
┌──────────────────────────────┐
│ Application: billing        │
│ Confidence: 94%             │
│                             │
│ frontend01                  │
│      │                      │
│      ▼                      │
│ backend01 ────► redis01     │
│      │                      │
│      ▼                      │
│ postgres01                  │
└──────────────────────────────┘
```

Application grouping MUST remain explainable.

Orbyn must never present an inferred application as absolute truth without exposing the evidence used to create it.

---

## 1. Application domain model

Introduce an explicit application model.

Suggested structures:

```rust
Application {
    id
    name
    source
    confidence
    created_at
    updated_at
}

ApplicationMember {
    application_id
    asset_id
    confidence
    evidence
}

ApplicationEvidence {
    source
    weight
    description
}
```

Applications may originate from:

```text
inferred
manual
imported
```

Manual decisions must take precedence over automatic inference.

---

## 2. Application inference engine

Implement an inference engine operating on the existing dependency graph.

Potential signals include:

### Runtime connections

Strong evidence.

```text
app01 → db01:5432
app02 → db01:5432
```

Repeated communication with the same backend strongly suggests application membership.

### Shared dependencies

Example:

```text
frontend01 ─┐
frontend02 ─┼──► backend01 ───► postgres01
frontend03 ─┘
```

The shared dependency neighborhood provides grouping evidence.

### DNS relationships

DNS should remain weaker evidence than observed runtime connections.

### Service relationships

Known service combinations can increase confidence.

Examples:

```text
HTTP → PostgreSQL
HTTP → Redis
Tomcat → Oracle
application → message broker
```

### Metadata

Existing Orbyn metadata can provide additional evidence:

```text
environment
owner
tags
cloud project
cloud account
resource group
VPC/VNet
subnet
Proxmox pool
```

Metadata alone SHOULD NOT normally be enough to create a high-confidence application.

---

## 3. Confidence scoring

Every inferred membership must carry a confidence score.

Example conceptual weighting:

```text
Observed runtime dependency     strong
Manual dependency              very strong
Repeated connection evidence   strong
Shared backend                 medium
Matching owner                 medium
Matching environment           weak
Matching tag                   weak-medium
DNS alias                      weak
Same subnet                    very weak
```

The exact weights MUST be versioned.

Example:

```text
application-inference/v1
```

The algorithm must be deterministic given identical inputs and rule versions.

---

## 4. Explainability

Every inferred application must answer:

> Why does Orbyn believe these assets belong together?

Example:

```text
$ orbyn applications explain billing

Application: billing
Confidence: 94%

Members
────────────────────────────────────

frontend01       96%
backend01        99%
postgres01       99%
redis01          91%

Evidence

frontend01 → backend01:443
  runtime connection
  observations: 823

backend01 → postgres01:5432
  runtime connection
  PostgreSQL detected
  observations: 483

backend01 → redis01:6379
  runtime connection
  Redis detected
  observations: 217

Additional evidence

✓ matching environment: production
✓ matching owner: payments
✓ shared dependency neighborhood

Inference model:
application-inference/v1
```

---

## 5. CLI

Introduce:

```text
orbyn applications
orbyn applications discover
orbyn applications show <application>
orbyn applications explain <application>
```

Manual correction:

```text
orbyn applications create billing

orbyn applications add billing <asset>

orbyn applications remove billing <asset>
```

Optional future command:

```text
orbyn applications merge app1 app2
```

---

## 6. Graph integration

Extend:

```text
orbyn graph
```

with:

```text
orbyn graph --application billing
```

and application-level graph:

```text
orbyn graph --applications
```

Example:

```text
billing
   │
   ├────► authentication
   │
   └────► reporting
              │
              ▼
          analytics
```

Support existing machine-readable formats and Mermaid.

---

## 7. Assessment integration

Assessment should operate at both:

```text
asset
application
```

Application assessment should aggregate:

- asset findings
- dependency risks
- unsupported platforms
- missing inventory
- dependency hubs
- external dependencies
- utilization evidence
- right-sizing readiness

Example:

```text
Application: billing

Complexity: 78/100
Risk: HIGH

Assets: 7
Dependencies: 12

High findings: 2
Warnings: 5
```

---

## v1.1 Exit Criteria

v1.1 is complete when:

- applications are first-class persisted entities;
- Orbyn can infer applications from existing dependency evidence;
- every inferred membership has confidence;
- every confidence score is explainable;
- inference rules are versioned;
- users can override automatic grouping;
- application graphs can be exported;
- application-level assessment works;
- identical evidence produces deterministic grouping;
- inference is covered by deterministic fixtures and tests.

---

# v1.2 — Migration Planner

## Goal

Combine:

```text
inventory
+
applications
+
dependencies
+
assessment
+
metrics
+
right-sizing
+
SKU matching
+
migration waves
```

into an actionable migration plan.

v1.2 should answer:

> How should this application be migrated?

---

## 1. Migration Plan domain model

Introduce:

```rust
MigrationPlan
MigrationPlanApplication
MigrationTarget
MigrationRecommendation
MigrationBlocker
MigrationAssumption
MigrationWave
```

Plans should be reproducible.

Store:

```text
creation timestamp
inventory snapshot/reference
assessment rule version
application inference version
sizing rule version
target catalog version
```

---

## 2. Migration readiness score

Separate migration readiness from migration complexity.

Example:

```text
Complexity: 78/100
Readiness: 63/100
```

Complexity represents inherent difficulty.

Readiness represents whether sufficient information and prerequisites exist to migrate safely.

Possible readiness factors:

```text
inventory completeness
dependency confidence
application confidence
metrics window quality
ownership metadata
capacity information
unsupported software
unconfirmed dependencies
external dependencies
```

The score MUST be explainable.

---

## 3. Migration blockers

Introduce explicit blockers.

Examples:

```text
Unsupported OS
Unknown dependency
Insufficient utilization history
Unknown application owner
External dependency
Legacy database
Missing capacity information
Unresolved dependency
```

Classification:

```text
INFO
WARNING
BLOCKER
```

---

## 4. Migration strategy

Orbyn should recommend a strategy where evidence allows it.

Initial strategies:

```text
REHOST
REPLATFORM
REFACTOR
RETAIN
RETIRE
UNKNOWN
```

The recommendation MUST include:

```text
strategy
confidence
rationale
evidence
alternatives
```

Orbyn must return `UNKNOWN` when evidence is insufficient rather than fabricate certainty.

---

## 5. Migration plan generation

Introduce:

```text
orbyn plan <application>
```

Example:

```text
$ orbyn plan billing

Application
billing

Assets
7

Complexity
78 / 100 — HIGH

Readiness
71 / 100

Recommended strategy
REPLATFORM

Confidence
82%

Migration wave
3

Blockers

⚠ PostgreSQL 11 EOL
⚠ NFS dependency
⚠ External SMTP endpoint

Sizing

Current:
16 vCPU
64 GB RAM

Recommended:
12 vCPU
48 GB RAM

Sizing confidence:
HIGH

Observation window:
168 hours
```

---

## 6. Target-aware planning

Allow:

```text
orbyn plan billing --target aws
orbyn plan billing --target azure
orbyn plan billing --target gcp
orbyn plan billing --target huawei
orbyn plan billing --target openstack
```

The target affects recommendations but must not alter the underlying discovered evidence.

---

## 7. Wave integration

Existing migration-wave functionality should become part of the planner.

Example:

```text
$ orbyn plan --all

WAVE 1
monitoring
internal-tools

WAVE 2
reporting
analytics

WAVE 3
billing
erp

WAVE 4
legacy-core
```

Applications should remain together unless explicitly overridden.

Cross-wave dependencies should generate warnings.

---

## 8. Plan explainability

Introduce:

```text
orbyn plan billing --explain
```

Example:

```text
Why REPLATFORM?

+ PostgreSQL workload detected
+ target provider offers managed PostgreSQL
+ application topology is understood
+ 168h utilization window available

Risks

- NFS dependency
- one external SMTP dependency

Why Wave 3?

+ high dependency count
+ database dependency
+ two upstream applications
+ complexity score 78
```

---

## 9. Migration Bundle

Introduce:

```text
orbyn bundle billing
```

Suggested output:

```text
billing-migration/
├── inventory.json
├── inventory.csv
├── applications.json
├── dependencies.json
├── dependencies.mmd
├── assessment.json
├── sizing.json
├── migration-plan.json
├── migration-plan.md
└── manifest.json
```

The manifest should record versions and provenance so the bundle can be reproduced and audited.

---

## v1.2 Exit Criteria

v1.2 is complete when:

- an application can produce a migration plan;
- readiness and complexity are separate concepts;
- blockers are explicit;
- recommendations expose evidence;
- migration strategies are deterministic;
- insufficient evidence produces `UNKNOWN`;
- right-sizing feeds target planning;
- application groups feed migration waves;
- cross-wave dependencies are detected;
- migration bundles can be exported;
- generated plans contain enough provenance to reproduce the decision.

---

# v1.3 — Target & Cost Intelligence

## Goal

Answer:

> Where should this workload run, what should it run on, and approximately what will it cost?

Initial targets:

```text
AWS
Azure
GCP
Huawei Cloud
OpenStack
```

Architecture MUST allow additional providers without modifying the planning engine.

---

## 1. Target catalog abstraction

Create a provider-neutral target model.

Example:

```rust
TargetSku {
    provider
    region
    sku
    cpu
    memory
    architecture
    storage
    capabilities
}

TargetPrice {
    provider
    region
    sku
    currency
    hourly_price
    pricing_model
    observed_at
    source
}
```

Keep SKU capability data separate from pricing data.

---

## 2. Versioned catalogs

Cloud pricing changes constantly.

Every catalog must therefore include:

```text
provider
region
retrieved_at
catalog_version
source
currency
```

A migration plan must never silently use stale or unknown pricing.

---

## 3. Target matching

Extend existing SKU matching from individual capacity matching into application-level target matching.

Consider:

```text
CPU
RAM
architecture
storage
operating system
virtualization
database requirements
network requirements
application dependencies
availability requirements
migration strategy
```

---

## 4. Cost engine

Calculate an estimated monthly baseline.

Initial scope:

```text
compute
storage
managed database
```

Future scope:

```text
network egress
load balancers
snapshots
backup
managed cache
managed messaging
support plans
licensing
```

Costs MUST clearly distinguish:

```text
known
estimated
not calculated
```

Unknown cost components must never silently become zero.

---

## 5. Multi-cloud comparison

Introduce:

```text
orbyn targets compare billing
```

Example:

```text
Application: billing

                 AWS       Azure       GCP       Huawei
─────────────────────────────────────────────────────────
Compute          $812      $846        $791      $754
Database         $291      $307        $284      $268
Storage          $118      $125        $121      $110
─────────────────────────────────────────────────────────
Estimated       $1,221    $1,278      $1,196    $1,132

Fit               94%       91%         93%       89%
Migration risk    LOW       LOW         LOW       MEDIUM
```

Do not rank providers solely by price.

---

## 6. Target fit score

Introduce a provider/target suitability score.

Potential inputs:

```text
capacity fit
managed-service compatibility
architecture compatibility
migration complexity
dependency compatibility
region availability
pricing completeness
data confidence
```

Example:

```text
AWS

Fit: 94%

Why?

+ exact compute fit
+ managed PostgreSQL available
+ supported architecture
+ complete pricing information

Risks

- NFS requires EFS migration
```

---

## 7. Recommendation engine

Introduce:

```text
orbyn targets recommend billing
```

Example:

```text
Recommended target

AWS

Fit
94%

Estimated monthly cost
$1,221

Alternative

GCP
93%
$1,196

Why AWS instead of GCP?

+ lower migration complexity
+ closer managed database match
+ stronger dependency compatibility

Cost difference:
+$25/month
```

Price MUST NOT automatically determine the recommendation.

---

## 8. Offline and online pricing

Preserve Orbyn's local-first philosophy.

Support two modes.

### Offline

Versioned bundled/downloaded catalogs:

```text
orbyn catalog update
```

Plans remain reproducible using a known catalog snapshot.

### Online

Optional provider pricing APIs.

Online access must never be required for core discovery or assessment.

---

## 9. Cost confidence

Every estimate should include confidence.

Example:

```text
Estimated monthly cost
$1,221

Confidence
MEDIUM

Included
✓ Compute
✓ Storage
✓ Database

Unknown
? Network egress
? Backup
? Software licensing
```

This prevents false precision.

---

## 10. Machine-readable output

All new commands MUST support Orbyn's existing automation philosophy.

Examples:

```text
orbyn applications --format json
orbyn plan billing --format json
orbyn targets compare billing --format json
```

Schemas should be versioned and documented.

---

# Cross-Version Engineering Requirements

## Explainability

No important recommendation should exist without:

```text
decision
confidence
evidence
rule/model version
```

## Determinism

Given the same:

```text
inventory
observations
rules
catalogs
configuration
```

Orbyn should produce the same result.

## Local-first

Core intelligence must continue working locally.

Cloud connectivity should only be required when explicitly accessing provider APIs.

## Vendor neutrality

Provider-specific logic belongs behind adapters.

The core domain must not contain AWS/Azure/GCP-specific assumptions.

## Read-only

Planning and analysis remain read-only.

Generating Terraform or other deployment artifacts does not imply automatically applying them.

## No fabricated certainty

When evidence is insufficient:

```text
UNKNOWN
INSUFFICIENT_EVIDENCE
NOT_CALCULATED
```

is preferable to an unreliable recommendation.

---

# Recommended Implementation Order

```text
v1.0.4
   │
   ▼
Application domain model
   │
   ▼
Application inference
   │
   ▼
Confidence + explainability
   │
   ▼
Application-level graph/assessment
   │
   ▼
v1.1
   │
   ▼
Readiness model
   │
   ▼
Migration strategies
   │
   ▼
Planner
   │
   ▼
Wave integration
   │
   ▼
Migration bundles
   │
   ▼
v1.2
   │
   ▼
Provider-neutral target catalog
   │
   ▼
Pricing model
   │
   ▼
Application target matching
   │
   ▼
Cost engine
   │
   ▼
Multi-cloud comparison
   │
   ▼
Recommendation + explainability
   │
   ▼
v1.3
```

# Definition of Success

At the end of v1.3, the ideal Orbyn workflow should be:

```bash
orbyn discover --target 10.0.0.0/24

orbyn applications discover

orbyn applications

orbyn applications explain billing

orbyn assess --application billing

orbyn plan billing

orbyn targets compare billing

orbyn plan billing --target aws

orbyn bundle billing --target aws
```

Conceptually:

```text
DISCOVER
   ↓
UNDERSTAND
   ↓
GROUP
   ↓
ASSESS
   ↓
RIGHT-SIZE
   ↓
PLAN
   ↓
COMPARE
   ↓
DECIDE
```

That is the product direction:

> **Orbyn discovers infrastructure, reconstructs applications from evidence, and turns that evidence into explainable migration decisions.**