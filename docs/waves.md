# Migration waves

`orbyn waves` turns the assessment into an ordered migration plan — Wave 1
(low risk) first, Wave 3 (core) last — mirroring the plan in Phase 10 of
`ORBYN_AGENT_PLAN.md`.

```bash
orbyn waves
orbyn waves --format json
orbyn waves --format csv
orbyn waves --pin 10-0-0-2=1 --exclude legacy-01
```

## What each wave is

The planner scores every asset from 0-9 and buckets into three risk bands:

| Wave | Band | Example |
| --- | --- | --- |
| 1 (low risk) | score 0-3 | development systems, low-risk internal tools |
| 2 (medium risk) | score 4-6 | web, API, cache |
| 3 (high risk / core) | score 7+ | ERP, legacy DB, tightly coupled integrations |

## How the score works

Each point is a reason you can read in the output — never a mystery number:

- **Environment** `dev/test/qa/...` → 0; unset → 1; production → 2.
- **Criticality** low → 0, medium → 1, high → 2, critical → 3; unset is
  treated conservatively as high (2).
- **Migration complexity** from the assessment: low → 0, medium → 1, high → 2.
- **External coupling** `dep.external` (connections to endpoints outside the
  inventory) adds 1.
- **Unconfirmed dependencies** `dep.unconfirmed` (observed but not yet
  confirmed edges) add 1 — confirm them first with `orbyn deps confirm`.

## Groups move together

Assets connected by runtime/manual dependency edges form an application group
(`app-1`, ...). A group takes the riskiest member's score and always lands in
one wave, so you never split an application across migrations. The output says
`member of app-1 (migrates as one unit)`.

## Manual constraints

- `--pin <asset>=<wave>` forces an asset — and its whole group — into a wave
  (1-3). The output marks it `pinned to wave N via --pin`.
- `--exclude <asset>` leaves an asset out of planning; it is reported in an
  `excluded:` note instead.

Unknown pins are reported as warnings instead of failing silently.

## Design

Wave planning is a pure function over the same snapshot `orbyn assess`
builds. It shares the "external endpoint" definition with the `dep.external`
rule (`assessment::external_endpoints`) so the two can never drift apart.

Scheduling, dates, and freeze windows are out of scope; waves are an ordered
suggestion, not a calendar.