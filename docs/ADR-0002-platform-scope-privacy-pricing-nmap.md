# ADR-0002 — Platform, scope, privacy, pricing, and Nmap-retirement decisions

**Status:** Accepted · **Date:** 2026-10-15 · **Deciders:** project maintainer ·
**Supersedes:** the "Pending decisions" list in ROADMAP_V2.md (all five closed)

Closes the five pending decisions from ROADMAP_V2. Each was taken with the
codebase's shipped behavior as evidence; revisit triggers are named.

## D1 — Supported platforms: Linux x64 + Windows x64 (tier-1)

Exactly what CI proves today (`ubuntu-latest`, `windows-latest`; the agent
has `/proc` and PowerShell sampling paths). ARM64 Linux and macOS are
best-effort: no CI promises, no packaging work. **Revisit** when a real
deployment needs ARM servers or macOS operators.

## D2 — Scanner: unprivileged-only, explicit scope as the consent record

No raw sockets, ever. TCP connect, connected-datagram UDP, and the system
`ping` cover Orbyn's discovery use cases without privileges; the explicit
`--target`/`--scope-cidr` (with CIDR floors) is the authorization record.
SYN/ARP stay deferred **permanently** unless NMAP-010 lab data shows a
measured need that unprivileged probes cannot meet.

## D3 — Retention/privacy: 30-day default, no at-rest encryption before v1.6

Local-first trust model: the database lives on the operator's machine, so
the operator's disk protections apply. Agent retention stays 30 days
(`--retention-hours`); process names/IPs are collected where visible
because dependency evidence is the product. **Revisit** encryption when
remote ingest (v1.6 server) actually lands — that is the first time data
leaves the host.

## D4 — Pricing: versioned catalog packages, no live API calls at report time

Freshness ships as versioned catalog data packages through the same
mechanism as the embedded catalogs. Reports stay deterministic and
offline-capable; missing prices stay `not_calculated`, never silently
zero; every report keeps stamping source, date, version, currency.

## D5 — Nmap retirement: measured-then-default

Native flips to the default collector only after NMAP-010 lab data shows
at least parity on host recall and service identification for Orbyn's
profiles (per-feature parity matrix, not all of Nmap). Removal happens at
earliest one minor release after the flip, with no discovery regressions
in that release. Until then nmap stays the default and `--collector
native` stays opt-in; `auto` stays gated on the same data.

**Flip executed 2026-10-27.** The gate was met by the recorded NMAP-010
run ([docs/lab-results/nmap-vs-native-20261025-231625/]):
host recall 4/4 on both adapters, TCP port recall native 9/9 vs nmap
8/9, named ports 9/9 vs 0/9, UDP observations native-only. `native` is
now the `discover` default, `auto` selects native with an explicit
logged notice (never silent, never a silent nmap dependency), and
`nmap` remains available as the opt-in adapter until its removal —
earliest one minor release after the flip, per this decision.
