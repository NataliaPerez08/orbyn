# ADR-0003 — Desktop contract, installer, updater, and hardening decisions

**Status:** Accepted · **Date:** 2026-10-15 · **Deciders:** project maintainer ·
**Closes:** the five decision points opened by the v1.6/v2.0 work (D6–D10)

Each decision was taken with the codebase's shipped behavior as evidence;
revisit triggers are named.

## D6 — Desktop engine contract: subprocess over the stable CLI

The desktop drives the `orbyn` binary's contract-tested surface
(`discover`, `assets`, `agent report`, `export`) and links no engine
code. The stable-command test pins the surface, so CLI and desktop
cannot drift. **Revisit** only when a view needs live streaming the CLI
cannot express — then link the lib for that view, not a general
refactor.

## D7 — Windows installer: NSIS only

One battle-tested bundler path; MSI adds WiX complexity for zero user
value. **Revisit** when an enterprise deployment demands MSI.

## D8 — Distribution: workflow artifacts now, Releases at the release milestone; signing on cert availability

Installers upload as workflow artifacts on main pushes (downloadable
from the run); tagged GitHub Releases become the channel when the
release milestone lands. Binaries stay unsigned until a code-signing
certificate exists — acquiring one is the **revisit trigger** for both
signing here and the auto-update path in D9.

## D9 — Updater: notifications-only, offline-first

Same spirit as ADR-0002 D4: the app checks a version manifest and
notifies; the user downloads deliberately. No in-app auto-update.
Signed auto-update (Tauri updater plugin) only after D8's signing
infrastructure exists.

## D10 — Multi-agent hardening: defer until a measured need

The ingest server is single-tenant and sequential by design. Aggregation
TTL, per-agent quotas, and connection-cardinality sampling get built
when a real deployment shows the need (measured-then-build, same spirit
as ADR-0002 D5). Multi-tenancy stays postponed.
