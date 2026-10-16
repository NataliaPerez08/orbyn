# Orbyn — Progressive Nmap-to-Rust Replacement Plan

**Status:** Technical plan pending audit · **Date:** 2026-10-12

> **The repository has not been verified in this deliverable.** The table below lists potentially relevant capabilities; it does **not** claim that Orbyn runs those flags today. The first mandatory task is to extract the actual commands from the code and tests before prioritizing or declaring parity.

## 1. Goal and non-goals

**Goal:** remove the hard Nmap dependency for the discovery and assessment workflows Orbyn actually uses, keeping an optional adapter while the native implementation is validated.

**Non-goals:** a full Nmap clone, universal NSE compatibility, evasion scanning, exact fingerprint reproduction, and every flag.

## 2. Real-usage audit (P0, blocking)

Search for invocations and wrappers in Rust, scripts, CI, and documentation: `nmap`, `Command::new`, external processes, arguments, and the XML/grepable parser. For **each call**, complete:

| Field | Evidence to record |
|---|---|
| Location | Path, symbol, commit SHA |
| Command/flags | Exact arguments, inputs, and defaults |
| Reason | What data Orbyn needs |
| Output consumed | XML/specific fields and errors |
| Permissions | Raw sockets/admin/root or normal user |
| Frequency | Per host, per range, per job |
| Native alternative | Proposed module/probe |
| Tests | Fixture and regression case |
| Priority | P0/P1/P2 based on actual usage |

**Output artifact:** `docs/discovery/NMAP_USAGE_MATRIX.md`, with traceability to code and tests. No flag may be labeled "currently used" without this evidence.

## 3. Initial candidate capability matrix

| Capability / illustrative Nmap flags | Rust alternative | Complexity | Phase | Notes |
|---|---|---|---|---|
| DNS resolution (`-n`, normal resolution) | OS resolver / DNS library | Low | I | Distinguish reverse DNS from inferred names |
| Host discovery (`-sn`) | ICMP echo, ARP on LAN, TCP probes | Medium | I | ICMP blocked ≠ host down |
| TCP connect (`-sT`) | `tokio::net::TcpStream` | Low-medium | I | No raw sockets; more visible to firewalls |
| Port selection (`-p`, `--top-ports`) | Parser/ranges/versioned lists | Low | I | Version the lists; don't copy databases with incompatible licenses |
| Service banners (`-sV`, partial) | Per-protocol probes and parsers | Medium-high | I–II | Version detection requires rules and a corpus |
| TCP SYN (`-sS`) | Raw sockets/capture and correlation | High | II | Privileges and APIs differ per platform |
| UDP (`-sU`) | Datagram probes + ICMP/error handling | High | II | Ambiguous open/filtered states |
| OS detection (`-O`) | Own signal-based fingerprints | Very high | II+ | Never equate simple heuristics with Nmap |
| Traceroute (`--traceroute`) | TTL/hop-limit and ICMP responses | Medium-high | II | Firewalls and privileges affect results |
| IPv6 (`-6`) | IPv6 parsing and probes | Medium | II | IPv6 LAN discovery needs specific design |
| NSE (`--script`) | Narrow, need-scoped plugins/probes | Very high | On demand only | Do not reimplement generic NSE |
| XML (`-oX`) | Internal evidence normalizer | Medium | I | Keep Nmap reading for compatibility |

## 4. Native scanner architecture

```text
DiscoveryRequest
   │
   ▼
Target Validator + Authorized Scope
   │
   ▼
Scheduler (rate limit, concurrency, cancellation, deadlines)
   │
   ├── Host probes (ICMP/ARP/TCP)
   ├── TCP connect scanner
   ├── UDP scanner (Phase II)
   ├── SYN scanner (Phase II)
   └── Service probes + fingerprint rules
   │
   ▼
Normalizer → Evidence Store → Asset/Service Inventory
```

**Interfaces:** `DiscoveryBackend`, `Probe`, `ServiceFingerprint`, `DiscoveryCapabilities`. Every result must include backend, version, timestamps, method, warnings, and confidence when inferred.

## 5. Phased plan

### Phase 0 — Baseline and tests

- Audit actual commands, permissions, and parsing.
- Capture Nmap fixtures from authorized lab hosts: Linux/Windows, open/closed/filtered ports, DNS, known services.
- Define semantic comparison: host visibility, port state, protocol, service, version, and latency.
- Freeze inventory contracts; add golden tests.

**Output:** complete usage matrix, regression suite, and code-based priorities.

### Phase I — Basic independence (v1.4)

- IPv4/CIDR/range target parser, allowlist/denylist, and target limits.
- TCP connect with timeout, max concurrency, jitter, and cancellation.
- Host discovery via TCP and ICMP/ARP where available.
- Optional DNS/reverse DNS; basic HTTP/TLS/SSH banner probes.
- Normalizer and `--scanner native|nmap|auto` selector.
- Automated lab comparisons and per-capability error reporting.

**Output:** basic host/TCP-port inventory without Nmap; advanced cases keep the fallback.

### Phase II — Detection depth (v1.7)

- UDP with conservative interpretation of results.
- SYN where privileges/platform allow.
- Service/version fingerprints with versioned rules and tests.
- IPv6 and traceroute once a validated use case exists.
- OS inference as candidates with evidence and low confidence where appropriate.
- Evaluate real coverage vs Nmap, maintenance cost, and false positives.

**Output:** greater native coverage without claiming full equivalence.

### Phase III — Selective retirement

- Mark as native-by-default **only** workflows that pass the gates.
- Keep Nmap as opt-in for uncovered features, or drop it from distribution if it serves no supported workflow.
- Document differences, permissions, and platforms explicitly.

## 6. Parity matrix — current status (v1.4 + v1.7 fingerprint slice, `--collector native`)

Per-feature parity for the features Orbyn actually consumes
(see [BASELINE_AUDIT.md](BASELINE_AUDIT.md) §2). Nmap remains the default
collector; this matrix is what gates any default flip (ADR-0001).

| Feature (Orbyn's use) | nmap adapter | native adapter | Parity |
|---|---|---|---|
| Host liveness | nmap default probes (ICMP + TCP 80/443) | ICMP echo via system `ping`, multi-host targets only; clean no-reply skips, errors fail open; `ORBYN_NATIVE_LIVENESS=0` sweeps everything | partial — narrower probe set, fail-open |
| TCP port state | default top-1000, SYN or connect | top ~90 ports, TCP connect, bounded concurrency | partial — top-ports only |
| Service name | `-sV` probe engine | port-number table, overridden by evidence: a parsed HTTP response renames the service (`http`/`https`) | partial — HTTP-family evidence only |
| Version/product | `-sV` | passive banners (SSH/FTP/SMTP…) plus versioned probes `native-fingerprints/v1`: HTTP `GET` → `Server` header or status line; TLS handshake (certs not verified — identify, don't authenticate) → greeting or HTTP inside the tunnel | partial — no probe cascade, no payload matching beyond HTTP |
| PTR hostname | built-in resolver | `dig +short -x` (graceful without dig); `ORBYN_NATIVE_REVERSE_DNS=0` | yes (when dig present) |
| MAC/vendor | on-link ARP | not collected | no |
| OS guess | `-O` (not invoked by Orbyn) | not collected | n/a — unused |
| Scope safety | shared `validate_target` floors | same floors + hard host cap (65 536, `ORBYN_NATIVE_MAX_HOSTS`); oversized IPv6 ranges refused | yes — stricter |
| Pacing | nmap timing templates | semaphore concurrency + `ORBYN_NATIVE_JITTER_MS` | partial |
| UDP (not in the nmap baseline — TCP-only) | n/a (Orbyn never invoked `-sU`) | top ~8 UDP ports (53/123/137/161/500/514/1900/5353), unprivileged connected-datagram probes: response = open, ICMP unreachable = closed (no observation), silence = `open\|filtered`; `ORBYN_NATIVE_UDP=0` disables | new capability — conservative states, ICMP rate limits mean closed ports often read `open\|filtered` |
| SYN / IPv6 ranges / traceroute | available | not implemented (SYN: raw sockets need privileges, don't port to Windows, and add nothing over connect scan for authorized inventory; IPv6/traceroute deferred until a measured need, see §9 risks) | deferred |

**Not yet measured:** host/port recall and runtime against lab ground truth
(NMAP-010). The matrix above is capability parity, not accuracy parity.

## 7. Parity gates and acceptance criteria

For each Orbyn profile, define thresholds before testing:

1. **Functional coverage:** 100% of the fields **required** by that profile, or an accepted, explicit degradation.
2. **Accuracy:** measure host and service precision/recall against lab ground truth; Nmap is the comparator, not absolute truth.
3. **Errors:** timeouts, DNS failures, filtered hosts, multiple interfaces, insufficient permissions, and cancellation.
4. **Performance:** duration and CPU/RAM/network usage within documented budgets for representative network sizes.
5. **Security:** no out-of-scope scanning; rate limits and auditable logs.
6. **Compatibility:** Windows/Linux with standard and, where applicable, privileged permissions.
7. **Regression:** stable normalized results and green tests in CI.

Do not set arbitrary "Nmap parity" percentages before measuring the baseline and defining the workflows that matter.

## 8. Test bench

An isolated, authorized lab network with: Linux and Windows hosts; open/closed/filtered TCP; HTTP, SSH, TLS, and test-database services; a firewall; hosts that don't answer ICMP; valid/invalid DNS; IPv6 if applicable. Store a known-truth manifest and versioned results. Never run comparisons against third-party networks.

Measurements: host recall, port precision, service/version identification, total time, error rate, packets/second, and overhead.

## 9. Technical risks

- **Privileges:** ICMP/raw sockets/SYN may need administrative capabilities; implement a safe fallback.
- **Windows vs Linux:** capture and raw sockets differ; abstract per-OS adapters.
- **UDP:** `open|filtered` can be indistinguishable; don't overstate states.
- **OS fingerprinting:** high effort and false positives; prioritize signals corroborated by agent/SSH/WinRM.
- **Licenses/data:** review Nmap, service-database, and rule licenses before copying or redistributing; build an own corpus or use compatible data.
- **False negatives:** firewalls, NAT, and rate limits can hide hosts; report uncertainty.

## 10. Suggested issues

| ID | Issue | Priority | Depends on | Status |
|---|---|---|---|---|
| NMAP-001 | Audit actual invocations and consumed outputs | P0 | — | done (BASELINE_AUDIT.md) |
| NMAP-002 | Fixtures and regression lab | P0 | 001 | fixtures done; lab pending |
| NMAP-003 | DiscoveryBackend + capabilities + normalizer | P0 | 001 | done (ADR-0001; `Collector` trait) |
| NMAP-004 | Target parser and authorization | P0 | 003 | done (pre-existing; re-verified) |
| NMAP-005 | TCP connect scanner | P0 | 004 | done (`src/collectors/native.rs`) |
| NMAP-006 | Rate limit, timeout, and cancellation | P0 | 005 | done (semaphore, timeouts, jitter) |
| NMAP-007 | ICMP/ARP discovery with fallback | P1 | 004 | ICMP via system `ping`, fail-open; ARP pending |
| NMAP-008 | Basic banner/service probes | P1 | 005 | done (passive banners + port table + `native-fingerprints/v1` HTTP/TLS probes) |
| NMAP-009 | Native/Nmap/auto selector | P0 | 003,005 | native+nmap done; `auto` gated on NMAP-010 |
| NMAP-010 | Comparison CI and difference reporting | P0 | 002,009 | pending (needs authorized lab) |
| NMAP-011 | UDP/SYN and IPv6 as needed | P2 | 010 | UDP done (unprivileged connect-probe, conservative `open\|filtered`); SYN deferred (privilege-gated, no gain over connect scan for authorized inventory); IPv6 ranges deferred |
| NMAP-012 | Advanced fingerprints and retirement evaluation | P2 | 010,011 | v1 fingerprints done (HTTP/TLS); advanced probes pending |

## 11. Nmap retirement condition

Nmap stops being an **installation requirement** when every officially supported workflow runs on the native engine or declares accepted degradations; tests pass on target platforms; differences are documented; and `auto` mode never silently depends on Nmap. Removing the adapter from the code is a separate, later, and reversible decision.
