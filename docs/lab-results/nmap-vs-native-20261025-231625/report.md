# NMAP-010 — native vs nmap on the QEMU lab

Date: 2026-10-26T05:21:23Z · Network: 192.0.2.0/24 (isolated lab bridge) ·
Scope: orbyn discover, default profiles, unprivileged connect scans.

| Adapter | Host recall | TCP port recall (per host) | Named ports (per host) | Runtime | Extra hosts | UDP observations |
| --- | --- | --- | --- | --- | --- | --- |
| nmap | 100% (4/4) | web-01 2/2; api-01 2/2; db-01 2/3; legacy-01 1/1 | web-01 0/2; api-01 0/2; db-01 0/3; legacy-01 0/1 | 32s | 192.0.2.1 | none |
| native | 100% (4/4) | web-01 2/2; api-01 2/2; db-01 3/3; legacy-01 1/1 | web-01 2/2; api-01 2/2; db-01 3/3; legacy-01 1/1 | 266s | 192.0.2.1 | 192-0-2-11:1900 192-0-2-11:500 192-0-2-12:123 192-0-2-12:53 192-0-2-13:1900 192-0-2-13:514 192-0-2-14:123 192-0-2-14:137 |

Ground truth (cloud-init): web-01 22,80 · api-01 22,8080 · db-01 22,5432,6379 · legacy-01 22.
Extra hosts and UDP observations are reported, not penalized: the nmap
baseline is TCP-only, and the native UDP sweep is a new capability with
conservative `open|filtered` states.

Checks: 2 passed, 0 failed.

Raw data: `results/nmap-vs-native-20261025-231625/{nmap,native}-assets.csv`, `results/nmap-vs-native-20261025-231625/{nmap,native}-services*.csv`,
and both SQLite databases in the same directory.
