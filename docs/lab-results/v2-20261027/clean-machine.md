# v2.0 evidence — clean Windows machine (ecs-84b2)

Exit criterion: full workflow (discover → observe → analyze → export)
on a clean Windows machine with no toolchain installed.

## Host

- ecs-84b2, Windows Server 2022 Standard Evaluation (10.0.20348),
  x64 — no rustc, cargo, or git present (verified via WinRM).
- Reached over the tailnet (Tailscale + approved 192.0.2.0/24 subnet
  route advertised by the Proxmox lab node); ICMP and TCP to the lab
  verified from the host before the run.

## Install (NSIS, no toolchain)

- `Orbyn_0.1.0_x64-setup.exe` (CI run 40411024002, artifact
  `orbyn-windows-nsis`, sha256 ec689fe5…, transfer verified by hash)
  installed silently (`/S`), exit 0.
- Layout `C:\Users\Administrator\AppData\Local\Orbyn`:
  `orbyn-desktop.exe` (9.0 MB) + sidecar `orbyn.exe` (15.7 MB, the
  `orbyn-windows-engine` artifact) + `uninstall.exe`; registry
  uninstall entry `Orbyn` 0.1.0. Sibling lookup satisfied.

## Full workflow (installed sidecar, the desktop's exact argv)

Machine env `ORBYN_DB=C:\orbyn\agent.db` anchors the desktop on the
host agent's database, so the observe view shows the host's own agent
data. Run via `C:\…\Orbyn\orbyn.exe` with the argv the desktop passes
(pinned by the frontend↔command contract test):

1. **discover** — `--db … discover --target 192.0.2.0/24 --collector
   native --format json`: exit 0, **6 assets** (192.0.2.1 bridge,
   web-01 .11, api-01 .12, db-01 .13, legacy-01 .14, and the VPS
   itself via agent facts), ~4.5 min — matching the NMAP-010 parity
   runtime (266s) for the same /24 from the lab node.
2. **observe** — `agent report --asset-ip 172.20.1.49 --format html`:
   2 542-byte standalone HTML report from the host's own agent data.
3. **analyze** — `assets --format json`: the inventory view.
4. **export** — `export --format csv --output …\orbyn-export.csv`:
   36 rows — 6 assets plus the connections section.

## Desktop app

- Launched in the interactive RDP session: window "Orbyn" + WebView2
  runtime 156.0.4314.50 (6 processes).
- Operator-confirmed: the four-step wizard (scope → discover →
  observe → export) renders and works correctly.
  [app-wizard.png](app-wizard.png) is the captured screen.

## Notes

- The initial "zero assets" readout during the run was a quoting
  artifact of the harness (a mangled regex and a 3-line CSV peek);
  the database and the exported CSV both held all six assets.
- The native collector's ICMP liveness prefetch (`ping -n 1 -w 1000`)
  works from this host through the tailnet route (exit 0 against
  192.0.2.11).
