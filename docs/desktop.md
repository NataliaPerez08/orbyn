# Desktop app (MVP)

The v2.0 Desktop MVP is a read-only Tauri shell over the `orbyn` CLI:
**Discover → Observe → Export**, aimed at operators who prefer a window
over a terminal. It adds no engine logic of its own — every view is a
thin wrapper around the stable, e2e-tested CLI surface (`discover`,
`assets`, `agent report`, `export`). One model, three interfaces: the
CLI, the desktop, and the ingest server all drive the same engine and
the same `Store`.

## Running it

```console
cd desktop
cargo run
```

The desktop needs the `orbyn` engine binary at runtime. It is located
in this order:

1. `ORBYN_BIN` — explicit path to the binary,
2. a sibling of the desktop executable (the bundled layout),
3. `PATH`.

The window header shows which binary was found and its version.

## Database

A GUI has no meaningful working directory, so the CLI default
(`./data/orbyn.db`, relative to wherever the terminal sits) is replaced
by a fixed profile path: `~/.local/share/orbyn/orbyn.db` on Linux and
macOS, `%LOCALAPPDATA%\orbyn\orbyn.db` on Windows. Set `ORBYN_DB` to
override — the engine reads it directly, and the desktop stays out of
the way.

## Guided flow

The window is a four-step wizard; steps unlock as you go and stay
clickable afterwards:

1. **Choose what to scan** — enter a scope (CIDR or single IP) and scan
   it with the built-in native collector: no nmap, no external tools,
   unprivileged. Engine log lines stream into the view while the scan
   runs, and a successful scan continues to step 2 on its own.
2. **Review devices** — the found inventory as a table.
3. **Observe a device** — renders the asset's observation report (the
   same standalone HTML document `orbyn agent report --format html`
   produces) inside the window.
4. **Save your results** — write the inventory as CSV (Excel), JSON
   (Orbyn), an Ansible inventory (INI or YAML), or Terraform. Relative
   paths are anchored in your home directory so exports are always
   findable.

First run starts at step 1; returning operators with an existing
inventory land directly on step 2. Messages are written for
non-technical users — errors surface the engine's own explanation under
a plain lead line.

Read-only by design: the MVP deliberately has no editing (scope-creep
mitigation from the roadmap risk table).

## Building

The desktop crate is a standalone Cargo workspace (`desktop/`, excluded
from the main workspace like `fuzz/`) with its own lockfile, so the
engine's dependency tree stays untouched. Linux builds need
`libwebkit2gtk-4.1-dev`; Windows uses the preinstalled WebView2. CI
builds and tests it on both platforms.

`tauri-build` validates the engine sidecar path at compile time, so
stage it before any desktop build:

```console
mkdir -p desktop/binaries
cp target/release/orbyn desktop/binaries/orbyn-x86_64-unknown-linux-gnu
```

(a plain `touch` of the same path is enough for UI-only work; the
placeholder is what CI's compile jobs stage).

## Installers

The engine ships inside the installer as a Tauri sidecar, so a clean
Windows machine needs no toolchain: the installer delivers
`orbyn-desktop.exe` and `orbyn.exe` side by side, and the sibling
lookup finds the engine without any `PATH` setup.

- The sidecar mechanics are verified locally via the Linux bundle:
  `cargo tauri build --bundles deb` produces a `.deb` whose `/usr/bin`
  holds both binaries, and the extracted app boots in a stripped
  environment with the engine found via the sibling lookup.
- CI builds the Windows NSIS installer on pushes to `main`
  (`desktop-installer` job): release engine → sidecar staging →
  `cargo tauri build --bundles nsis`.
- Dependency policy is carried over: `cargo deny` runs against the
  desktop lockfile with the same `deny.toml` (plus the desktop-only
  allowances documented there).

## Not yet (tracked in the backlog)

- Installer artifact upload and signed binaries.
- Native save dialog for exports (currently an editable path field).
