//! Orbyn Desktop MVP: a read-only Tauri shell over the `orbyn` CLI.
//!
//! The desktop adds no engine logic of its own. Every view is a thin
//! wrapper around the stable, e2e-tested CLI surface (`discover`,
//! `assets`, `agent report`, `export`) — one model, three interfaces
//! (CLI, desktop, server). The engine binary is located via
//! `ORBYN_BIN`, next to this executable, or on `PATH`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tauri::Emitter;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

/// Locate the engine binary: `ORBYN_BIN`, then a sibling of this
/// executable (the bundled layout — plain, or the Tauri sidecar name
/// `orbyn-<triple>`), then `PATH`.
fn resolve_orbyn_with(
    exe: &Path,
    env_bin: Option<&str>,
    path_var: Option<&str>,
    triple: &str,
) -> Result<PathBuf, String> {
    if let Some(bin) = env_bin {
        let path = PathBuf::from(bin);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!("ORBYN_BIN points at {bin}, which does not exist"));
    }
    if let Some(dir) = exe.parent() {
        for name in [
            format!("orbyn{}", std::env::consts::EXE_SUFFIX),
            format!("orbyn-{triple}{}", std::env::consts::EXE_SUFFIX),
        ] {
            let sibling = dir.join(name);
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    if let Some(paths) = path_var {
        for dir in std::env::split_paths(paths) {
            let candidate = dir.join(format!("orbyn{}", std::env::consts::EXE_SUFFIX));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(
        "the orbyn engine binary was not found: set ORBYN_BIN, place orbyn next to \
         the app, or add it to PATH"
            .into(),
    )
}

fn resolve_orbyn() -> Result<PathBuf, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot locate this executable: {e}"))?;
    resolve_orbyn_with(
        &exe,
        std::env::var("ORBYN_BIN").ok().as_deref(),
        std::env::var("PATH").ok().as_deref(),
        env!("ORBYN_TARGET_TRIPLE"),
    )
}

/// The database the desktop operates on. A GUI has no meaningful
/// working directory, so the CLI default (`./data/orbyn.db`) would
/// scatter databases across launch directories; anchor it in the user
/// profile instead. An explicit `ORBYN_DB` is read by the engine
/// itself, so nothing is passed in that case.
fn desktop_db_with(home: Option<&str>, orbyn_db_set: bool) -> Option<String> {
    if orbyn_db_set {
        return None;
    }
    let home = home?;
    if cfg!(windows) {
        Some(format!("{home}\\AppData\\Local\\orbyn\\orbyn.db"))
    } else {
        Some(format!("{home}/.local/share/orbyn/orbyn.db"))
    }
}

fn desktop_db() -> Option<String> {
    desktop_db_with(
        std::env::var(if cfg!(windows) {
            "USERPROFILE"
        } else {
            "HOME"
        })
        .ok()
        .as_deref(),
        std::env::var("ORBYN_DB").is_ok(),
    )
}

/// Anchor a relative export path in the user profile so the file lands
/// somewhere findable regardless of the launch directory.
fn resolve_output_with(path: &str, home: Option<&str>) -> String {
    if Path::new(path).is_absolute() {
        return path.to_string();
    }
    match home {
        Some(home) => Path::new(home).join(path).to_string_lossy().into_owned(),
        None => path.to_string(),
    }
}

fn engine_args(extra: &[&str]) -> Vec<String> {
    let mut args = Vec::new();
    if let Some(db) = desktop_db() {
        args.push("--db".into());
        args.push(db);
    }
    args.extend(extra.iter().map(|arg| (*arg).to_string()));
    args
}

/// Run the engine, streaming stderr lines to the frontend as
/// `engine-log` events. Returns stdout on success, the collected
/// stderr on failure.
async fn run_engine(app: &tauri::AppHandle, extra: &[&str]) -> Result<String, String> {
    let bin = resolve_orbyn()?;
    let args = engine_args(extra);
    let mut child = Command::new(&bin)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start {}: {e}", bin.display()))?;
    let stderr = child.stderr.take().expect("stderr is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");

    let emitter = app.clone();
    let log_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        let mut collected = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = emitter.emit("engine-log", &line);
            collected.push(line);
        }
        collected
    });

    let mut out = String::new();
    stdout
        .read_to_string(&mut out)
        .await
        .map_err(|e| format!("reading engine output: {e}"))?;
    let status = child
        .wait()
        .await
        .map_err(|e| format!("waiting for the engine: {e}"))?;
    let logged = log_task.await.map_err(|e| format!("engine log: {e}"))?;

    if status.success() {
        Ok(out)
    } else {
        Err(format!(
            "the engine reported a failure ({status}): {}",
            logged.join("\n")
        ))
    }
}

/// Engine version and location, shown in the header so the operator
/// can see which binary and database the desktop is driving.
#[tauri::command]
async fn binary_status() -> Result<String, String> {
    let bin = resolve_orbyn()?;
    let output = Command::new(&bin)
        .arg("--version")
        .output()
        .await
        .map_err(|e| format!("could not start {}: {e}", bin.display()))?;
    let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(format!("{version} — {}", bin.display()))
}

/// Discover assets in a scope with the built-in native collector
/// (zero external tooling). Returns the JSON asset list.
#[tauri::command]
async fn discover(app: tauri::AppHandle, scope: String) -> Result<String, String> {
    run_engine(
        &app,
        &[
            "discover",
            "--target",
            &scope,
            "--collector",
            "native",
            "--format",
            "json",
        ],
    )
    .await
}

/// The current inventory as JSON.
#[tauri::command]
async fn assets(app: tauri::AppHandle) -> Result<String, String> {
    run_engine(&app, &["assets", "--format", "json"]).await
}

/// The standalone HTML observation report for one asset.
#[tauri::command]
async fn report_html(app: tauri::AppHandle, asset_ip: String) -> Result<String, String> {
    run_engine(
        &app,
        &["agent", "report", "--asset-ip", &asset_ip, "--format", "html"],
    )
    .await
}

/// Export the inventory in the given CLI format; returns the path
/// actually written (relative inputs are anchored in the user profile).
#[tauri::command]
async fn export(app: tauri::AppHandle, format: String, path: String) -> Result<String, String> {
    let home = std::env::var(if cfg!(windows) {
        "USERPROFILE"
    } else {
        "HOME"
    })
    .ok();
    let path = resolve_output_with(&path, home.as_deref());
    run_engine(&app, &["export", "--format", &format, "--output", &path]).await?;
    Ok(path)
}

/// Notifications-only update check (ADR-0003 D9). When
/// `ORBYN_UPDATE_MANIFEST_URL` is set, fetch a two-line text manifest
/// (line 1: latest version, line 2: download URL) with `curl` and
/// return a notice when the offered version is newer than this app's.
/// Offline-first: no URL, or any fetch/parse failure, means no notice —
/// never a blocking error, never an auto-download.
#[tauri::command]
async fn check_update() -> Result<Option<String>, String> {
    let url = std::env::var("ORBYN_UPDATE_MANIFEST_URL")
        .ok()
        .map(|u| u.trim().to_string())
        .unwrap_or_default();
    if url.is_empty() {
        return Ok(None);
    }
    let output = tokio::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "5", &url])
        .output()
        .await;
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let mut lines = body.lines().map(str::trim).filter(|l| !l.is_empty());
    let (Some(offered), Some(download)) = (lines.next(), lines.next()) else {
        return Ok(None);
    };
    if version_newer(offered, env!("CARGO_PKG_VERSION")) {
        Ok(Some(format!(
            "Version {offered} of Orbyn is available. Download it at {download} \
             (this window will not update itself)."
        )))
    } else {
        Ok(None)
    }
}

/// True when `offered` is a numerically newer dotted version than
/// `current` (`1.10.0` > `1.9.2`; non-numeric parts count as 0).
fn version_newer(offered: &str, current: &str) -> bool {
    let parts = |v: &str| -> Vec<u64> {
        v.trim_start_matches('v')
            .split('.')
            .map(|p| p.trim().parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (o, c) = (parts(offered), parts(current));
    let len = o.len().max(c.len());
    for i in 0..len {
        let (a, b) = (o.get(i).copied().unwrap_or(0), c.get(i).copied().unwrap_or(0));
        if a != b {
            return a > b;
        }
    }
    false
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            binary_status,
            discover,
            assets,
            report_html,
            export,
            check_update
        ])
        .run(tauri::generate_context!())
        .expect("orbyn desktop failed to start");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The JS↔Rust contract: every `invoke("...")` in the frontend must
    /// name a `#[tauri::command]` here, and the `engine-log` event the
    /// frontend listens for must be the one the backend emits. A typo in
    /// either only fails at runtime, so pin it with a check instead.
    #[test]
    fn frontend_invoke_names_match_commands() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let ui = std::fs::read_to_string(format!("{manifest}/ui/index.html"))
            .expect("read ui/index.html");
        let rust = std::fs::read_to_string(format!("{manifest}/src/main.rs"))
            .expect("read src/main.rs");

        let mut invoked = Vec::new();
        let mut rest = ui.as_str();
        while let Some(start) = rest.find("invoke(\"") {
            rest = &rest[start + 8..];
            let end = rest.find('"').expect("unterminated invoke name");
            invoked.push(rest[..end].to_string());
            rest = &rest[end..];
        }
        assert!(!invoked.is_empty(), "no invoke calls found in the frontend");

        for name in invoked {
            assert!(
                rust.contains(&format!("async fn {name}(")),
                "frontend invokes {name}, but no such command exists"
            );
        }
        assert!(
            ui.contains("engine-log") && rust.contains("engine-log"),
            "the engine-log event name must match on both sides"
        );
    }

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, b"").expect("create file");
        path
    }

    #[test]
    fn env_bin_wins_then_sibling_then_path() {
        let base = std::env::temp_dir().join(format!("orbyn-desktop-{}", std::process::id()));
        let app_dir = base.join("app");
        let path_dir = base.join("bin");
        std::fs::create_dir_all(&app_dir).expect("mkdir");
        std::fs::create_dir_all(&path_dir).expect("mkdir");
        let exe = touch(&app_dir, "orbyn-desktop");
        let sibling = touch(&app_dir, "orbyn");
        let on_path = touch(&path_dir, "orbyn");
        let path_var = path_dir.to_string_lossy().into_owned();

        // Sibling beats PATH.
        assert_eq!(
            resolve_orbyn_with(&exe, None, Some(&path_var), "x86_64-unknown-linux-gnu").unwrap(),
            sibling
        );
        // The Tauri sidecar name is found when the plain name is absent.
        std::fs::remove_file(&sibling).expect("remove sibling");
        let sidecar = touch(&app_dir, "orbyn-x86_64-unknown-linux-gnu");
        assert_eq!(
            resolve_orbyn_with(&exe, None, Some(&path_var), "x86_64-unknown-linux-gnu").unwrap(),
            sidecar
        );
        std::fs::remove_file(&sidecar).expect("remove sidecar");
        // ORBYN_BIN beats both, even when it is not next to the app.
        let explicit = touch(&base, "elsewhere-orbyn");
        assert_eq!(
            resolve_orbyn_with(
                &exe,
                Some(explicit.to_str().unwrap()),
                Some(&path_var),
                "x86_64-unknown-linux-gnu"
            )
            .unwrap(),
            explicit
        );
        // A dangling ORBYN_BIN is an error, not a silent fallback.
        assert!(resolve_orbyn_with(
            &exe,
            Some("/no/such/binary"),
            Some(&path_var),
            "x86_64-unknown-linux-gnu"
        )
        .is_err());
        // PATH is used when no sibling exists.
        assert_eq!(
            resolve_orbyn_with(&exe, None, Some(&path_var), "x86_64-unknown-linux-gnu").unwrap(),
            on_path
        );
        // Nothing found: the error names the three lookup rules.
        let err =
            resolve_orbyn_with(&exe, None, Some("/nonexistent-dir-xyz"), "x86_64-unknown-linux-gnu")
                .unwrap_err();
        assert!(err.contains("ORBYN_BIN"), "{err}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn relative_export_paths_anchor_in_the_home_directory() {
        assert_eq!(resolve_output_with("/tmp/a.json", None), "/tmp/a.json");
        assert_eq!(
            resolve_output_with("out/export.csv", Some("/home/op")),
            "/home/op/out/export.csv"
        );
        assert_eq!(resolve_output_with("x.json", None), "x.json");
    }

    #[test]
    fn desktop_db_anchors_in_the_profile_and_respects_orbyn_db() {
        // ORBYN_DB set means the engine resolves the database itself.
        assert_eq!(desktop_db_with(Some("/home/op"), true), None);
        let db = desktop_db_with(Some("/home/op"), false).expect("a path");
        assert!(db.starts_with("/home/op"), "{db}");
        assert!(db.ends_with("orbyn.db"), "{db}");
        assert_eq!(desktop_db_with(None, false), None);
    }

    #[test]
    fn version_comparison_is_numeric_not_lexical() {
        assert!(version_newer("1.10.0", "1.9.2"));
        assert!(version_newer("0.2.0", "0.1.0"));
        assert!(version_newer("v1.0.1", "1.0.0"));
        assert!(version_newer("1.0.1", "1.0.0-alpha")); // non-numeric parts are 0
        assert!(!version_newer("1.0.0", "1.0.0"));
        assert!(!version_newer("1.0.0", "1.0.1"));
        assert!(!version_newer("1.0.0", "1.0.0.1"));
    }
}
