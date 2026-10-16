fn main() {
    // The triple names the Tauri sidecar layout: bundled engine binaries
    // keep a `orbyn-<triple>` name next to the app executable.
    println!(
        "cargo:rustc-env=ORBYN_TARGET_TRIPLE={}",
        std::env::var("TARGET").expect("TARGET is set by cargo")
    );
    tauri_build::build()
}
