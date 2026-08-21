use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

    // Prebuilt client binaries directory
    let prebuilt_dir = env::var("PREBUILT_CLIENTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace_root.join("zig-out"));

    // Target triples to look for
    let targets = [
        ("x86_64-linux-gnu", "x86_64-linux"),
        ("aarch64-linux-musl", "aarch64-linux"),
        ("x86_64-macos", "x86_64-macos"),
        ("aarch64-macos", "aarch64-macos"),
// not supported         ("x86_64-windows-gnu", "x86_64-windows"),
    ];

    for (zig_triple, client_name) in &targets {
        let src = prebuilt_dir.join(zig_triple).join("boom-sshsend");
        let dst = out_dir.join(format!("boom-sshsend-{client_name}"));

        if src.exists() {
            fs::copy(&src, &dst).unwrap_or_else(|e| {
                panic!("failed to copy {} to {}: {e}", src.display(), dst.display());
            });
            println!("cargo::rerun-if-changed={}", src.display());
        } else {
            // Create empty placeholder so include_bytes! doesn't fail
            fs::write(&dst, b"").unwrap();
            println!(
                "cargo::warning=client not found for {zig_triple}, embedding empty placeholder"
            );
        }
    }

    println!("cargo::rerun-if-env-changed=PREBUILT_CLIENTS_DIR");
    println!("cargo::rerun-if-changed={}", workspace_root.join("zig-out").display());
}
