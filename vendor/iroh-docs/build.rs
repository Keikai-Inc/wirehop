// hop: what `cfg_aliases! { wasm_browser: { all(target_family = "wasm",
// target_os = "unknown") } }` did, written out. Rust 1.99 turned the trailing
// semicolon cfg_aliases' macro expands to into a hard error, and as a path
// dependency this crate's diagnostics are not capped, so CI's clippy failed.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(wasm_browser)");
    let family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if family.split(',').any(|f| f == "wasm") && os == "unknown" {
        println!("cargo:rustc-cfg=wasm_browser");
    }
}
