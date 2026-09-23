//! Embeds the app icon in the Windows executable. GPUI loads icon resource 1
//! for the taskbar, title bar and Alt-Tab; Explorer shows it for the file.

use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/app-icon.ico");
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    if !windows || env::var_os("CARGO_FEATURE_UI").is_none() {
        return;
    }
    let icon = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets/app-icon.ico");
    // An absolute path, escaped for an RC string, so the resource compiler's
    // working directory does not matter.
    let icon = icon.display().to_string().replace('\\', "\\\\");
    let script = PathBuf::from(env::var("OUT_DIR").unwrap()).join("gantry.rc");
    fs::write(&script, format!("1 ICON \"{icon}\"\n")).unwrap();
    embed_resource::compile(&script, embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
