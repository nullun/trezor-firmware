use std::env;

fn is_linux() -> bool {
    env::var("CARGO_CFG_UNIX").is_ok()
        || env::var("CARGO_CFG_TARGET_OS")
            .map(|os| os == "linux")
            .unwrap_or(false)
}

fn is_macos() -> bool {
    env::var("CARGO_CFG_TARGET_OS")
        .map(|os| os == "macos")
        .unwrap_or(false)
}

fn is_unit_test() -> bool {
    env::var("CARGO_FEATURE_TEST").is_ok()
}

fn main() {
    if !is_unit_test() {
        if is_macos() {
            // The emulator loads the app with dlopen + dlsym("applet_main"), so
            // build a dlopen-able Mach-O image rather than an executable (the
            // macOS analogue of `-shared` on Linux). Undefined symbols (the
            // trezor API the SDK calls) are resolved against the emulator
            // process at load time; the emulator is linked with -export_dynamic.
            println!("cargo:rustc-link-lib=System");
            println!("cargo:rustc-link-arg=-dynamiclib");
            println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
            println!("cargo:rustc-link-arg=-Wl,-export_dynamic");
        } else if is_linux() {
            // On Linux, link to C library to get __libc_start_main, memcpy, etc.
            println!("cargo:rustc-link-lib=c");
            println!("cargo:rustc-link-arg=-shared");
        }
    }
}
