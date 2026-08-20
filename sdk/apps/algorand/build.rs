use std::{env, fs, path::PathBuf};

/// Parse `Name = value;` enum entries out of a proto enum body.
///
/// `proto` is the file's text, `enum_name` the enum to look for. Entries
/// marked `deprecated` and `reserved` slots are skipped. This is a
/// line-oriented scrape, not a proto parser — enough for the two flat enums
/// this app generates from, and it keeps prost-build out of the build graph
/// (the wire codecs themselves are hand-rolled in `src/wire.rs`).
fn parse_proto_enum(proto: &str, enum_name: &str) -> Vec<(String, u32)> {
    let mut entries = Vec::new();
    let mut in_enum = false;
    for line in proto.lines() {
        let line = line.trim();
        if line.starts_with(&format!("enum {enum_name}")) {
            in_enum = true;
            continue;
        }
        if !in_enum {
            continue;
        }
        if line.starts_with('}') {
            break;
        }
        if line.starts_with("//") || line.starts_with("/*") || line.starts_with('*') {
            continue;
        }
        if line.starts_with("reserved") || line.contains("deprecated") {
            continue;
        }
        let Some((name, rest)) = line.split_once('=') else {
            continue;
        };
        let value = rest.trim().trim_end_matches(';').trim();
        let Ok(value) = value.parse::<u32>() else {
            continue;
        };
        entries.push((name.trim().to_string(), value));
    }
    assert!(!entries.is_empty(), "no entries parsed for enum {enum_name}");
    entries
}

/// Generate `$OUT_DIR/proto_ids.rs` (included by `src/proto.rs`): the app's
/// wire message ids from `protob/messages.proto` and the `ButtonRequestType`
/// codes from `protob/common.proto`, so the Rust enums cannot drift from the
/// wire spec.
fn build_proto_ids() {
    println!("cargo:rerun-if-changed=protob/messages.proto");
    println!("cargo:rerun-if-changed=protob/common.proto");

    let messages = fs::read_to_string("protob/messages.proto").unwrap();
    let common = fs::read_to_string("protob/common.proto").unwrap();

    let mut out = String::new();

    out.push_str("/// Wire message ids of this app, generated from `protob/messages.proto`.\n");
    out.push_str("#[derive(Copy, Clone, PartialEq, Eq, num_enum::FromPrimitive, num_enum::IntoPrimitive)]\n");
    out.push_str("#[repr(u16)]\n");
    out.push_str("pub enum AlgorandMessages {\n");
    for (name, value) in parse_proto_enum(&messages, "MessageType") {
        let variant = name
            .strip_prefix("MessageType_Algorand")
            .unwrap_or_else(|| panic!("unexpected MessageType entry: {name}"));
        out.push_str(&format!("    {variant} = {value},\n"));
    }
    out.push_str("    #[num_enum(catch_all)]\n");
    out.push_str("    Unknown(u16),\n");
    out.push_str("}\n\n");

    out.push_str("/// `ButtonRequestType` codes, generated from `protob/common.proto`.\n");
    out.push_str("#[allow(dead_code)]\n");
    out.push_str("#[derive(Copy, Clone, PartialEq, Eq)]\n");
    out.push_str("#[repr(i32)]\n");
    out.push_str("pub enum ButtonRequestType {\n");
    for (name, value) in parse_proto_enum(&common, "ButtonRequestType") {
        out.push_str(&format!("    {name} = {value},\n"));
    }
    out.push_str("}\n\n");
    out.push_str("impl From<ButtonRequestType> for i32 {\n");
    out.push_str("    fn from(value: ButtonRequestType) -> Self {\n");
    out.push_str("        value as i32\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("proto_ids.rs"), out).unwrap();
}

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
    build_proto_ids();
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
