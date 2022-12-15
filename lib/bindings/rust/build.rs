use bindgen::callbacks::ParseCallbacks;
use std::{env, fs, path::PathBuf};

#[derive(Debug)]
struct MacroCallback {}

impl ParseCallbacks for MacroCallback {
    fn add_derives(&self, name: &str) -> Vec<String> {
        if name.contains("_t_enum") {
            vec!["TryFromPrimitive".into()]
        } else {
            vec![]
        }
    }
}

fn main() {
    let libcpc_relative_path = PathBuf::from("../../../build");
    let libcpc_absolute_path =
        PathBuf::from(env::current_dir().unwrap()).join(&libcpc_relative_path);
    let libcpc_absolute_canonical_path = fs::canonicalize(&libcpc_absolute_path).unwrap();

    println!("cargo:rustc-link-lib=dylib=cpc");
    println!(
        "cargo:rustc-link-search=native={}",
        libcpc_absolute_canonical_path.display()
    );

    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../../{}:{}",
        libcpc_relative_path.display(),
        libcpc_absolute_canonical_path.display()
    );

    let bindings = bindgen::Builder::default()
        // Warning rules
        .raw_line("#![allow(non_upper_case_globals)]")
        .raw_line("#![allow(non_camel_case_types)]")
        .raw_line("#![allow(non_snake_case)]")
        // Enum rules
        .raw_line("use num_enum::TryFromPrimitive;")
        .rustified_enum("*_t_enum")
        .parse_callbacks(Box::new(MacroCallback {}))
        // Layout tests rules
        .layout_tests(false)
        // Generation
        .header("../../sl_cpc.h")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(PathBuf::from("./src").join("sl_cpc.rs"))
        .expect("Unable write bindings");
}
