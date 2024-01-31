use std::env;
use std::path::PathBuf;

#[derive(Debug)]
struct MacroCallback {}
impl bindgen::callbacks::ParseCallbacks for MacroCallback {
    fn add_derives(&self, info: &bindgen::callbacks::DeriveInfo<'_>) -> Vec<String> {
        if info.name.contains("_t_enum") {
            vec!["TryFromPrimitive".into()]
        } else {
            vec![]
        }
    }
}

fn search() -> (PathBuf, PathBuf, bool) {
    // used to generate bindings by bindgen
    let header_path = env::var_os("CPC_HEADER_PATH");
    // used to search libcpc by linker and loader
    let library_dir = env::var_os("CPC_LIBRARY_DIR");

    match (header_path, library_dir) {
        (Some(header_path), Some(library_dir)) => (header_path.into(), library_dir.into(), false),
        (_, _) => {
            let maybe_pkg = pkg_config::Config::new().probe("libcpc");
            if let Ok(pkg) = maybe_pkg {
                (
                    pkg.include_paths[0].join("sl_cpc.h"),
                    (&pkg.link_paths[0]).into(),
                    true,
                )
            } else {
                println!("cargo:warning=libcpc - fallback to in-tree search");
                let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
                (
                    // $PWD/../../../sl_cpc.h
                    root.parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .with_file_name("sl_cpc.h"),
                    // $PWD/../../../../build
                    root.parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .parent()
                        .unwrap()
                        .with_file_name("build"),
                    false,
                )
            }
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let (header_path, library_dir, pkgconf_used) = search();

    let bindings = bindgen::Builder::default()
        // this may introduce undefined behavior
        .raw_line("use num_enum::TryFromPrimitive;")
        .parse_callbacks(Box::new(MacroCallback {}))
        .rustified_enum(".*_t_enum")
        .header(header_path.to_str().unwrap())
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_dir.join("bindings.rs").as_path())
        .expect("Unable to write bindings");

    if !pkgconf_used {
        println!(
            "cargo:rustc-link-search=native={}",
            library_dir.to_str().unwrap()
        );
        println!("cargo:rustc-link-lib=dylib=cpc");

        println!("cargo:rerun-if-changed={}", header_path.to_str().unwrap());
    }

    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{}",
        library_dir.to_str().unwrap()
    );

    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#cargorerun-if-changedpath
    println!("cargo:rerun-if-changed=build.rs");
}
