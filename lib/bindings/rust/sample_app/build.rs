use std::{env, fs, path::PathBuf};
    
fn main() {
    let libcpc_relative_path = PathBuf::from("../../../../build");
    let libcpc_absolute_path = PathBuf::from(env::current_dir().unwrap()).join(&libcpc_relative_path);
    let libcpc_absolute_canonical_path = fs::canonicalize(&libcpc_absolute_path).unwrap();

    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN/../../{}:{}",
        libcpc_relative_path.display(), libcpc_absolute_canonical_path.display()
    );
}