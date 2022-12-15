# Sample app

## Configuration

In `Cargo.toml`, the following path must point to the rust library:

`libcpc = { version = "0.1.0", path = ".." }`

In `build.rs`, the following path must point to the location of `libcpc.so` (ie. the build folder of [CPCd](../../../../readme.md)):

`let libcpc_relative_path = PathBuf::from("../../../../build");`

## Usage

If this folder is not moved, it should run as is:

`cargo run`