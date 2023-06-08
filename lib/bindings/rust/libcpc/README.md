# Libcpc

This library exports all underlying functions, enums and constants to easily interoperate with the C API of CPC by proving safe Rust wrappers. The dependencies needed to build the library are:

- [Rust](https://www.rust-lang.org/tools/install)
- [Libcpc](../../../readme.md)
- [libclang-dev](https://index.ros.org/d/libclang-dev/)

## Project setup

In order to build the library, we need the path of `sl_cpc.h` and the directory of `libcpc.so`. There are three ways to find them:
 - Look into the environment variables `CPC_HEADER_PATH` and `CPC_LIBRARY_DIR`
 - Search for "libcpc" with pkg-config
 - Fallback into the in-tree `$PWD/../../../build`

Projects that want to use this crate need to do two things:

Add a dependency entry in your `Cargo.toml` pointing to this library, ie:
```
[dependencies]
libcpc = { path = "../../lib/bindings/rust/libcpc" }
```

If `libcpc.so.X` is not installed in a system path, you can tell the dynamic loader where to find it with the `LD_LIBRARY_PATH`.

## Sample app setup

From the root directory, run the following commands:
```
cargo build --example sample_app
cargo run --example sample_app
```
