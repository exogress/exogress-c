extern crate cbindgen;

use std::env;

use cbindgen::Language;

fn main() {
    let out_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let version = env::var("EXOGRESS_VERSION")
        .ok()
        .and_then(|v| {
            //Empty string in fact means None
            if v.is_empty() {
                None
            } else {
                Some(v)
            }
        })
        .or_else(|| env::var("CARGO_PKG_VERSION").ok())
        .expect("Failed to generate version");
    println!("cargo:rustc-env=EXOGRESS_VERSION={}", version);

    let path = format!("{}/{}", out_dir, "exogress.h");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libwasmer.dylib");

    match cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(Language::C)
        .with_header(&format!(
            "\
             #ifdef __cplusplus\n\
             extern \"C\" {{\n\
             #endif\n\n\
             #define EXOGRESS_HEADER_VERSION \"{}\"",
            version
        ))
        .with_trailer(
            "#ifdef __cplusplus\n\
             }\n\
             #endif\n",
        )
        .generate()
    {
        Ok(r) => {
            r.write_to_file(path);
        }
        Err(e) => panic!("Could not generate bindings with cbindgen: {:?}", e),
    }
}
