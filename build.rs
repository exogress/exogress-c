extern crate cbindgen;

use std::{
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
};

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
        .or_else(|| {
            env::var("CARGO_PKG_VERSION")
                .ok()
                .map(|cargo_version| format!("{}-DEV", cargo_version))
        })
        .expect("Failed to generate version");
    println!("cargo:rustc-env=EXOGRESS_VERSION={}", version);

    let path = format!("{}/{}", out_dir, "exogress.h");

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

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
