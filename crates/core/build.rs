use std::io::Write;
use std::path::{Component, Path, PathBuf};

const TABLE: &str = "src/views/assets.rs";
const MACRO: &str = "gzip!(\"";
const WORKSPACE: &str = "../..";

fn main() {
    println!("cargo:rerun-if-changed={TABLE}");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let table = std::fs::read_to_string(TABLE).expect("asset table is readable");
    for (start, _) in table.match_indices(MACRO) {
        let rest = &table[start + MACRO.len()..];
        let name = &rest[..rest.find('"').expect("gzip! path is a string literal")];
        assert!(
            Path::new(name)
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
            "embedded asset {name} must be a plain workspace-relative path"
        );
        let source = Path::new(WORKSPACE).join(name);
        println!("cargo:rerun-if-changed={}", source.display());
        let body = std::fs::read(&source).unwrap_or_else(|e| panic!("embedded asset {name}: {e}"));
        let mut encoder = flate2::GzBuilder::new().write(Vec::new(), flate2::Compression::best());
        encoder.write_all(&body).expect("in-memory gzip");
        let mut target = out.join(name);
        std::fs::create_dir_all(target.parent().expect("asset path has a parent"))
            .expect("OUT_DIR is writable");
        target.as_mut_os_string().push(".gz");
        std::fs::write(&target, encoder.finish().expect("in-memory gzip"))
            .expect("OUT_DIR is writable");
    }
}
