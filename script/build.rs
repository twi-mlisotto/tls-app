use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../program/src");
    println!("cargo:rerun-if-changed=../program/Cargo.toml");

    let elf_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(
        "../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/sp1-https-json-program",
    );

    let skip = env::var("SP1_SKIP_PROGRAM_BUILD").is_ok();

    if !skip && !elf_path.exists() {
        // Only build when the ELF is missing; set SP1_SKIP_PROGRAM_BUILD=1 to
        // skip (e.g. for `cargo clippy` / `cargo check` after initial build).
        let prove_bin = home_sp1_bin().join("cargo-prove");
        let cargo_prove = if prove_bin.exists() {
            prove_bin.to_str().unwrap().to_string()
        } else {
            "cargo-prove".to_string() // hope it's on PATH
        };

        let status = Command::new(&cargo_prove)
            .args(["prove", "build"])
            .current_dir("../program")
            .status()
            .unwrap_or_else(|_| panic!("failed to run {cargo_prove}"));
        assert!(status.success(), "cargo prove build failed");
    }

    // Emit the env var (canonicalize if the file exists; otherwise emit the
    // raw path so clippy/check can complete without the ELF on disk).
    let elf = if elf_path.exists() {
        elf_path.canonicalize().expect("ELF canonicalize failed")
    } else {
        elf_path
    };

    println!(
        "cargo:rustc-env=SP1_ELF_sp1-https-json-program={}",
        elf.display()
    );
}

fn home_sp1_bin() -> PathBuf {
    dirs_next::home_dir().unwrap_or_default().join(".sp1/bin")
}
