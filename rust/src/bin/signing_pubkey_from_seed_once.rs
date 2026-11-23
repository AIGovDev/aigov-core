//! Tiny offline helper: print the base64 Ed25519 verifying key for a seed.
//!
//! Usage:
//!   signing_pubkey_from_seed_once --seed-file <path>
//!   signing_pubkey_from_seed_once --seed-stdin
//!   signing_pubkey_from_seed_once <seed-hex> --allow-seed-argv     (legacy)
//!
//! See sign_audit_export_once for the seed-handling rules.
use aigov_audit::audit_export_signing::{
    parse_seed_hex_strict, read_seed_hex_file, read_seed_hex_from_reader, verifying_key_from_seed,
};
use base64::Engine;
use std::path::PathBuf;

const USAGE: &str = "usage: signing_pubkey_from_seed_once (--seed-file <path> | --seed-stdin | <seed-hex> --allow-seed-argv)";

fn fail(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut seed_file: Option<PathBuf> = None;
    let mut seed_stdin = false;
    let mut allow_argv = false;
    let mut positional: Vec<String> = Vec::new();
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seed-file" => match it.next() {
                Some(p) => seed_file = Some(PathBuf::from(p)),
                None => fail(USAGE),
            },
            "--seed-stdin" => seed_stdin = true,
            "--allow-seed-argv" => allow_argv = true,
            _ => positional.push(arg),
        }
    }

    let seed = if let Some(path) = seed_file {
        read_seed_hex_file(&path).unwrap_or_else(|e| fail(&format!("seed: {e}")))
    } else if seed_stdin {
        read_seed_hex_from_reader(std::io::stdin()).unwrap_or_else(|e| fail(&format!("seed: {e}")))
    } else if allow_argv {
        eprintln!(
            "warning: seed given on the command line is visible in process listings and shell history; \
prefer --seed-file or --seed-stdin"
        );
        let arg = positional
            .first()
            .cloned()
            .unwrap_or_else(|| fail(USAGE));
        parse_seed_hex_strict(&arg).unwrap_or_else(|e| fail(&format!("seed: {e}")))
    } else {
        fail(&format!(
            "refusing: no seed source. Use --seed-file or --seed-stdin.\n{USAGE}"
        ))
    };

    let vk = verifying_key_from_seed(&seed);
    println!(
        "{}",
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
    );
}
