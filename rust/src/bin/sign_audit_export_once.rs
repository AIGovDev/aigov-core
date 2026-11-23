//! Offline helper: Ed25519-sign an `aigov.audit_export.v1` document in place.
//!
//! Usage:
//!   sign_audit_export_once <export.json> <issuer_id> <signer> --seed-file <path> [out.json]
//!   sign_audit_export_once <export.json> <issuer_id> <signer> --seed-stdin [out.json]
//!   sign_audit_export_once <export.json> <issuer_id> <signer> <seed-hex> --allow-seed-argv [out.json]   (legacy)
//!
//! The seed is never accepted silently on the command line: a seed in argv is visible in
//! process listings and shell history, so it requires the explicit `--allow-seed-argv` flag.
//! Seed files must not be readable by group or others (Unix).

use aigov_audit::audit_export_signing::{
    parse_seed_hex_strict, read_seed_hex_file, read_seed_hex_from_reader, sign_audit_export_ed25519,
    signing_key_from_seed,
};
use serde_json::Value;
use std::path::PathBuf;

const USAGE: &str = "usage: sign_audit_export_once <export.json> <issuer_id> <signer> \
(--seed-file <path> | --seed-stdin | <seed-hex> --allow-seed-argv) [out.json]";

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

    let sources = [seed_file.is_some(), seed_stdin, allow_argv];
    if sources.iter().filter(|x| **x).count() != 1 {
        fail(&format!(
            "refusing: choose exactly one seed source (--seed-file, --seed-stdin, or --allow-seed-argv).\n{USAGE}"
        ));
    }

    let (export_path, issuer_id, signer) = match positional.as_slice() {
        [e, i, s, ..] => (e.clone(), i.clone(), s.clone()),
        _ => fail(USAGE),
    };

    let (seed, out_path) = if let Some(path) = seed_file {
        let seed = read_seed_hex_file(&path).unwrap_or_else(|e| fail(&format!("seed: {e}")));
        (seed, positional.get(3).cloned().unwrap_or_else(|| export_path.clone()))
    } else if seed_stdin {
        let seed = read_seed_hex_from_reader(std::io::stdin())
            .unwrap_or_else(|e| fail(&format!("seed: {e}")));
        (seed, positional.get(3).cloned().unwrap_or_else(|| export_path.clone()))
    } else {
        eprintln!(
            "warning: seed given on the command line is visible in process listings and shell history; \
prefer --seed-file or --seed-stdin"
        );
        let seed_arg = positional
            .get(3)
            .cloned()
            .unwrap_or_else(|| fail(&format!("missing seed argument\n{USAGE}")));
        let seed = parse_seed_hex_strict(&seed_arg).unwrap_or_else(|e| fail(&format!("seed: {e}")));
        (seed, positional.get(4).cloned().unwrap_or_else(|| export_path.clone()))
    };

    let txt = std::fs::read_to_string(&export_path).unwrap_or_else(|e| {
        eprintln!("read {export_path}: {}", e.kind());
        std::process::exit(1);
    });
    let mut export: Value = serde_json::from_str(&txt).unwrap_or_else(|e| {
        eprintln!("parse json: {e}");
        std::process::exit(1);
    });

    let signing_key = signing_key_from_seed(&seed);
    let created_at_utc = chrono::Utc::now().to_rfc3339();

    if let Err(e) = sign_audit_export_ed25519(
        &mut export,
        &issuer_id,
        &signer,
        &signing_key,
        &created_at_utc,
        None,
    ) {
        eprintln!("sign failed: {e}");
        std::process::exit(1);
    }

    std::fs::write(
        &out_path,
        serde_json::to_string_pretty(&export).expect("json"),
    )
    .unwrap_or_else(|e| {
        eprintln!("write {out_path}: {}", e.kind());
        std::process::exit(1);
    });

    println!("signed {out_path} as issuer_id={issuer_id} signer={signer}");
}
