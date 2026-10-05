//! Offline helper: Ed25519-sign an `aigov.audit_export.v1` document in place.
//! Usage: `sign_audit_export_once <export.json> <issuer_id> <signer> <seed-hex-32-bytes> [out.json]`
//!
//! Wires up `audit_export_signing::sign_audit_export_ed25519`, which previously
//! had no caller outside `#[cfg(test)]`. Writes the same document back out with
//! a `signatures` array appended — nothing else about the export changes, so
//! `replay_audit_export_once` still replays it exactly as before.

use aigov_audit::audit_export_signing::{sign_audit_export_ed25519, signing_key_from_seed};
use serde_json::Value;

fn parse_seed_hex(s: &str) -> [u8; 32] {
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| {
                eprintln!("seed-hex must be 64 hex chars (32 bytes)");
                std::process::exit(2);
            })
        })
        .collect::<Vec<u8>>();
    bytes.try_into().unwrap_or_else(|_| {
        eprintln!("seed-hex must be 64 hex chars (32 bytes)");
        std::process::exit(2);
    })
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        eprintln!(
            "usage: sign_audit_export_once <export.json> <issuer_id> <signer> <seed-hex-32-bytes> [out.json]"
        );
        std::process::exit(2);
    }
    let path = &args[0];
    let issuer_id = &args[1];
    let signer = &args[2];
    let seed = parse_seed_hex(&args[3]);
    let out_path = args.get(4).cloned().unwrap_or_else(|| path.clone());

    let txt = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("read {path}: {e}");
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
        issuer_id,
        signer,
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
        eprintln!("write {out_path}: {e}");
        std::process::exit(1);
    });

    println!("signed {out_path} as issuer_id={issuer_id} signer={signer}");
}
