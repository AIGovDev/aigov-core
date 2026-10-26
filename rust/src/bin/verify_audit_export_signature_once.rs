//! Offline helper: verify the Ed25519 signature on a signed
//! `aigov.audit_export.v1` document (plain JSON, not a zip bundle — see
//! `verify_audit_export_bundle_once` for the zip-bundle variant).
//! Usage: `verify_audit_export_signature_once <signed-export.json> <issuer_id> <verifying-key-base64>`
//!
//! No network, no server: the trust store is built in-process from the one
//! verifying key passed on the command line.

use aigov_audit::audit_export_signing::verify_audit_export_ed25519_signature;
use aigov_audit::policy_signing::PolicyTrustStore;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use std::collections::BTreeMap;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!(
            "usage: verify_audit_export_signature_once <signed-export.json> <issuer_id> <verifying-key-base64>"
        );
        std::process::exit(2);
    }
    let path = &args[0];
    let issuer_id = &args[1];
    let vk_b64 = &args[2];

    let txt = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("read {path}: {e}");
        std::process::exit(1);
    });
    let export: Value = serde_json::from_str(&txt).unwrap_or_else(|e| {
        eprintln!("parse json: {e}");
        std::process::exit(1);
    });

    let vk_bytes = base64::engine::general_purpose::STANDARD
        .decode(vk_b64.trim())
        .unwrap_or_else(|e| {
            eprintln!("invalid verifying-key base64: {e}");
            std::process::exit(2);
        });
    let vk_arr: [u8; 32] = vk_bytes.as_slice().try_into().unwrap_or_else(|_| {
        eprintln!("verifying key must be 32 bytes");
        std::process::exit(2);
    });
    let verifying_key = VerifyingKey::from_bytes(&vk_arr).unwrap_or_else(|e| {
        eprintln!("invalid ed25519 verifying key: {e}");
        std::process::exit(2);
    });

    let mut pubkeys: BTreeMap<String, Vec<VerifyingKey>> = BTreeMap::new();
    pubkeys.insert(issuer_id.clone(), vec![verifying_key]);
    let trust = PolicyTrustStore {
        ed25519_pubkeys: pubkeys,
    };

    match verify_audit_export_ed25519_signature(&export, &trust, Some(issuer_id)) {
        Ok(verified_issuer_id) => {
            println!("ok: true");
            println!("signature_verified: true");
            println!("issuer_id: {verified_issuer_id}");
        }
        Err(e) => {
            println!("ok: false");
            println!("signature_verified: false");
            println!("error: {e}");
            std::process::exit(1);
        }
    }
}
