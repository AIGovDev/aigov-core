//! Regression: signing binaries must not accept private seeds silently on the command line,
//! must refuse group/world-readable seed files, and must not echo seeds in output.
//!
//! All seeds here are fixed TEST-ONLY values.
#![cfg(unix)]

use aigov_audit::audit_export_signing::verifying_key_from_seed;
use base64::Engine;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const SEED_HEX: &str = "0101010101010101010101010101010101010101010101010101010101010101";

fn expected_pubkey_b64() -> String {
    let seed = [1u8; 32];
    base64::engine::general_purpose::STANDARD.encode(verifying_key_from_seed(&seed).to_bytes())
}

fn pubkey_bin() -> &'static str {
    env!("CARGO_BIN_EXE_signing_pubkey_from_seed_once")
}

fn sign_bin() -> &'static str {
    env!("CARGO_BIN_EXE_sign_audit_export_once")
}

fn write_file(dir: &Path, name: &str, content: &str, mode: u32) -> std::path::PathBuf {
    let p = dir.join(name);
    fs::write(&p, content).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn run_with_stdin(bin: &str, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

fn assert_no_seed_leak(out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(SEED_HEX), "seed leaked to stdout");
    assert!(!stderr.contains(SEED_HEX), "seed leaked to stderr");
}

#[test]
fn pubkey_bin_refuses_seed_on_argv_without_opt_in() {
    let out = Command::new(pubkey_bin()).arg(SEED_HEX).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("refusing"));
    assert!(out.stdout.is_empty(), "no key may be printed without a valid source");
    assert_no_seed_leak(&out);
}

#[test]
fn pubkey_bin_accepts_argv_seed_only_with_explicit_opt_in_and_warns() {
    let out = Command::new(pubkey_bin())
        .args([SEED_HEX, "--allow-seed-argv"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_pubkey_b64());
    assert!(String::from_utf8_lossy(&out.stderr).contains("visible in process listings"));
}

#[test]
fn pubkey_bin_seed_file_with_owner_only_mode_works() {
    let dir = tempfile::tempdir().unwrap();
    let f = write_file(dir.path(), "seed.hex", &format!("{SEED_HEX}\n"), 0o600);
    let out = Command::new(pubkey_bin())
        .args(["--seed-file", f.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_pubkey_b64());
    assert_no_seed_leak(&out);
}

#[test]
fn pubkey_bin_refuses_seed_file_readable_by_group_or_others() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o644u32, 0o640, 0o604] {
        let f = write_file(dir.path(), &format!("seed-{mode:o}.hex"), &format!("{SEED_HEX}\n"), mode);
        let out = Command::new(pubkey_bin())
            .args(["--seed-file", f.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "mode {mode:o} must be refused");
        assert!(out.stdout.is_empty());
        assert_no_seed_leak(&out);
    }
}

#[test]
fn pubkey_bin_reads_seed_from_stdin() {
    let out = run_with_stdin(pubkey_bin(), &["--seed-stdin"], &format!("{SEED_HEX}\n"));
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), expected_pubkey_b64());
    assert_no_seed_leak(&out);
}

#[test]
fn malformed_seed_fails_closed_without_echoing_input() {
    // Too short, and non-hex content.
    for bad in ["0101", "zz01010101010101010101010101010101010101010101010101010101010101"] {
        let out = run_with_stdin(pubkey_bin(), &["--seed-stdin"], bad);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("64 hex characters"));
        assert!(!stderr.contains(bad), "malformed input must not be echoed");
    }
}

#[test]
fn sign_bin_refuses_seed_on_argv_without_opt_in_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_file(dir.path(), "export.json", "{}", 0o600);
    let out_path = dir.path().join("signed.json");
    let out = Command::new(sign_bin())
        .args([
            export.to_str().unwrap(),
            "issuer-a",
            "signer-a",
            SEED_HEX,
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!out_path.exists(), "nothing may be written without a seed source");
    assert_no_seed_leak(&out);
}

#[test]
fn sign_bin_refuses_group_readable_seed_file_before_touching_export() {
    let dir = tempfile::tempdir().unwrap();
    let export = write_file(dir.path(), "export.json", "{}", 0o600);
    let seed = write_file(dir.path(), "seed.hex", &format!("{SEED_HEX}\n"), 0o644);
    let out_path = dir.path().join("signed.json");
    let out = Command::new(sign_bin())
        .args([
            export.to_str().unwrap(),
            "issuer-a",
            "signer-a",
            "--seed-file",
            seed.to_str().unwrap(),
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!out_path.exists());
    assert_no_seed_leak(&out);
}

#[test]
fn sign_bin_with_seed_file_produces_signature_that_verifies() {
    use aigov_audit::audit_export_signing::{verify_audit_export_ed25519_signature};
    use aigov_audit::policy_signing::PolicyTrustStore;
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    let run_id = "run-seed-file-test";
    let events = json!([{
        "event_id": format!("{run_id}-e1"),
        "event_type": "ai_discovery_reported",
        "ts_utc": "2026-01-01T00:00:01Z",
        "actor": "test",
        "system": "test",
        "run_id": run_id,
        "payload": {"openai": false, "transformers": false, "model_artifacts": false}
    }]);
    let events_vec: Vec<aigov_audit::schema::EvidenceEvent> =
        serde_json::from_value(events.clone()).expect("events");
    let events_sha = aigov_audit::bundle::portable_evidence_digest_v1(run_id, &events_vec);
    let export: Value = json!({
        "ok": true,
        "schema_version": "aigov.audit_export.v1",
        "policy_version": "test-policy",
        "environment": "dev",
        "run": {"run_id": run_id},
        "evidence_hashes": {
            "bundle_sha256": "a".repeat(64),
            "events_content_sha256": events_sha,
            "chain_head_record_sha256": "b".repeat(64),
            "log_chain": []
        },
        "decision": {"verdict": "BLOCKED"},
        "evidence_events": events
    });

    let dir = tempfile::tempdir().unwrap();
    let export_path = write_file(dir.path(), "export.json", &export.to_string(), 0o600);
    let seed_path = write_file(dir.path(), "seed.hex", &format!("{SEED_HEX}\n"), 0o600);
    let out_path = dir.path().join("signed.json");
    let out = Command::new(sign_bin())
        .args([
            export_path.to_str().unwrap(),
            "govai-export-signer",
            "test",
            "--seed-file",
            seed_path.to_str().unwrap(),
            out_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_no_seed_leak(&out);

    let signed: Value = serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
    let vk = verifying_key_from_seed(&[1u8; 32]);
    let mut map = BTreeMap::new();
    map.insert("govai-export-signer".to_string(), vec![vk]);
    let trust = PolicyTrustStore { ed25519_pubkeys: map };
    let issuer = verify_audit_export_ed25519_signature(&signed, &trust, None)
        .expect("signature must verify against the public key derived from the seed file");
    assert_eq!(issuer, "govai-export-signer");
}
