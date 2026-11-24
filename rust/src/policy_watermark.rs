//! Anti-rollback for signed policy bundles.
//!
//! A signed bundle stays valid after a newer version replaces it, so an older bundle could be redeployed
//! to restore a weaker policy. This module records the highest accepted version of each policy in
//! `<ledger dir>/policy_watermark.json` and refuses anything older.
//!
//! Rules (staging and production only; development is unchanged):
//! - `version` must be a non-negative integer. Other forms cannot be ordered, so they are refused.
//! - No record for the policy: accept and record it.
//! - Version lower than the record: refuse (rollback).
//! - Same version, same document digest: accept. Re-signing the same content, for example to extend the
//!   expiry, keeps the digest and is allowed.
//! - Same version, different document digest: refuse. Content cannot change without a new version.
//! - Higher version: accept and advance the record.
//! - Record missing: accept as a first start. Record present but unreadable, malformed, or inconsistent:
//!   refuse (fail closed).
//!
//! The record is written atomically (temporary file, fsync, rename) only after the bundle has passed
//! signature verification and the production contract.
//!
//! Limits: the record lives on the ledger volume. Whoever can write that volume can also reset the record,
//! the same trust boundary as the ledger itself. Multiple replicas sharing one volume would also need a
//! lock, which is not implemented.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const WATERMARK_FILE: &str = "policy_watermark.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkEntry {
    pub version: u64,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    pub schema: String,
    pub policies: BTreeMap<String, WatermarkEntry>,
}

/// Parse a policy version for ordering. Only ASCII digits are accepted, so `01`, `+1`, `1.0`, and `v1`
/// are refused rather than guessed at.
pub fn parse_version(raw: &str) -> Result<u64, String> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "policy version {raw:?} is not a non-negative integer; rollback protection requires one"
        ));
    }
    if t.len() > 1 && t.starts_with('0') {
        return Err(format!(
            "policy version {raw:?} has a leading zero; use a plain integer"
        ));
    }
    t.parse::<u64>()
        .map_err(|_| format!("policy version {raw:?} is out of range"))
}

pub fn watermark_path(ledger_dir: &Path) -> PathBuf {
    ledger_dir.join(WATERMARK_FILE)
}

/// Read the record. A missing file is an empty record; any other failure is an error.
pub fn read_watermark(ledger_dir: &Path) -> Result<Watermark, String> {
    let path = watermark_path(ledger_dir);
    if !path.exists() {
        return Ok(Watermark {
            schema: "govai.policy_watermark.v1".to_string(),
            policies: BTreeMap::new(),
        });
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("policy watermark unreadable at {}: {e}", path.display()))?;
    let wm: Watermark = serde_json::from_str(&raw)
        .map_err(|e| format!("policy watermark malformed at {}: {e}", path.display()))?;
    if wm.schema != "govai.policy_watermark.v1" {
        return Err(format!(
            "policy watermark has unsupported schema {:?}",
            wm.schema
        ));
    }
    Ok(wm)
}

fn write_watermark_atomic(ledger_dir: &Path, wm: &Watermark) -> Result<(), String> {
    let path = watermark_path(ledger_dir);
    let tmp = ledger_dir.join(format!("{WATERMARK_FILE}.tmp"));
    let body = serde_json::to_vec_pretty(wm).map_err(|e| e.to_string())?;
    {
        let mut f = std::fs::File::create(&tmp)
            .map_err(|e| format!("policy watermark write failed: {e}"))?;
        f.write_all(&body)
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("policy watermark write failed: {e}"))?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("policy watermark commit failed: {e}"))?;
    if let Ok(dir) = std::fs::File::open(ledger_dir) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Decide whether a verified bundle may be served, and advance the record when it may.
///
/// Call only after signature verification and the production contract have passed.
pub fn enforce(
    ledger_dir: &Path,
    policy_id: &str,
    version_raw: &str,
    digest_sha256: &str,
) -> Result<(), String> {
    let version = parse_version(version_raw)?;
    let mut wm = read_watermark(ledger_dir)?;
    let existing = wm.policies.get(policy_id).cloned();
    match existing {
        None => {
            wm.policies.insert(
                policy_id.to_string(),
                WatermarkEntry {
                    version,
                    digest_sha256: digest_sha256.to_string(),
                },
            );
            write_watermark_atomic(ledger_dir, &wm)
        }
        Some(entry) if version < entry.version => Err(format!(
            "rollback refused: bundle version {version} for policy {policy_id:?} is older than the accepted version {}",
            entry.version
        )),
        Some(entry) if version == entry.version => {
            if entry.digest_sha256 == digest_sha256 {
                Ok(())
            } else {
                Err(format!(
                    "same-version content change refused: policy {policy_id:?} version {version} has a different document digest than the one accepted"
                ))
            }
        }
        Some(_) => {
            wm.policies.insert(
                policy_id.to_string(),
                WatermarkEntry {
                    version,
                    digest_sha256: digest_sha256.to_string(),
                },
            );
            write_watermark_atomic(ledger_dir, &wm)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    #[test]
    fn version_must_be_a_plain_non_negative_integer() {
        assert_eq!(parse_version("1").unwrap(), 1);
        assert_eq!(parse_version("0").unwrap(), 0);
        assert_eq!(parse_version("42").unwrap(), 42);
        for bad in [
            "",
            "v1",
            "1.0",
            "+1",
            "-1",
            "01",
            "1a",
            " ",
            "99999999999999999999999",
        ] {
            assert!(parse_version(bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn first_start_records_the_version() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        let wm = read_watermark(dir.path()).unwrap();
        assert_eq!(wm.policies["p"].version, 1);
        assert_eq!(wm.policies["p"].digest_sha256, D1);
    }

    #[test]
    fn higher_version_advances_and_lower_version_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        enforce(dir.path(), "p", "2", D2).unwrap();
        let err = enforce(dir.path(), "p", "1", D1).unwrap_err();
        assert!(err.contains("rollback refused"), "{err}");
        assert_eq!(read_watermark(dir.path()).unwrap().policies["p"].version, 2);
    }

    #[test]
    fn same_version_same_content_is_allowed_for_resigning() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "3", D1).unwrap();
        enforce(dir.path(), "p", "3", D1).unwrap();
    }

    #[test]
    fn same_version_different_content_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "3", D1).unwrap();
        let err = enforce(dir.path(), "p", "3", D2).unwrap_err();
        assert!(err.contains("same-version content change refused"), "{err}");
    }

    #[test]
    fn policies_are_tracked_independently() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "a", "5", D1).unwrap();
        enforce(dir.path(), "b", "1", D2).unwrap();
        assert!(enforce(dir.path(), "a", "4", D1).is_err());
        assert!(enforce(dir.path(), "b", "1", D2).is_ok());
    }

    #[test]
    fn corrupt_record_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(watermark_path(dir.path()), "{ not json").unwrap();
        let err = enforce(dir.path(), "p", "1", D1).unwrap_err();
        assert!(err.contains("malformed"), "{err}");
    }

    #[test]
    fn unknown_fields_in_the_record_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            watermark_path(dir.path()),
            r#"{"schema":"govai.policy_watermark.v1","policies":{},"extra":1}"#,
        )
        .unwrap();
        assert!(enforce(dir.path(), "p", "1", D1).is_err());
    }

    #[test]
    fn missing_ledger_directory_is_refused_not_created() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("nope");
        assert!(enforce(&missing, "p", "1", D1).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        assert!(!dir.path().join(format!("{WATERMARK_FILE}.tmp")).exists());
    }
}
