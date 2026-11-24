//! Anti-rollback for signed policy bundles: a monotonic, durable revision record.
//!
//! A signed bundle stays valid after a newer revision replaces it, so an older bundle could be
//! redeployed to restore a weaker policy. This module records the highest accepted revision of each
//! policy in `<ledger dir>/policy_watermark.json` and refuses anything older.
//!
//! ## Semantics
//!
//! - `version` must be a plain non-negative integer. Other forms cannot be ordered, so they are refused.
//! - No record for the policy: accept and record it.
//! - Revision lower than the record: refuse (`rollback refused`).
//! - Same revision, same document digest: accept without writing (idempotent). Re-signing the same content,
//!   for example to extend the expiry or to rotate the signing key, keeps the digest.
//! - Same revision, different document digest: refuse. Content cannot change without a new revision.
//! - Higher revision: accept and advance the record.
//! - A verified bundle that is not activated (for example, startup fails later) leaves the record unchanged.
//!   Only `Pending::commit`, called after the whole service has started, advances the record.
//! - Missing record while the ledger already holds data: refuse. That combination means the record was lost,
//!   and a first start cannot be assumed. Missing record with an empty ledger: first start.
//! - Corrupt, unreadable, or unknown-field record: refuse (fail closed).
//!
//! The document digest excludes the `signatures` array, so trust-store changes and signing-key rotation do
//! not reset the record. The record is keyed by `policy_id`, not by key.
//!
//! ## Concurrency and durability
//!
//! `check` reads the record for a fast refusal. `commit` takes an exclusive `flock` on
//! `policy_watermark.lock`, re-reads the record, applies the same decision again, and writes the new record
//! atomically (temporary file, fsync, rename, directory fsync). Two processes committing at once are serialized,
//! so the later commit cannot move the record backwards.
//!
//! ## Limits
//!
//! - The record lives on the ledger volume. Whoever can write that volume can reset it, which is the same trust
//!   boundary as the ledger itself. Deleting the record while ledger data remains is refused.
//! - The lock is a local `flock`. It serializes instances that share one filesystem. It does not protect across
//!   hosts. Several replicas on separate volumes each keep their own record.
//! - No PostgreSQL table is used for this record. The ledger volume is the existing durable store for the
//!   service's evidence, and a database table would add a migration and a second trust boundary. A
//!   multi-host deployment needs a shared store with a row lock, which is not implemented.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const WATERMARK_FILE: &str = "policy_watermark.json";
pub const LOCK_FILE: &str = "policy_watermark.lock";
const SCHEMA: &str = "govai.policy_watermark.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatermarkEntry {
    pub version: u64,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Watermark {
    pub schema: String,
    pub policies: BTreeMap<String, WatermarkEntry>,
}

impl Watermark {
    fn empty() -> Self {
        Watermark {
            schema: SCHEMA.to_string(),
            policies: BTreeMap::new(),
        }
    }
}

/// Parse a policy version for ordering. Only ASCII digits are accepted, so `01`, `+1`, `1.0`, `v1`, and
/// `-1` are refused rather than guessed at.
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

fn lock_path(ledger_dir: &Path) -> PathBuf {
    ledger_dir.join(LOCK_FILE)
}

/// True when the ledger directory already holds evidence (tenant ledger files).
fn ledger_has_data(ledger_dir: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(ledger_dir) else {
        return false;
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let name = name.to_string_lossy();
        name.starts_with("audit_log") && name.ends_with(".jsonl")
    })
}

/// Read the record. A missing record is a first start only when the ledger holds no data.
pub fn read_watermark(ledger_dir: &Path) -> Result<Watermark, String> {
    if !ledger_dir.is_dir() {
        return Err(format!(
            "policy watermark: ledger directory {} is not present; rollback protection cannot be established",
            ledger_dir.display()
        ));
    }
    let path = watermark_path(ledger_dir);
    if !path.exists() {
        if ledger_has_data(ledger_dir) {
            return Err(format!(
                "policy watermark is missing at {} but the ledger already holds data; refusing to assume a first start",
                path.display()
            ));
        }
        return Ok(Watermark::empty());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| format!("policy watermark unreadable at {}: {e}", path.display()))?;
    let wm: Watermark = serde_json::from_str(&raw)
        .map_err(|e| format!("policy watermark malformed at {}: {e}", path.display()))?;
    if wm.schema != SCHEMA {
        return Err(format!(
            "policy watermark has unsupported schema {:?}",
            wm.schema
        ));
    }
    Ok(wm)
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Record is already at this revision with the same content: nothing to write.
    Idempotent,
    /// No record for the policy, or a higher revision: record this revision.
    Advance,
}

fn decide(wm: &Watermark, policy_id: &str, version: u64, digest: &str) -> Result<Decision, String> {
    match wm.policies.get(policy_id) {
        None => Ok(Decision::Advance),
        Some(entry) if version < entry.version => Err(format!(
            "rollback refused: bundle version {version} for policy {policy_id:?} is older than the accepted version {}",
            entry.version
        )),
        Some(entry) if version == entry.version => {
            if entry.digest_sha256 == digest {
                Ok(Decision::Idempotent)
            } else {
                Err(format!(
                    "same-version content change refused: policy {policy_id:?} version {version} has a different document digest than the one accepted"
                ))
            }
        }
        Some(_) => Ok(Decision::Advance),
    }
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

/// A verified bundle's revision, checked but not yet recorded. Dropping it records nothing.
#[derive(Debug)]
pub struct Pending {
    ledger_dir: PathBuf,
    policy_id: String,
    version: u64,
    digest_sha256: String,
}

/// Fast refusal: validate the revision against the current record. Writes nothing.
pub fn check(
    ledger_dir: &Path,
    policy_id: &str,
    version_raw: &str,
    digest_sha256: &str,
) -> Result<Pending, String> {
    let version = parse_version(version_raw)?;
    let wm = read_watermark(ledger_dir)?;
    decide(&wm, policy_id, version, digest_sha256)?;
    Ok(Pending {
        ledger_dir: ledger_dir.to_path_buf(),
        policy_id: policy_id.to_string(),
        version,
        digest_sha256: digest_sha256.to_string(),
    })
}

impl Pending {
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Record the revision under an exclusive lock. Re-reads and re-decides, so a concurrent commit
    /// cannot move the record backwards.
    pub fn commit(self) -> Result<(), String> {
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path(&self.ledger_dir))
            .map_err(|e| format!("policy watermark lock unavailable: {e}"))?;
        lock_exclusive(&lock)?;
        // The lock is released when `lock` is dropped at the end of this function.
        let mut wm = read_watermark(&self.ledger_dir)?;
        match decide(&wm, &self.policy_id, self.version, &self.digest_sha256)? {
            Decision::Idempotent => Ok(()),
            Decision::Advance => {
                wm.policies.insert(
                    self.policy_id.clone(),
                    WatermarkEntry {
                        version: self.version,
                        digest_sha256: self.digest_sha256.clone(),
                    },
                );
                write_watermark_atomic(&self.ledger_dir, &wm)
            }
        }
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &std::fs::File) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `file` is a valid open descriptor for the duration of the call.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "policy watermark lock failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(unix))]
fn lock_exclusive(_file: &std::fs::File) -> Result<(), String> {
    Err(
        "policy watermark requires a platform with flock; refusing to run without the lock"
            .to_string(),
    )
}

/// Check and record in one step. Used by tests; startup uses `check` and defers `commit` to the end.
pub fn enforce(
    ledger_dir: &Path,
    policy_id: &str,
    version_raw: &str,
    digest_sha256: &str,
) -> Result<(), String> {
    check(ledger_dir, policy_id, version_raw, digest_sha256)?.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn record(dir: &Path) -> Watermark {
        read_watermark(dir).unwrap()
    }

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
    fn first_start_records_the_revision() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        assert_eq!(record(dir.path()).policies["p"].version, 1);
        assert_eq!(record(dir.path()).policies["p"].digest_sha256, D1);
    }

    #[test]
    fn revision_1_to_2_is_accepted_and_2_to_1_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        enforce(dir.path(), "p", "2", D2).unwrap();
        let err = enforce(dir.path(), "p", "1", D1).unwrap_err();
        assert!(err.contains("rollback refused"), "{err}");
        assert_eq!(record(dir.path()).policies["p"].version, 2);
    }

    #[test]
    fn same_revision_same_content_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "2", D1).unwrap();
        let before = std::fs::read(watermark_path(dir.path())).unwrap();
        enforce(dir.path(), "p", "2", D1).unwrap();
        assert_eq!(
            std::fs::read(watermark_path(dir.path())).unwrap(),
            before,
            "idempotent reapply must not rewrite"
        );
    }

    #[test]
    fn same_revision_different_content_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "2", D1).unwrap();
        let err = enforce(dir.path(), "p", "2", D2).unwrap_err();
        assert!(err.contains("same-version content change refused"), "{err}");
    }

    #[test]
    fn a_checked_but_uncommitted_revision_changes_nothing() {
        // Failed activation: the bundle verified, but startup failed before commit.
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        let pending = check(dir.path(), "p", "2", D2).unwrap();
        assert_eq!(pending.version(), 2);
        drop(pending);
        assert_eq!(
            record(dir.path()).policies["p"].version,
            1,
            "failed activation must not advance"
        );
    }

    #[test]
    fn a_rejected_check_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "3", D1).unwrap();
        assert!(check(dir.path(), "p", "2", D1).is_err());
        assert_eq!(record(dir.path()).policies["p"].version, 3);
    }

    #[test]
    fn restart_retains_the_accepted_revision() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "5", D1).unwrap();
        // A new process reads the same file.
        assert!(check(dir.path(), "p", "4", D1).is_err());
        assert!(check(dir.path(), "p", "5", D1).is_ok());
    }

    #[test]
    fn concurrent_commits_cannot_move_the_record_backwards() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        let path = dir.path().to_path_buf();
        // Each thread checks against revision 1, as two processes started together would, then commits.
        let mut handles = Vec::new();
        for i in 0..16u64 {
            let p = path.clone();
            handles.push(std::thread::spawn(move || {
                let version = (i % 8) + 2; // revisions 2..=9, several copies of each
                let digest = format!("{:0>64}", version);
                if let Ok(pending) = check(&p, "p", &version.to_string(), &digest) {
                    let _ = pending.commit();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_version = record(dir.path()).policies["p"].version;
        assert_eq!(final_version, 9, "the highest committed revision must win");
        assert!(enforce(dir.path(), "p", "8", &format!("{:0>64}", 8)).is_err());
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
    fn missing_record_with_ledger_data_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("audit_log__tenant-a.jsonl"), "{}\n").unwrap();
        let err = enforce(dir.path(), "p", "1", D1).unwrap_err();
        assert!(err.contains("refusing to assume a first start"), "{err}");
        assert!(
            !watermark_path(dir.path()).exists(),
            "must not create a record over lost state"
        );
    }

    #[test]
    fn missing_record_with_empty_ledger_is_a_first_start() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
    }

    #[test]
    fn missing_ledger_directory_is_refused_not_created() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("nope");
        assert!(enforce(&missing, "p", "1", D1).is_err());
        assert!(!missing.exists());
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
    fn no_temporary_file_is_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        enforce(dir.path(), "p", "1", D1).unwrap();
        assert!(!dir.path().join(format!("{WATERMARK_FILE}.tmp")).exists());
    }
}
