//! Policy rollback across two volumes (issue #501, A2), on real separate filesystems.
//!
//! The ledger directories are `AIGOV_TEST_VOLUME_A` and `AIGOV_TEST_VOLUME_B`, which must be on different devices. The
//! PostgreSQL policy anchor is shared, which is the point: the row is the authority, and the filesystem records are not.
//!
//! Run through `make two-volume-rollback`, which creates and detaches the volumes. Ignored by default: it needs
//! `AIGOV_TEST_PG_ADMIN_URL`, which creates its own database.

mod common;

use serde_json::json;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn revision(version: &str) -> serde_json::Value {
    let mut doc = common::base_policy();
    doc["version"] = json!(version);
    common::sign_v1(&mut doc, "ci", common::created_at(), None);
    doc
}

fn bundle_for(dir: &Path, version: &str) -> PathBuf {
    let sub = dir.join(format!("rev-{version}"));
    std::fs::create_dir_all(&sub).unwrap();
    common::write_bundle(&sub, &revision(version))
}

/// Start a separate Core process against one ledger directory and one bundle, with the shared database. A start succeeds
/// once `/health` answers; a refused start is a process that exits, and its error text is returned. Each start is its own
/// process, as an operator would run it: the API-key configuration is process-wide and is set once.
fn start(ledger: &Path, bundle: &Path, db: &str) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    common::environment_env(ledger, Some(bundle), "prod");
    std::env::set_var("GOVAI_DATABASE_URL", db);
    std::env::set_var("GOVAI_AUTO_MIGRATE", "true");
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let log_path = ledger.parent().unwrap().join(format!("core-{port}.log"));
    let log = std::fs::File::create(&log_path).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_aigov_audit"))
        .env("AIGOV_BIND", format!("127.0.0.1:{port}"))
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .stdin(Stdio::null())
        .spawn()
        .expect("spawn aigov_audit");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(_status) = child.try_wait().unwrap() {
            let text = std::fs::read_to_string(&log_path).unwrap_or_default();
            return Err(text.lines().filter(|l| !l.trim().is_empty()).last().unwrap_or("").to_string());
        }
        if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            if out.starts_with("HTTP/1.1 200") {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(());
            }
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("timed out waiting for /health".to_string());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn watermark_version(ledger: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(ledger.join("policy_watermark.json")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    v["policies"]["tb-policy"]["version"].as_u64().map(|n| n.to_string())
}

#[tokio::test]
#[ignore = "needs AIGOV_TEST_PG_ADMIN_URL and two volumes on different devices (make two-volume-rollback)"]
async fn rollback_across_two_volumes_is_refused_and_recovers_from_the_anchor() {
    let a = PathBuf::from(std::env::var("AIGOV_TEST_VOLUME_A").expect("AIGOV_TEST_VOLUME_A"));
    let b = PathBuf::from(std::env::var("AIGOV_TEST_VOLUME_B").expect("AIGOV_TEST_VOLUME_B"));
    let dev_a = std::fs::metadata(&a).expect("volume A").dev();
    let dev_b = std::fs::metadata(&b).expect("volume B").dev();
    assert_ne!(dev_a, dev_b, "the two ledger directories must be on different filesystems");

    let db = common::fresh_database_url().await.expect("AIGOV_TEST_PG_ADMIN_URL");
    let work = tempfile::tempdir().unwrap();
    let rev1 = bundle_for(work.path(), "1");
    let rev2 = bundle_for(work.path(), "2");
    let ledger_a = a.join("ledger");
    let ledger_b = b.join("ledger");
    std::fs::create_dir_all(&ledger_a).unwrap();
    std::fs::create_dir_all(&ledger_b).unwrap();

    // 1. Volume B starts on revision 1. The shared anchor records revision 1.
    start(&ledger_b, &rev1, &db).expect("first start on B with revision 1");
    // 2. Volume A starts on revision 2. The anchor advances to revision 2.
    start(&ledger_a, &rev2, &db).expect("start on A with revision 2");
    assert_eq!(watermark_version(&ledger_a).as_deref(), Some("2"));

    // 3. Rollback on B: its own record says 1, the anchor says 2. Revision 1 must be refused.
    let err = start(&ledger_b, &rev1, &db).expect_err("rollback to revision 1 on B must be refused");
    eprintln!("refused on B (rollback to 1): {err}");
    assert!(err.to_lowercase().contains("rollback") || err.to_lowercase().contains("older") || err.contains("anchor"), "{err}");
    assert_eq!(watermark_version(&ledger_b).as_deref(), Some("1"), "a refused start must not change B's record");

    // 4. Rollback on A: revision 1 must be refused there too.
    let err_a = start(&ledger_a, &rev1, &db).expect_err("rollback to revision 1 on A must be refused");
    eprintln!("refused on A (rollback to 1): {err_a}");
    assert_eq!(watermark_version(&ledger_a).as_deref(), Some("2"));

    // 5. Restored older volume: B holds revision 1, the anchor holds 2. Starting B on revision 2 is accepted, and B's
    //    record is brought forward from the anchor.
    start(&ledger_b, &rev2, &db).expect("B brought forward to revision 2 from the anchor");
    assert_eq!(watermark_version(&ledger_b).as_deref(), Some("2"));

    // 6. Deleted record on A: refused without the anchor, restored from it with the anchor. Revision 1 is refused,
    //    revision 2 is accepted and the record comes back.
    std::fs::remove_file(ledger_a.join("policy_watermark.json")).unwrap();
    let err_d = start(&ledger_a, &rev1, &db).expect_err("revision 1 after a deleted record must be refused");
    eprintln!("refused on A (deleted record, revision 1): {err_d}");
    start(&ledger_a, &rev2, &db).expect("revision 2 after a deleted record");
    assert_eq!(watermark_version(&ledger_a).as_deref(), Some("2"));
}
