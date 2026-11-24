//! Audit ledger storage validation.
//!
//! The audit evidence ledger is stored in append-only JSONL files. In hosted deployments,
//! writing to the process working directory is unsafe because container filesystems may be
//! ephemeral. Staging/prod therefore require an explicit, durable base directory.

use crate::govai_environment::GovaiEnvironment;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const LEDGER_DIR_ENV: &str = "GOVAI_LEDGER_DIR";

/// Resolved `GOVAI_LEDGER_DIR` when non-empty after trim.
pub fn configured_ledger_dir() -> Option<PathBuf> {
    env_ledger_dir_raw().map(PathBuf::from)
}

fn env_ledger_dir_raw() -> Option<String> {
    std::env::var(LEDGER_DIR_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn probe_filename() -> String {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(".govai_ledger_probe_{pid}_{nanos}.tmp")
}

fn ensure_dir_exists(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        if !dir.is_dir() {
            return Err(format!(
                "{LEDGER_DIR_ENV} must be a directory path, but it points to a non-directory: {}",
                dir.display()
            ));
        }
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "Failed to create {LEDGER_DIR_ENV} directory {}: {e}",
            dir.display()
        )
    })?;
    Ok(())
}

fn probe_writable(dir: &Path) -> Result<(), String> {
    let probe_path = dir.join(probe_filename());
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&probe_path)
        .map_err(|e| {
            format!(
                "{LEDGER_DIR_ENV} is not writable: failed to create probe file {}: {e}",
                probe_path.display()
            )
        })?;
    f.write_all(b"ok\n").map_err(|e| {
        format!(
            "{LEDGER_DIR_ENV} is not writable: failed to write probe file {}: {e}",
            probe_path.display()
        )
    })?;
    drop(f);
    std::fs::remove_file(&probe_path).map_err(|e| {
        format!(
            "{LEDGER_DIR_ENV} is not writable: failed to remove probe file {}: {e}",
            probe_path.display()
        )
    })?;
    Ok(())
}

/// Validate configured ledger directory (create if missing) and ensure it is writable.
pub fn validate_ledger_dir(dir: &Path) -> Result<(), String> {
    ensure_dir_exists(dir)?;
    probe_writable(dir)?;
    Ok(())
}

/// Read-only check: default tenant ledger file can be opened for read (missing file is OK).
pub fn default_tenant_ledger_readable() -> bool {
    let path = crate::project::resolve_ledger_path("audit_log.jsonl", "default");
    let p = Path::new(&path);
    if !p.exists() {
        return true;
    }
    std::fs::File::open(p).is_ok()
}

/// Non-mutating readiness check for the ledger directory.
///
/// Readiness must not write to the ledger. Writability is proven once at startup by `validate_startup`,
/// which fails closed. This check only confirms that the configured directory is still present. It never
/// creates the directory and never writes a probe file.
pub fn ledger_dir_present_for(configured: Option<&Path>, deployment_env: GovaiEnvironment) -> bool {
    match configured {
        Some(dir) => dir.is_dir(),
        None => matches!(deployment_env, GovaiEnvironment::Dev),
    }
}

/// Readiness form of `ledger_dir_present_for` using `GOVAI_LEDGER_DIR`.
pub fn ledger_dir_present(deployment_env: GovaiEnvironment) -> bool {
    let configured = env_ledger_dir_raw().map(PathBuf::from);
    ledger_dir_present_for(configured.as_deref(), deployment_env)
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn readiness_check_does_not_write_to_a_present_ledger_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("audit_log.jsonl"), "{}\n").unwrap();
        let before = listing(dir.path());
        for _ in 0..5 {
            assert!(ledger_dir_present_for(
                Some(dir.path()),
                GovaiEnvironment::Staging
            ));
        }
        assert_eq!(
            listing(dir.path()),
            before,
            "readiness must not create or delete files"
        );
    }

    #[test]
    fn readiness_does_not_depend_on_write_permission() {
        // The write probe at startup needs write access. Readiness must only read, so a directory that
        // is present but not writable (for example a read-only volume after startup) stays ready.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let ready = ledger_dir_present_for(Some(dir.path()), GovaiEnvironment::Staging);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(ready, "readiness must not require write access");
    }

    #[test]
    fn readiness_check_never_creates_a_missing_directory() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("not-yet");
        assert!(!ledger_dir_present_for(
            Some(&missing),
            GovaiEnvironment::Staging
        ));
        assert!(
            !missing.exists(),
            "readiness must not create the ledger directory"
        );
    }

    #[test]
    fn a_file_in_place_of_the_directory_is_not_ready() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("ledger");
        std::fs::write(&file, "x").unwrap();
        assert!(!ledger_dir_present_for(
            Some(&file),
            GovaiEnvironment::Staging
        ));
    }

    #[test]
    fn unset_directory_is_ready_only_in_dev() {
        assert!(ledger_dir_present_for(None, GovaiEnvironment::Dev));
        assert!(!ledger_dir_present_for(None, GovaiEnvironment::Staging));
        assert!(!ledger_dir_present_for(None, GovaiEnvironment::Prod));
    }
}

/// Startup validation:
/// - **staging/prod**: `GOVAI_LEDGER_DIR` is required and must be a writable directory
/// - **dev**: missing `GOVAI_LEDGER_DIR` is allowed but warns about ephemeral storage risk
pub fn validate_startup(deployment_env: GovaiEnvironment) -> Result<Option<PathBuf>, String> {
    let configured = env_ledger_dir_raw().map(PathBuf::from);

    match deployment_env {
        GovaiEnvironment::Dev => {
            if let Some(ref dir) = configured {
                validate_ledger_dir(dir)?;
                Ok(Some(dir.clone()))
            } else {
                eprintln!(
                    "WARNING: {LEDGER_DIR_ENV} is not set; using local ledger files relative to the process working directory. This is NOT suitable for production: mount persistent storage and set {LEDGER_DIR_ENV}."
                );
                Ok(None)
            }
        }
        GovaiEnvironment::Staging | GovaiEnvironment::Prod => {
            let Some(dir) = configured else {
                return Err(format!(
                    "{LEDGER_DIR_ENV} is required in staging/prod. Ledger storage must be mounted on persistent storage (durable volume/disk). Example: {LEDGER_DIR_ENV}=/var/lib/govai/ledger"
                ));
            };
            validate_ledger_dir(&dir)?;
            Ok(Some(dir))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_env() {
        std::env::remove_var(LEDGER_DIR_ENV);
    }

    #[test]
    fn dev_allows_missing_dir_but_warns() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let r = validate_startup(GovaiEnvironment::Dev).unwrap();
        assert!(r.is_none());
        clear_env();
    }

    #[test]
    fn staging_requires_env_var() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let err = validate_startup(GovaiEnvironment::Staging).unwrap_err();
        assert!(err.contains("GOVAI_LEDGER_DIR is required in staging/prod"));
        clear_env();
    }

    #[test]
    fn staging_accepts_and_creates_writable_dir() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("ledger");
        std::env::set_var(LEDGER_DIR_ENV, sub.to_string_lossy().to_string());

        let out = validate_startup(GovaiEnvironment::Staging).unwrap();
        assert_eq!(out.as_deref(), Some(sub.as_path()));
        assert!(sub.exists());
        assert!(sub.is_dir());
        clear_env();
    }

    #[test]
    fn default_tenant_ledger_readable_missing_file_ok() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(LEDGER_DIR_ENV, dir.path().to_string_lossy().to_string());
        assert!(default_tenant_ledger_readable());
        clear_env();
    }

    #[test]
    fn default_tenant_ledger_readable_existing_file_ok() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(LEDGER_DIR_ENV, dir.path().to_string_lossy().to_string());
        let path = dir.path().join("audit_log__default.jsonl");
        std::fs::write(&path, b"{}\n").unwrap();
        assert!(default_tenant_ledger_readable());
        clear_env();
    }

    #[cfg(unix)]
    #[test]
    fn prod_rejects_non_writable_dir() {
        use std::os::unix::fs::PermissionsExt;

        let _g = ENV_LOCK.lock().unwrap();
        clear_env();
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger");
        std::fs::create_dir_all(&ledger).unwrap();
        let mut perms = std::fs::metadata(&ledger).unwrap().permissions();
        perms.set_mode(0o500); // r-x
        std::fs::set_permissions(&ledger, perms).unwrap();
        std::env::set_var(LEDGER_DIR_ENV, ledger.to_string_lossy().to_string());

        let err = validate_startup(GovaiEnvironment::Prod).unwrap_err();
        assert!(err.contains("not writable"));
        clear_env();
    }
}
