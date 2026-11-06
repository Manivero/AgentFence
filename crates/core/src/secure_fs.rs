//! Restrict AgentFence local state to the current OS user.
//!
//! SECURITY: this module is the only place that establishes filesystem
//! protection for the approval store, the audit store and their auxiliary
//! files. It never assumes Unix permission semantics on Windows.
//!
//! What it guarantees:
//!
//! - **Windows** — the directory's ACL is replaced with a single access entry
//!   for the current user (`icacls /inheritance:r /grant:r <user>:F`), so
//!   inherited rights from `%APPDATA%` (which include `SYSTEM` and
//!   `Administrators`) are removed. Files created inside inherit that ACL.
//! - **Unix** — the directory is `0700` and database files are `0600`, so only
//!   the owning user can traverse the directory or read its contents.
//!
//! What it does **not** guarantee: protection from the OS administrator, from
//! another process running as the same user, or from a user who has already
//! obtained read access before the directory was restricted. Those are outside
//! the cooperative trust boundary and are documented as such.

use std::io;
use std::path::{Path, PathBuf};

/// Outcome of a filesystem protection attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionReport {
    pub path: PathBuf,
    /// True when the current user is the only account that can read the path.
    pub restricted_to_current_user: bool,
    /// Human-readable problems. Empty when protection was established.
    pub issues: Vec<String>,
}

impl PermissionReport {
    fn ok(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            restricted_to_current_user: true,
            issues: Vec::new(),
        }
    }

    fn failed(path: &Path, issue: String) -> Self {
        Self {
            path: path.to_path_buf(),
            restricted_to_current_user: false,
            issues: vec![issue],
        }
    }

    pub fn is_secure(&self) -> bool {
        self.restricted_to_current_user && self.issues.is_empty()
    }
}

/// Create `path` if necessary and restrict it to the current OS user.
///
/// SECURITY: a directory that already exists is **never** re-written. On
/// Windows, `icacls /inheritance:r` applied to a directory also strips the
/// inherited ACEs of every child object, which leaves pre-existing files with
/// an empty DACL and locks the operator out of their own data. A pre-existing
/// directory is therefore reported as unverified instead of being modified.
pub fn secure_dir(path: &Path) -> io::Result<PermissionReport> {
    if path.exists() {
        return Ok(PermissionReport {
            path: path.to_path_buf(),
            restricted_to_current_user: false,
            issues: vec![format!(
                "{} already exists; AgentFence did not change its permissions. \
                 Verify that other accounts cannot read it.",
                path.display()
            )],
        });
    }

    std::fs::create_dir_all(path)?;
    match restrict_dir(path) {
        Ok(()) => Ok(PermissionReport::ok(path)),
        Err(e) => Ok(PermissionReport::failed(
            path,
            format!("could not restrict {}: {}", path.display(), e),
        )),
    }
}

/// Restrict an existing file to the current OS user.
pub fn secure_file(path: &Path) -> io::Result<PermissionReport> {
    if !path.exists() {
        return Ok(PermissionReport::ok(path));
    }
    match restrict_file(path) {
        Ok(()) => Ok(PermissionReport::ok(path)),
        Err(e) => Ok(PermissionReport::failed(
            path,
            format!("could not restrict {}: {}", path.display(), e),
        )),
    }
}

/// Prepare the directory holding a database and restrict any existing database
/// file plus its auxiliary files.
///
/// Returns a report describing the directory. Auxiliary files (`-wal`, `-shm`,
/// `-journal`) are protected by the directory's own ACL/permissions; they are
/// also restricted individually when present.
pub fn prepare_db_path(db_path: &Path) -> io::Result<PermissionReport> {
    let parent = match db_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    let dir_report = secure_dir(parent)?;

    let mut issues = dir_report.issues.clone();
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let candidate = PathBuf::from(format!("{}{}", db_path.display(), suffix));
        if candidate.exists() {
            if let Ok(r) = secure_file(&candidate) {
                issues.extend(r.issues);
            }
        }
    }

    Ok(PermissionReport {
        path: parent.to_path_buf(),
        restricted_to_current_user: dir_report.restricted_to_current_user,
        issues,
    })
}

// ─── Platform implementations ────────────────────────────────────────────────

#[cfg(unix)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(windows)]
fn current_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "CurrentUser".to_string())
}

/// Replace the directory ACL with a single full-control entry for the current
/// user. `/inheritance:r` drops inherited rights; `/grant:r` replaces (rather
/// than appends) the user's own entry.
#[cfg(windows)]
fn restrict_dir(path: &Path) -> io::Result<()> {
    run_icacls(path)
}

#[cfg(windows)]
fn restrict_file(path: &Path) -> io::Result<()> {
    run_icacls(path)
}

#[cfg(windows)]
fn run_icacls(path: &Path) -> io::Result<()> {
    // `icacls` writes localized output; only the exit code is meaningful.
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg(format!("{}:F", current_user()))
        .output()
        .map_err(|e| io::Error::other(format!("icacls failed to start: {e}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "icacls exited with {:?}",
            output.status.code()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "af-secure-{}-{}-{}",
            label,
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a_pre_existing_directory_is_reported_not_rewritten() {
        // SECURITY: rewriting a pre-existing directory's ACL with
        // `/inheritance:r` strips inherited ACEs from its children, leaving
        // them with an empty DACL. AgentFence must never do that.
        let dir = temp_dir("existing");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("operator-file.txt");
        std::fs::write(&file, b"operator data").unwrap();

        let report = secure_dir(&dir).expect("secure_dir");
        assert!(
            !report.is_secure(),
            "a pre-existing dir is reported, not silently trusted"
        );
        assert!(!report.issues.is_empty());

        // The operator's file is still readable and writable.
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "operator data");
        std::fs::write(&file, b"still mine").unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_new_directory_is_created_and_restricted() {
        let dir = temp_dir("new");
        let report = secure_dir(&dir).expect("secure_dir");
        assert!(report.is_secure(), "issues: {:?}", report.issues);
        assert!(dir.is_dir());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "directory mode must be 0700");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn database_and_auxiliary_files_are_restricted() {
        let dir = temp_dir("db");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("approvals.db");
        std::fs::write(&db, b"x").unwrap();
        std::fs::write(dir.join("approvals.db-wal"), b"y").unwrap();
        std::fs::write(dir.join("approvals.db-shm"), b"z").unwrap();

        // The directory pre-exists, so it is reported rather than rewritten; the
        // database files themselves are still restricted.
        let report = prepare_db_path(&db).expect("prepare_db_path");
        assert!(!report.is_secure(), "a pre-existing directory is reported");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["approvals.db", "approvals.db-wal", "approvals.db-shm"] {
                let mode = std::fs::metadata(dir.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777;
                assert_eq!(mode, 0o600, "{} must be 0600", name);
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_auxiliary_files_are_not_an_error() {
        let dir = temp_dir("db2");
        let report = prepare_db_path(&dir.join("approvals.db")).expect("prepare_db_path");
        assert!(report.is_secure(), "issues: {:?}", report.issues);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_where_the_directory_should_be_is_reported() {
        let path = temp_dir("blocker");
        std::fs::write(&path, b"not a directory").unwrap();
        // `path.exists()` is true, so the pre-existing branch reports it rather
        // than attempting a destructive rewrite; the report must not claim
        // success.
        let report = secure_dir(&path).expect("secure_dir must not panic");
        assert!(!report.is_secure());
        let _ = std::fs::remove_file(&path);
    }
}
