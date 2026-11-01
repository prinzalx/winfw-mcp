use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Read a file, or `None` when it does not exist. Any other error is real and reported.
pub fn read_if_exists(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Write `bytes` to `path` through a temporary sibling file, then rename.
///
/// A crash or a power loss therefore never leaves a half-written `config.toml` behind, which
/// matters because the WFP filters we generate are persistent (PLAN.md section 5).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .with_context(|| format!("{} has no file name", path.display()))?;
    let tmp = path.with_file_name(format!("{}.tmp", file_name.to_string_lossy()));

    {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("flush {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// The path of the previous generation of `path`, which is its name plus a `.bak` suffix.
///
/// The suffix is added to the whole file name rather than replacing the extension, so
/// `rules.toml` keeps a readable name next to its backup.
pub fn backup_path(path: &Path) -> std::path::PathBuf {
    let file_name = path
        .file_name()
        .map(|name| format!("{}.bak", name.to_string_lossy()))
        .unwrap_or_else(|| "backup.bak".to_owned());

    path.with_file_name(file_name)
}

/// [`write_atomic`] with the file that was there kept as [`backup_path`] first.
///
/// The copy happens before the rename, so a write that fails halfway leaves the previous
/// generation on disk under both names, which is the better of the two accidents. A file that does
/// not exist yet has nothing to keep, and a backup that cannot be copied is reported rather than
/// ignored: the point of the backup is that the user can trust it.
pub fn write_backup(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        let backup = backup_path(path);

        std::fs::copy(path, &backup)
            .with_context(|| format!("back up {} to {}", path.display(), backup.display()))?;
    }

    write_atomic(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_if_exists_reports_a_missing_file_as_none() {
        let missing = crate::testutil::scratch_dir("read").join("nope.toml");

        assert_eq!(read_if_exists(&missing).expect("no error"), None);
    }

    #[test]
    fn write_atomic_replaces_an_existing_file() {
        let path = crate::testutil::scratch_dir("write").join("values.toml");
        write_atomic(&path, b"first").expect("first write");
        write_atomic(&path, b"second").expect("second write");

        assert_eq!(std::fs::read(&path).expect("read"), b"second");
    }

    #[test]
    fn write_atomic_leaves_no_temporary_file_behind() {
        let path = crate::testutil::scratch_dir("tmp").join("values.toml");
        write_atomic(&path, b"data").expect("write");

        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[test]
    fn write_backup_keeps_the_previous_generation() {
        let path = crate::testutil::scratch_dir("backup").join("values.toml");
        write_backup(&path, b"first").expect("first write");
        write_backup(&path, b"second").expect("second write");

        let backup = backup_path(&path);

        assert_eq!(std::fs::read(&path).expect("read"), b"second");
        assert_eq!(
            std::fs::read(&backup).expect("read backup"),
            b"first",
            "the file that was there has to be kept",
        );
    }

    /// A file written for the first time has nothing to keep, and that is not an error.
    #[test]
    fn a_first_write_has_no_backup_to_make() {
        let path = crate::testutil::scratch_dir("backup-first").join("values.toml");
        write_backup(&path, b"only").expect("write");

        assert!(!backup_path(&path).exists());
    }
}
