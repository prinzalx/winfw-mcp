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
}
