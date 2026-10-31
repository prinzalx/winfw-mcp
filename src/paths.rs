use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// The directory this tool owns, plus the files inside it.
///
/// Resolved once at startup and never re-derived from a relative path afterwards, so the
/// process cannot be confused by a later change of the working directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPaths {
    pub root: PathBuf,
    pub config: PathBuf,
    pub rules: PathBuf,
    pub profiles: PathBuf,
    pub logs: PathBuf,
    pub export: PathBuf,
}

impl DataPaths {
    /// Build the layout under a root we were handed. Separate from [`DataPaths::resolve`] so
    /// tests do not have to touch the process environment.
    pub fn under(root: PathBuf) -> Self {
        Self {
            config: root.join("config.toml"),
            rules: root.join("rules.toml"),
            profiles: root.join("profiles"),
            logs: root.join("logs"),
            export: root.join("export"),
            root,
        }
    }

    /// `%APPDATA%\winfw-mcp`.
    ///
    /// Portable here does not mean "next to the executable": always using AppData keeps the
    /// behaviour identical wherever the exe is copied to (PLAN.md section 2).
    pub fn resolve() -> Result<Self> {
        let Some(appdata) = std::env::var_os("APPDATA") else {
            bail!("APPDATA is not set, cannot locate %APPDATA%\\winfw-mcp");
        };
        if appdata.is_empty() {
            bail!("APPDATA is empty, cannot locate %APPDATA%\\winfw-mcp");
        }
        Ok(Self::under(
            PathBuf::from(appdata).join(env!("CARGO_PKG_NAME")),
        ))
    }

    /// Create the directories that may hold files we do not write at startup.
    pub fn ensure(&self) -> Result<()> {
        for dir in [&self.root, &self.profiles, &self.logs, &self.export] {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("create directory {}", dir.display()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_stable_for_a_given_root() {
        let paths = DataPaths::under(PathBuf::from("root"));

        assert_eq!(paths.config, PathBuf::from("root/config.toml"));
        assert_eq!(paths.rules, PathBuf::from("root/rules.toml"));
        assert_eq!(paths.profiles, PathBuf::from("root/profiles"));
        assert_eq!(paths.export, PathBuf::from("root/export"));
    }

    #[test]
    fn ensure_creates_every_directory_it_promises() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("paths"));
        paths.ensure().expect("ensure");

        for dir in [&paths.root, &paths.profiles, &paths.logs, &paths.export] {
            assert!(dir.is_dir(), "{} should exist", dir.display());
        }
    }
}
