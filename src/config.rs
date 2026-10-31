use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::store;

/// Everything the user can configure that is not a rule.
///
/// Unknown keys are rejected rather than ignored, so a typo in the file surfaces instead of
/// silently keeping the default forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Loopback port for the web UI and, later, the MCP endpoint.
    pub port: u16,
    /// `tracing` filter. `RUST_LOG` still wins so a support case needs no file edit.
    pub log_level: String,
    /// Collect connections that match no rule into the Detected list (PLAN.md section 3).
    pub learn_mode: bool,
    /// Presentation only, but stored so the browser and the file agree.
    pub theme: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 8788,
            log_level: "info".to_owned(),
            learn_mode: true,
            theme: "dark".to_owned(),
        }
    }
}

impl Settings {
    /// Load the settings, writing the defaults first when the file does not exist yet, so
    /// the user has something to edit after the very first run.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match store::read_if_exists(path)? {
            Some(bytes) => {
                toml::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
            }
            None => {
                let settings = Self::default();
                settings.save(path)?;
                Ok(settings)
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("serialize settings")?;
        store::write_atomic(path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_survive_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("config").join("config.toml");
        let settings = Settings {
            port: 9001,
            log_level: "debug".to_owned(),
            learn_mode: false,
            theme: "light".to_owned(),
        };

        settings.save(&path).expect("save");

        assert_eq!(Settings::load_or_create(&path).expect("load"), settings);
    }

    #[test]
    fn a_missing_file_is_created_with_the_defaults() {
        let path = crate::testutil::scratch_dir("config-create").join("config.toml");

        let settings = Settings::load_or_create(&path).expect("load");

        assert!(path.is_file(), "the file should exist after the first run");
        assert_eq!(settings, Settings::default());
    }

    #[test]
    fn an_unknown_key_is_rejected_not_ignored() {
        let path = crate::testutil::scratch_dir("config-typo").join("config.toml");
        std::fs::write(&path, "port = 8788\nlog_levell = \"debug\"\n").expect("write");

        let error = Settings::load_or_create(&path).expect_err("should fail");

        // `{error:#}` prints the whole chain; the plain Display would only show our own
        // "parse <path>" context and hide the reason.
        assert!(format!("{error:#}").contains("unknown field"), "{error:#}");
    }
}
