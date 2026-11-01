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
    ///
    /// The page follows this rather than the operating system unless it says `auto`, because a
    /// setting that names one theme while the page shows another is the confusion this field exists
    /// to avoid.
    pub theme: Theme,
    /// How much the MCP endpoint may change (PLAN.md section 10).
    ///
    /// `none` is the default on purpose: an agent talking to a firewall it did not configure should
    /// be able to ask questions before it is allowed to answer them.
    pub mcp_writes: Writes,
    /// The named profile whose rules are live, or empty for `rules.toml` itself.
    ///
    /// A profile is a rule file under `profiles\<name>.toml`; naming it here is what makes the
    /// choice survive a restart (PLAN.md section 10).
    pub active_profile: String,
    /// Install the filters so they go out with the process instead of surviving it.
    ///
    /// Persistent filters (the default) are what makes a quit keep the rules; a volatile install
    /// has the BFE take the filters out again when the last engine handle closes, which is what a
    /// user who wants the tool to be the firewall only while it runs asks for.
    pub volatile_filters: bool,
    /// What an application that no rule mentions should get: the Windows default (`allow`) or a
    /// firewall (`deny`).
    ///
    /// `deny` is the simplewall reading: every connection is blocked at the lowest weight and the
    /// rules, the loopback permits and the IPv6 plumbing permits are what lets traffic through
    /// again (BACKLOG section 4.1). `allow` keeps the machine exactly as it was, which is the
    /// safe default for a tool that has just been installed next to a running Windows Firewall.
    pub default_policy: Policy,
}

/// What the store should do with traffic no rule of this tool mentions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    /// Install no base filter; whatever the rest of the machine decides, decides.
    #[default]
    Allow,
    /// Block everything at the lowest weight, so only rules and permits let traffic through.
    Deny,
}

impl Policy {
    /// The name as `config.toml` spells it and as the page shows it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Read a name back. A client that sends anything else gets an error rather than a policy it
    /// did not ask for, which is what the settings route reports to the browser.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Which of the page's two colour schemes to show.
///
/// The page carries both schemes as CSS custom properties, so this is a switch rather than a
/// palette: nothing about the layout depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the operating system, which is what the page does when it is told nothing.
    Auto,
    /// Always light.
    Light,
    /// Always dark. The default, and the value a config file written before this field meant
    /// anything carries.
    #[default]
    Dark,
}

impl Theme {
    /// The name as `config.toml` spells it and as the page shows it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    /// Read a name back, the way [`Policy::parse`] does it. A page or an agent that sends anything
    /// else hears what the values are rather than watching nothing change.
    pub fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }

    /// The stable number an `AtomicU8` holds. Adding a variant means adding a number here, and
    /// `from_index` clamps a value it does not know to the default.
    pub(crate) fn index(&self) -> u8 {
        match self {
            Self::Auto => 0,
            Self::Light => 1,
            Self::Dark => 2,
        }
    }

    /// Read back an [`index`](Self::index). A number from a future version falls back to the
    /// default rather than panicking on a value the process cannot name.
    pub(crate) fn from_index(index: u8) -> Self {
        match index {
            0 => Self::Auto,
            1 => Self::Light,
            2 => Self::Dark,
            _ => Self::default(),
        }
    }
}

/// What the MCP endpoint is allowed to modify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Writes {
    /// Read-only. Every write answers "refused" rather than touching the store.
    #[default]
    None,
    /// The rules may change; the profile and the settings may not.
    Rules,
    /// Everything an MCP client can see, it can change.
    All,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 8788,
            log_level: "info".to_owned(),
            learn_mode: true,
            theme: Theme::Dark,
            mcp_writes: Writes::None,
            active_profile: String::new(),
            volatile_filters: false,
            default_policy: Policy::default(),
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

    /// The live setting holds a theme as a number, and the fallback for a number it does not know
    /// is the default rather than the first variant. Those two facts overlap at `0`, so a value
    /// read back has to be tested for every variant rather than trusted to the order they are
    /// declared in.
    #[test]
    fn every_theme_survives_the_number_the_live_setting_holds() {
        for theme in [Theme::Auto, Theme::Light, Theme::Dark] {
            assert_eq!(
                Theme::from_index(theme.index()),
                theme,
                "{} does not survive its own number",
                theme.name(),
            );
        }

        assert_eq!(
            Theme::from_index(9),
            Theme::default(),
            "a number from a future version falls back to the default",
        );
    }

    #[test]
    fn settings_survive_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("config").join("config.toml");
        let settings = Settings {
            port: 9001,
            log_level: "debug".to_owned(),
            learn_mode: false,
            theme: Theme::Light,
            mcp_writes: Writes::Rules,
            active_profile: "work".to_owned(),
            volatile_filters: true,
            default_policy: Policy::Deny,
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

    /// A `config.toml` written by an earlier version has no `mcp_writes`. Upgrading must not fail
    /// the whole start over one missing key, so the field falls back to the read-only default.
    #[test]
    fn a_config_from_an_older_version_still_loads() {
        let path = crate::testutil::scratch_dir("config-upgrade").join("config.toml");
        std::fs::write(
            &path,
            "port = 9999\nlog_level = \"warn\"\nlearn_mode = false\ntheme = \"light\"\n",
        )
        .expect("write");

        let settings = Settings::load_or_create(&path).expect("load");

        assert_eq!(settings.port, 9999);
        assert_eq!(
            settings.mcp_writes,
            Writes::None,
            "a missing key must not silently enable writes"
        );
        assert_eq!(
            settings.active_profile, "",
            "a missing profile must mean the default rules.toml"
        );
    }
}
