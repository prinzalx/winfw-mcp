use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::store;

/// What WFP eventually does with a matching connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// A single user rule.
///
/// `pattern` may contain the wildcards `*` and `?` (PLAN.md section 4). Matching is our job,
/// not the kernel's, so the string is stored exactly as the user typed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub pattern: String,
    #[serde(default = "always_enabled")]
    pub enabled: bool,
}

const fn always_enabled() -> bool {
    true
}

/// The contents of `rules.toml`. Order is significant: the first matching rule wins, which is
/// why an import has to preserve it (PLAN.md section 2).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl RuleFile {
    /// Load the rules, creating an empty file when there is none yet.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        match store::read_if_exists(path)? {
            Some(bytes) => {
                toml::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
            }
            None => {
                let rules = Self::default();
                rules.save(path)?;
                Ok(rules)
            }
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("serialize rules")?;
        store::write_atomic(path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuleFile {
        RuleFile {
            rule: vec![
                Rule {
                    name: "browser".to_owned(),
                    action: Action::Allow,
                    pattern: "C:\\Program Files\\*\\browser.exe".to_owned(),
                    enabled: true,
                },
                Rule {
                    name: "telemetry".to_owned(),
                    action: Action::Deny,
                    pattern: "C:\\Tools\\agent?.exe".to_owned(),
                    enabled: false,
                },
            ],
        }
    }

    #[test]
    fn rules_survive_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("rules").join("rules.toml");
        let rules = sample();

        rules.save(&path).expect("save");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn an_empty_rule_file_round_trips() {
        let path = crate::testutil::scratch_dir("rules-empty").join("rules.toml");

        RuleFile::default().save(&path).expect("save");

        assert_eq!(RuleFile::load_or_create(&path).expect("load").rule.len(), 0);
    }

    #[test]
    fn actions_are_written_lowercase() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        assert!(text.contains("action = \"allow\""), "{text}");
        assert!(text.contains("action = \"deny\""), "{text}");
    }
}
