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

/// The characters that make a pattern a wildcard pattern.
const WILDCARD_STAR: char = '*';
const WILDCARD_ANY: char = '?';

/// Whether a pattern needs matching at all, rather than being an exact path.
pub fn is_wildcard(pattern: &str) -> bool {
    pattern.contains([WILDCARD_STAR, WILDCARD_ANY])
}

/// Match a pattern against text with `*` and `?` placeholders.
///
/// Comparison is case-insensitive, because Windows paths are. Unlike a shell glob, `*` is not
/// stopped by a path separator: a rule about `C:\Windows\*` is meant to cover everything below
/// that directory, separators included, which is the reading PLAN.md section 4 promises.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();

    // The usual two-pointer match with a single remembered star: `star` is the index of the last
    // star in the pattern, and `given` how much of the text that star has swallowed so far.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut given) = (None, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == WILDCARD_ANY || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == WILDCARD_STAR {
            star = Some(p);
            p += 1;
            given = t;
        } else if let Some(at) = star {
            // The star has to swallow one more character; whatever follows it starts over.
            given += 1;
            t = given;
            p = at + 1;
        } else {
            return false;
        }
    }

    // Whatever is left of the pattern has to be stars matching nothing.
    pattern[p..].iter().all(|&c| c == WILDCARD_STAR)
}

/// Whether any enabled rule covers this path.
///
/// This is the question learning mode asks before showing an application as detected: a
/// connection a rule already speaks about is not new, whatever the store decided to do with it.
pub fn covered_by(rules: &RuleFile, path: &str) -> bool {
    rules
        .rule
        .iter()
        .filter(|rule| rule.enabled)
        .any(|rule| wildcard_match(&rule.pattern, path))
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
    fn a_star_matches_across_separators() {
        assert!(wildcard_match(
            "C:\\Windows\\*",
            "C:\\Windows\\System32\\a.exe"
        ));
    }

    #[test]
    fn a_question_mark_matches_exactly_one_character() {
        assert!(wildcard_match("C:\\a?.exe", "C:\\ab.exe"));
        assert!(!wildcard_match("C:\\a?.exe", "C:\\abc.exe"));
    }

    #[test]
    fn matching_ignores_case_because_windows_paths_do() {
        assert!(wildcard_match(
            "c:\\WINDows\\SUB\\*.EXE",
            "C:\\windows\\sub\\x\\a.exe"
        ));
    }

    #[test]
    fn a_pattern_must_cover_the_whole_text() {
        assert!(!wildcard_match("C:\\Windows\\*", "C:\\Windows"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("*x", "anything"));
    }

    #[test]
    fn only_enabled_rules_can_cover_a_path() {
        let rules = RuleFile {
            rule: vec![Rule {
                name: "windows".to_owned(),
                action: Action::Deny,
                pattern: "C:\\Windows\\*".to_owned(),
                enabled: false,
            }],
        };

        assert!(!covered_by(&rules, "C:\\Windows\\a.exe"));
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
