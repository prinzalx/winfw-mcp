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

/// The transport a rule is about.
///
/// Absent on a rule means both, which is what a rule was before this dimension existed. A bare
/// protocol number is not offered yet; TCP and UDP are what the reference offers too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// The IP protocol number WFP wants in a `FWPM_CONDITION_IP_PROTOCOL` condition.
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

/// Which way the connection goes for a rule to apply.
///
/// This decides the layers a rule is installed on: outbound is the ALE connect layer, inbound the
/// ALE recv-accept layer. Absent means both, as it did before the dimension existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// A port, or an inclusive range of them, written `443` or `1024-2048`.
///
/// It is a string in the file and in JSON rather than a number, because a range has no number form
/// and because a port is read as text far more often than it is computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    /// Whether the range names one port, which is how WFP is told about it.
    pub const fn is_single(&self) -> bool {
        self.lo == self.hi
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// The error text a bad port answers with, which becomes a serde message and a web error.
type ParseError = String;

impl std::str::FromStr for PortRange {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let parse = |part: &str| {
            part.trim()
                .parse::<u16>()
                .map_err(|_| format!("'{part}' is not a port"))
        };

        let (lo, hi) = match text.split_once('-') {
            Some((lo, hi)) => (parse(lo)?, parse(hi)?),
            None => (parse(text)?, parse(text)?),
        };

        if lo > hi {
            return Err(format!("port range '{text}' runs backwards"));
        }

        Ok(Self { lo, hi })
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A single user rule.
///
/// `pattern` may contain the wildcards `*` and `?` (PLAN.md section 4). Matching is our job,
/// not the kernel's, so the string is stored exactly as the user typed it.
///
/// `protocol`, `direction` and `port` narrow the rule and are absent when it is about all of
/// them. They are skipped when written out, so a rule that does not use them is stored exactly as
/// it was before they existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub pattern: String,
    #[serde(default = "always_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<PortRange>,
}

const fn always_enabled() -> bool {
    true
}

impl Rule {
    /// A rule that narrows nothing: an enabled rule about an application, with no protocol,
    /// direction or port. This is what a detected application and an MCP agent turn into.
    pub fn plain(name: impl Into<String>, action: Action, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action,
            pattern: pattern.into(),
            enabled: true,
            protocol: None,
            direction: None,
            port: None,
        }
    }
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

/// A profile name is the stem of one file in `profiles\`: a single component, no separators.
///
/// The empty name is not a profile at all — it means `rules.toml` itself — so it is rejected here;
/// the caller decides what empty means before asking.
pub fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':'])
}

/// The names of the profiles stored in `dir`, sorted, without the `.toml` suffix.
///
/// A directory that does not exist or cannot be read simply has no profiles, which is what a
/// fresh install looks like.
pub fn list_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            {
                return None;
            }

            Some(path.file_stem()?.to_str()?.to_owned())
        })
        .collect();

    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuleFile {
        RuleFile {
            rule: vec![
                Rule::plain(
                    "browser",
                    Action::Allow,
                    "C:\\Program Files\\*\\browser.exe",
                ),
                Rule {
                    enabled: false,
                    ..Rule::plain("telemetry", Action::Deny, "C:\\Tools\\agent?.exe")
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
                enabled: false,
                ..Rule::plain("windows", Action::Deny, "C:\\Windows\\*")
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
    fn a_profile_name_is_a_single_component() {
        assert!(is_valid_profile_name("work"));
        assert!(is_valid_profile_name("home.v2"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name(".."));
        assert!(!is_valid_profile_name("a\\b"));
        assert!(!is_valid_profile_name("a/b"));
        assert!(!is_valid_profile_name("c:d"));
    }

    #[test]
    fn profile_names_are_listed_without_their_suffix() {
        let dir = crate::testutil::scratch_dir("profile-names");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("work.toml"), "").expect("write work");
        std::fs::write(dir.join("home.toml"), "").expect("write home");
        std::fs::write(dir.join("notes.txt"), "").expect("write notes");

        assert_eq!(list_names(&dir), vec!["home".to_owned(), "work".to_owned()]);
    }

    #[test]
    fn actions_are_written_lowercase() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        assert!(text.contains("action = \"allow\""), "{text}");
        assert!(text.contains("action = \"deny\""), "{text}");
    }

    #[test]
    fn a_port_range_reads_both_of_its_forms() {
        let single: PortRange = "443".parse().expect("parse a single port");

        assert_eq!((single.lo, single.hi, single.is_single()), (443, 443, true));

        let range: PortRange = "1024-2048".parse().expect("parse a range");

        assert_eq!((range.lo, range.hi, range.is_single()), (1024, 2048, false));
    }

    #[test]
    fn a_port_range_refuses_what_is_not_one() {
        assert!("".parse::<PortRange>().is_err());
        assert!("http".parse::<PortRange>().is_err());
        assert!(
            "2048-1024".parse::<PortRange>().is_err(),
            "it runs backwards"
        );
        assert!("70000".parse::<PortRange>().is_err(), "past a u16");
        assert!("1024-".parse::<PortRange>().is_err(), "no upper end");
    }

    #[test]
    fn a_port_range_is_written_as_it_is_read() {
        assert_eq!(
            "443".parse::<PortRange>().expect("parse").to_string(),
            "443"
        );
        assert_eq!(
            "1024-2048".parse::<PortRange>().expect("parse").to_string(),
            "1024-2048",
        );
    }

    #[test]
    fn a_rule_without_narrowing_is_written_as_it_used_to_be() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        for key in ["protocol", "direction", "port"] {
            assert!(
                !text.contains(key),
                "{key} appeared for a rule that has none: {text}"
            );
        }
    }

    #[test]
    fn the_narrowing_of_a_rule_survives_a_round_trip() {
        let path = crate::testutil::scratch_dir("rules-narrowing").join("rules.toml");
        let rules = RuleFile {
            rule: vec![Rule {
                protocol: Some(Protocol::Tcp),
                direction: Some(Direction::Out),
                port: Some("1024-2048".parse().expect("parse a port")),
                ..Rule::plain("ssh", Action::Allow, "C:\\Tools\\ssh.exe")
            }],
        };

        rules.save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("protocol = \"tcp\""), "{text}");
        assert!(text.contains("direction = \"out\""), "{text}");
        assert!(text.contains("port = \"1024-2048\""), "{text}");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn a_rule_file_refuses_a_port_it_cannot_read() {
        let parsed: Result<RuleFile, toml::de::Error> = toml::from_str(
            "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"a\"\nport = \"http\"\n",
        );

        assert!(parsed.is_err(), "a port must be a port");
    }

    #[test]
    fn a_rule_file_refuses_a_protocol_it_does_not_know() {
        let parsed: Result<RuleFile, toml::de::Error> = toml::from_str(
            "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"a\"\nprotocol = \"sctp\"\n",
        );

        assert!(parsed.is_err(), "only tcp and udp are protocols");
    }
}
