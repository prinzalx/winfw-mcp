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

/// The address family an address belongs to.
///
/// WFP keeps the two families in separate layers, so this decides which of them a rule with a
/// remote address is installed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The width of an address of this family, which is the longest prefix it accepts.
    pub const fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

/// A remote address, written `192.168.1.0/24`, `10.0.0.5` or `fe80::/10`.
///
/// A bare address is a prefix as wide as its family, so `10.0.0.5` means `10.0.0.5/32` and
/// `fe80::1` means `fe80::1/128`. Host bits are masked away while the text is read, so what ends
/// up in the file is exactly the network WFP will match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The network address: four significant bytes for v4, sixteen for v6.
    pub addr: [u8; 16],
    /// How many leading bits of `addr` have to match.
    pub prefix: u8,
    /// Which family the address is in.
    pub family: Family,
}

impl Cidr {
    /// The four bytes of a v4 address, which is how WFP wants them in a v4 condition.
    pub fn v4_bytes(&self) -> [u8; 4] {
        [self.addr[0], self.addr[1], self.addr[2], self.addr[3]]
    }

    /// The v4 mask WFP wants beside the address: the prefix widened to 32 bits, read big-endian
    /// like the address itself. `/0` masks everything away, which matches any address.
    pub fn v4_mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (Family::V4.bits() - self.prefix)
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (host, given) = match text.split_once('/') {
            Some((host, prefix)) => (
                host,
                Some(
                    prefix
                        .parse::<u8>()
                        .map_err(|_| format!("'{prefix}' is not a prefix length"))?,
                ),
            ),
            None => (text, None),
        };

        // IPv4 is tried first, because Rust reads a dotted quad as an IPv4-mapped IPv6 address
        // too, and `10.0.0.5` should stay the four byte address the user typed.
        let (addr, family) = if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            let mut addr = [0u8; 16];
            addr[..4].copy_from_slice(&v4.octets());
            (addr, Family::V4)
        } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            (v6.octets(), Family::V6)
        } else {
            return Err(format!("'{host}' is not an IP address"));
        };

        let prefix = given.unwrap_or_else(|| family.bits());

        if prefix > family.bits() {
            return Err(format!(
                "'{text}' has a prefix longer than {}",
                family.bits()
            ));
        }

        // Keep only the network part, so `10.0.0.5/24` is stored and shown as `10.0.0.0/24`.
        let mut addr = addr;
        for (index, byte) in addr.iter_mut().enumerate() {
            let keep = prefix.saturating_sub(8 * index as u8);

            *byte &= if keep >= 8 {
                0xff
            } else if keep == 0 {
                0
            } else {
                0xffu8 << (8 - keep)
            };
        }

        Ok(Self {
            addr,
            prefix,
            family,
        })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.family {
            Family::V4 => write!(f, "{}", std::net::Ipv4Addr::from(self.v4_bytes()))?,
            Family::V6 => write!(f, "{}", std::net::Ipv6Addr::from(self.addr))?,
        }

        if self.prefix == self.family.bits() {
            Ok(())
        } else {
            write!(f, "/{}", self.prefix)
        }
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
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
/// `protocol`, `direction`, `port` and `remote` narrow the rule and are absent when it is about
/// all of them. They are skipped when written out, so a rule that does not use them is stored
/// exactly as
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
    /// The remote address the rule is about, written `192.168.1.0/24`. Absent means any address,
    /// which is also what narrows the rule to the application alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Cidr>,
}

const fn always_enabled() -> bool {
    true
}

impl Rule {
    /// A rule that narrows nothing: an enabled rule about an application, with no protocol,
    /// direction, port or remote address. This is what a detected application and an MCP agent
    /// turn into.
    pub fn plain(name: impl Into<String>, action: Action, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action,
            pattern: pattern.into(),
            enabled: true,
            protocol: None,
            direction: None,
            port: None,
            remote: None,
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

    /// A prefix is read in both families, a bare address is one host, and the host bits of a
    /// network do not survive the read.
    #[test]
    fn a_cidr_reads_its_written_forms() {
        let network: Cidr = "192.168.1.0/24".parse().expect("parse a network");
        assert_eq!(network.family, Family::V4);
        assert_eq!(network.prefix, 24);
        assert_eq!(network.v4_bytes(), [192, 168, 1, 0]);
        assert_eq!(network.v4_mask(), 0xffff_ff00);

        let host: Cidr = "10.0.0.5".parse().expect("parse a host");
        assert_eq!(host.prefix, 32);
        assert_eq!(host.to_string(), "10.0.0.5");

        let scoped: Cidr = "fe80::1/64".parse().expect("parse a scoped network");
        assert_eq!(scoped.family, Family::V6);
        assert_eq!(scoped.prefix, 64);
        assert_eq!(scoped.to_string(), "fe80::/64");

        // A whole family is a prefix as wide as the family, and is written without one.
        let any: Cidr = "::/0".parse().expect("parse the whole family");
        assert_eq!(any.prefix, 0);
        assert_eq!(any.to_string(), "::/0");
    }

    /// Reading a prefix keeps the network and drops the host bits, so what is stored is what WFP
    /// matches.
    #[test]
    fn a_cidr_keeps_only_its_network_part() {
        for (text, expected) in [
            ("10.0.0.5/24", "10.0.0.0/24"),
            ("10.0.0.5/32", "10.0.0.5"),
            ("10.0.0.5/0", "0.0.0.0/0"),
            ("2001:db8::5/48", "2001:db8::/48"),
        ] {
            let parsed: Cidr = text
                .parse()
                .unwrap_or_else(|error| panic!("parse {text}: {error}"));

            assert_eq!(parsed.to_string(), expected, "keep the network of {text}");
        }
    }

    /// What is refused: text that is not an address, a prefix that is not a number, and a prefix
    /// wider than the family.
    #[test]
    fn a_cidr_refuses_what_is_not_one() {
        for text in [
            "example.com",
            "10.0.0.5/abc",
            "10.0.0.5/33",
            "10.0.0.5/",
            "::/129",
            "",
        ] {
            assert!(text.parse::<Cidr>().is_err(), "'{text}' is not a prefix");
        }
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
