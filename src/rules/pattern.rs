//! The rule itself, and the wildcard language its program path speaks.

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::rules::Action;
use crate::rules::Direction;
use crate::rules::disk::RuleFile;
use crate::rules::fields::{Dests, Patterns, Ports, Remotes};
use crate::rules::protocol::Protocol;

/// A single user rule.
///
/// `pattern` names one application or a comma-separated list of them, and may contain the
/// wildcards `*` and `?` (plan section 4). Matching is our job,
/// not the kernel's, so the string is stored exactly as the user typed it.
///
/// `protocol`, `direction`, `port`, `remote` and `local` narrow the rule and are absent when it is
/// about all of them. They are skipped when written out, so a rule that does not use them is
/// stored exactly as
/// it was before they existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub pattern: Patterns,
    #[serde(default = "always_enabled")]
    pub enabled: bool,
    /// A rule meant for one run of one program: it leaves the firewall again as soon as no process
    /// of its program is running.
    ///
    /// It decides nothing about how a connection is judged, only how long the rule is worth
    /// keeping. Skipped when written out, so a rules file that never uses it is written exactly as
    /// it was before the field existed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub temporary: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Ports>,
    /// The remote address or addresses the rule is about, written `192.168.1.0/24`, `10.0.0.5` or
    /// `10.0.0.1-10.0.0.9`, and a comma-separated list of them for more than one destination.
    /// Absent means any address, which is also what narrows the rule to the application alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Remotes>,
    /// The remote names the rule is about, written `www.example.com` and a comma-separated
    /// list of them for more than one. Names are resolved to addresses when the filters are
    /// built, and a name nothing answered for matches nothing. `remote` and `dest` narrow the
    /// same condition and are used as a union: a connection matches when its remote address is
    /// in `remote` or among the addresses `dest` resolved to. Absent means no name narrows the
    /// rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<Dests>,
    /// The local address or addresses the rule is about, written `192.168.1.0/24`, `10.0.0.5` or
    /// `10.0.0.1-10.0.0.9`, and a comma-separated list of them for more than one source.
    /// Absent means any address, which is also what leaves the rule about the destination alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<Remotes>,
    /// Why the rule exists, in the words of the person who wrote it.
    ///
    /// It decides nothing: the field is for the reader of a list they did not write. It is skipped
    /// when absent, so a rules file that never uses it is written exactly as it was before the
    /// field existed. The reference has the same field on its rules (`ITEM_RULE`, `main.h`), and
    /// like there it is never sent to the store: a filter is what a rule became, and a wildcard rule
    /// that expands to a dozen filters would repeat the sentence a dozen times.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

const fn always_enabled() -> bool {
    true
}

/// Whether a bool field is the value that is never written out.
///
/// `temporary` is the only one, and the rule is the same as for the optional fields: a file that
/// does not use the feature holds exactly the text it held before it existed.
const fn is_false(value: &bool) -> bool {
    !*value
}

impl Rule {
    /// A rule that narrows nothing: an enabled rule about an application, with no protocol,
    /// direction, port, remote address or local address. This is what a detected application and an
    /// MCP agent turn into.
    pub fn plain(name: impl Into<String>, action: Action, pattern: impl Into<Patterns>) -> Self {
        Self {
            name: name.into(),
            action,
            pattern: pattern.into(),
            enabled: true,
            temporary: false,
            protocol: None,
            direction: None,
            port: None,
            remote: None,
            dest: None,
            local: None,
            comment: None,
        }
    }

    /// Whether the remote end of a connection is one this rule speaks about, given the
    /// addresses its names were answered with. `remote` and `dest` are a union; a rule that
    /// names neither speaks about every address.
    pub fn reaches(&self, addr: std::net::IpAddr, answers: &crate::dns::Answers) -> bool {
        match (self.remote.as_ref(), self.dest.as_ref()) {
            (None, None) => true,
            (Some(remote), None) => remote.contains(addr),
            (None, Some(dest)) => dest.contains(addr, answers),
            (Some(remote), Some(dest)) => remote.contains(addr) || dest.contains(addr, answers),
        }
    }
}

/// The characters that make a pattern a wildcard pattern.
const WILDCARD_STAR: char = '*';

pub(crate) const WILDCARD_ANY: char = '?';

/// Refuse a pattern that cannot name a path.
///
/// The reference checks a path the user typed against the shape of a drive path
/// (`_app_isappvalidpath`, `helper.c:574`) and refuses anything else. Doing without that check
/// means a typo is not an error but a rule that silently matches nothing, which is worse for a
/// firewall than for most programs: the connection it was supposed to decide goes the other way.
///
/// A rule may be rooted at a drive (`C:\...`) or at a single separator, because a device path the
/// drive map did not resolve arrives as `\Device\HarddiskVolume3\...`.
pub fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.trim().is_empty() {
        bail!("a rule needs a pattern");
    }

    if pattern.chars().any(char::is_control) {
        bail!("a pattern cannot contain a control character");
    }

    if pattern.contains(['"', '<', '>', '|']) {
        bail!("a pattern cannot contain the characters \" < > |");
    }

    let bytes = pattern.as_bytes();
    let drive_rooted =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';

    if !drive_rooted && bytes[0] != b'\\' {
        bail!("a pattern must be an absolute path such as C:\\Windows\\*.exe");
    }

    Ok(())
}

/// The longest comment a rule accepts.
///
/// The reference keeps its comments in a fixed buffer, so a longer one is simply cut off there.
/// Refusing is kinder than cutting: the person who typed it finds out at once, and the file never
/// holds a sentence that lost its ending.
pub const COMMENT_LIMIT: usize = 200;

/// Refuse a comment that would not read back the way it was meant.
///
/// A comment is the one field a person pastes rather than types, and pasted text brings control
/// characters with it. TOML would escape a newline and read it back happily, but a rule that spans
/// three lines in a file the user is expected to scan is not worth what it looks like in an editor.
pub fn validate_comment(comment: &str) -> Result<()> {
    if comment.chars().any(char::is_control) {
        bail!("a comment cannot contain a control character");
    }

    if comment.chars().count() > COMMENT_LIMIT {
        bail!("a comment cannot be longer than {COMMENT_LIMIT} characters");
    }

    Ok(())
}

/// Whether a pattern needs matching at all, rather than being an exact path.
pub fn is_wildcard(pattern: &str) -> bool {
    pattern.contains([WILDCARD_STAR, WILDCARD_ANY])
}

/// Match a pattern against text with `*` and `?` placeholders.
///
/// Comparison is case-insensitive, because Windows paths are. Unlike a shell glob, `*` is not
/// stopped by a path separator: a rule about `C:\Windows\*` is meant to cover everything below
/// that directory, separators included, which is the reading plan section 4 promises.
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
        .any(|rule| rule.pattern.matches(path))
}

/// Whether the destination of an application a rule covers is decided as well.
///
/// A rule that names no destination reaches every address, and a rule that names one has to
/// contain it. A destination no enabled rule of this application contains is new even when the
/// application itself is not, which is what learning mode asks next.
pub fn reaches(
    rules: &RuleFile,
    path: &str,
    addr: std::net::IpAddr,
    answers: &crate::dns::Answers,
) -> bool {
    rules
        .rule
        .iter()
        .filter(|rule| rule.enabled && rule.pattern.matches(path))
        .any(|rule| rule.reaches(addr, answers))
}

/// The temporary rules whose program is no longer running.
///
/// `running` holds the image paths of the processes that are running right now, in the drive form
/// a rule is typed in. A temporary rule is one the person meant for a single run of one program,
/// so it is worth exactly as long as a process of that program is there; a wildcard program is
/// still there when any running process matches it.
pub fn expired_temporary(rules: &RuleFile, running: &[String]) -> Vec<String> {
    rules
        .rule
        .iter()
        .filter(|rule| rule.temporary)
        .filter(|rule| !running.iter().any(|path| rule.pattern.matches(path)))
        .map(|rule| rule.name.clone())
        .collect()
}

/// Take the temporary rules whose program is no longer running out of the list, and name them.
///
/// A permanent rule that happens to share a name with an expired one is kept: only rules marked
/// temporary are ever retired this way.
pub fn prune_temporary(rules: &mut RuleFile, running: &[String]) -> Vec<String> {
    let expired = expired_temporary(rules, running);

    if !expired.is_empty() {
        rules
            .rule
            .retain(|rule| !rule.temporary || !expired.contains(&rule.name));
    }

    expired
}
