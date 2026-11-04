//! Reading and writing a rule file.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::rules::Action;
use crate::rules::pattern::Rule;
use crate::rules::stamp::Fingerprint;
use crate::store;

/// The contents of `rules.toml`. Order is significant: the first matching rule wins, which is
/// why an import has to preserve it (plan section 2).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl RuleFile {
    /// The two rules a first run writes into `rules.toml`.
    ///
    /// An empty file is a correct default and a poor first screen: nothing on it shows what a rule
    /// is supposed to look like. These two are the shape of the common case - one application
    /// allowed to one network, one denied - and they are deliberately the same pair the manual
    /// talks about. The paths name `C:\test\`, which a normal machine does not have, so a rule
    /// teaches without blocking anything a real program does, and the prefixes are the
    /// documentation ranges of RFC 5737, which no host of this network is ever in.
    pub fn examples() -> Self {
        let mut allow = Rule::plain("example allow", Action::Allow, "C:\\test\\tool1.exe");
        allow.remote = Some(
            "192.0.2.0/24"
                .parse()
                .expect("the example prefix is a literal"),
        );
        allow.comment = Some("the allow shape: this app may reach this network".to_owned());

        let mut deny = Rule::plain("example deny", Action::Deny, "C:\\test\\tool2.exe");
        deny.remote = Some(
            "198.51.100.0/24"
                .parse()
                .expect("the example prefix is a literal"),
        );
        deny.comment = Some("the deny shape: this app may not".to_owned());

        Self {
            rule: vec![allow, deny],
        }
    }
}

/// The version written to a rule file.
///
/// The reference keeps a schema version in its profile files and migrates when it reads an older
/// one. We only ever need to notice the opposite case, because a file with a field we do not know
/// is refused outright: the version turns that refusal into a message that names the versions.
pub const RULE_FILE_VERSION: u32 = 1;

/// What `rules.toml` holds: the version, the checksum of the body, and the rules.
///
/// The version and the checksum are deliberately not fields of [`RuleFile`], which is built by hand
/// in a dozen places and would have to carry two things none of them cares about.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFileDisk {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    rule: Vec<Rule>,
}

/// The checksum a rule file carries over its own body.
///
/// The reference ends its files with a hash of the body, which catches a file that still parses but
/// lost content on the way to disk. This is the same idea with the FNV-1a hash [`Fingerprint`]
/// already uses, because the goal is to notice an accident rather than to withstand an attacker,
/// and the security chapter says that out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// What the file named, or `None` when it named nothing.
    pub(crate) stated: Option<String>,
    /// What the rules the file holds hash to.
    actual: String,
}

impl Checksum {
    /// Whether the file and its contents disagree.
    ///
    /// A file that names no checksum disagrees as well, which is the honest answer: an older build
    /// wrote no such line, and a person who deletes it has the same effect.
    pub(crate) fn mismatched(&self) -> bool {
        self.stated.as_deref() != Some(self.actual.as_str())
    }
}

/// The body of a rule file: the rules alone, without the version and without the checksum.
///
/// Serialising the rules rather than cutting the text at the first table keeps the bytes that go
/// into the hash the same on both sides of a round trip, which is the whole point of the field.
fn body_text(rule: &[Rule]) -> Result<String> {
    toml::to_string_pretty(&RuleFile {
        rule: rule.to_vec(),
    })
    .context("serialize the rule body")
}

/// The text a rule file is written as.
///
/// The two scalars come first because TOML would otherwise read them as keys of the last `[[rule]]`
/// table, and `Rule` refuses a field it does not know.
fn file_text(rule: &[Rule]) -> Result<String> {
    let body = body_text(rule)?;
    let sum = Fingerprint::of(body.as_bytes()).hash;

    Ok(format!(
        "version = {RULE_FILE_VERSION}\nchecksum = \"{sum:016x}\"\n{body}"
    ))
}

/// Read one file's bytes, refusing a version this build cannot know.
///
/// A checksum that does not match is not refused here. A hand edit changes it, and a rules file a
/// person edited is an ordinary thing, so the caller is handed both values and decides how loudly to
/// say so.
pub(crate) fn parse_rule_file(
    bytes: &[u8],
) -> std::result::Result<(RuleFile, Checksum), toml::de::Error> {
    use serde::de::Error as _;

    let disk = toml::from_slice::<RuleFileDisk>(bytes)?;

    if disk.version > RULE_FILE_VERSION {
        return Err(toml::de::Error::custom(format!(
            "rule file version {} is newer than {}",
            disk.version, RULE_FILE_VERSION
        )));
    }

    let body = body_text(&disk.rule)
        .map_err(|error| toml::de::Error::custom(format!("checksum of the rule body: {error}")))?;

    Ok((
        RuleFile { rule: disk.rule },
        Checksum {
            stated: disk.checksum,
            actual: format!("{:016x}", Fingerprint::of(body.as_bytes()).hash),
        },
    ))
}

impl RuleFile {
    /// Load the rules, creating an empty file when there is none yet.
    ///
    /// A file that cannot be read is not the end of it: the previous generation written by
    /// [`RuleFile::save`] is tried before the error is reported, which is what makes a torn or
    /// mistyped write survivable. Falling back is logged rather than silent, because the file on
    /// disk still holds what could not be read.
    ///
    /// A file that reads but whose checksum disagrees with its contents is read anyway and warned
    /// about, because the disagreement has the same cause as a hand edit and the same cure.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let Some(bytes) = store::read_if_exists(path)? else {
            let rules = Self::default();
            rules.save(path)?;

            return Ok(rules);
        };

        match parse_rule_file(&bytes) {
            Ok((rules, checksum)) => {
                warn_checksum(path, &checksum);

                Ok(rules)
            }
            Err(error) => {
                let backup = store::backup_path(path);
                let Some(back_bytes) = store::read_if_exists(&backup)? else {
                    return Err(error).with_context(|| format!("parse {}", path.display()));
                };

                let rules = parse_rule_file(&back_bytes)
                    .map(|(rules, _checksum)| rules)
                    .with_context(|| {
                        format!(
                            "parse {} after {} failed: {error}",
                            backup.display(),
                            path.display()
                        )
                    })?;

                warn!(
                    backup = %backup.display(),
                    file = %path.display(),
                    "rules file unreadable, read the backup instead",
                );

                Ok(rules)
            }
        }
    }

    /// Read a whole rule file from text, which is what an import hands over rather than a path.
    ///
    /// This is the same reader [`RuleFile::load_or_create`] uses for the file on disk, so a body
    /// that would fail to start the tool fails an import too: the version, the field names and the
    /// values a rule cannot hold are refused before anything is written.
    pub fn from_text(text: &str) -> Result<Self> {
        let (rules, checksum) =
            parse_rule_file(text.as_bytes()).context("parse the imported rules")?;

        if checksum.mismatched() {
            warn!(
                stated = checksum.stated.as_deref().unwrap_or("none"),
                found = %checksum.actual,
                "imported rules file checksum does not match its contents",
            );
        }

        Ok(rules)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        store::write_backup(path, file_text(&self.rule)?.as_bytes())
    }
}

/// Say so when a file on disk does not hash to what it claims.
fn warn_checksum(path: &Path, checksum: &Checksum) {
    if checksum.mismatched() {
        warn!(
            file = %path.display(),
            stated = checksum.stated.as_deref().unwrap_or("none"),
            found = %checksum.actual,
            "rules file checksum does not match its contents",
        );
    }
}
