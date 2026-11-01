//! Manual backups of the files the tool owns, plus the Base64 form of a single rule.
//!
//! Export is on demand rather than automatic: the real state already lives in AppData, and this is
//! the "I want a copy in one folder" feature PLAN.md section 2 asks for. Import is deliberately
//! narrower than export: only a shared rule can come back in, and it is appended, so nothing that
//! exists can be overwritten by accident.

use std::path::Path;

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use serde::{Deserialize, Serialize};

use crate::paths::DataPaths;
use crate::rules::Rule;
use crate::store;

/// Which part of the data dir a backup takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Area {
    Rules,
    Config,
    Detected,
    Profiles,
    All,
}

/// What an export wrote. A missing source file is simply absent from `files`, because a backup of
/// a state the tool never created is not an error.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub area: Area,
    pub dir: String,
    pub files: Vec<String>,
}

/// Copy the chosen files into `export\`, under the same names.
///
/// Profiles keep their own subdirectory, because they are a set of equal files rather than a single
/// file, and flattening them would hide which of them is the default rules file.
///
/// Repeated exports overwrite one another on purpose: the directory mirrors the current state
/// rather than acting as a history, and the user copies it out whenever they want a snapshot.
pub fn run(paths: &DataPaths, area: Area) -> Result<Report> {
    std::fs::create_dir_all(&paths.export)
        .with_context(|| format!("create directory {}", paths.export.display()))?;

    let mut files = Vec::new();

    if matches!(area, Area::Rules | Area::All) {
        one(&paths.rules, &paths.export.join("rules.toml"), &mut files)?;
    }

    if matches!(area, Area::Config | Area::All) {
        one(&paths.config, &paths.export.join("config.toml"), &mut files)?;
    }

    if matches!(area, Area::Detected | Area::All) {
        one(&paths.learn, &paths.export.join("learn.json"), &mut files)?;
    }

    if matches!(area, Area::Profiles | Area::All) {
        many(&paths.profiles, &paths.export.join("profiles"), &mut files)?;
    }

    Ok(Report {
        area,
        dir: paths.export.display().to_string(),
        files,
    })
}

/// Encode one rule as the compact JSON of its fields, in Base64.
///
/// The alphabet is the standard one with padding, so the string survives an email, a chat message
/// and a double-click selection. Its length stays under the 998 characters a DNS label allows for
/// any realistic rule, which keeps it printable.
pub fn encode(rule: &Rule) -> Result<String> {
    let json = serde_json::to_string(rule).context("encode the rule as JSON")?;

    Ok(BASE64_STANDARD.encode(json.as_bytes()))
}

/// Read back what [`encode`] produced.
pub fn decode(text: &str) -> Result<Rule> {
    let bytes = BASE64_STANDARD
        .decode(text.trim())
        .context("the share string is not Base64")?;

    serde_json::from_slice(&bytes).context("the share string does not hold a rule")
}

/// Copy one file across when it exists.
fn one(from: &Path, to: &Path, files: &mut Vec<String>) -> Result<()> {
    let Some(bytes) = store::read_if_exists(from)? else {
        return Ok(());
    };

    // Written atomically even though this is only a backup, because a half-written backup is worse
    // than none at all when the original is being edited at the same time.
    store::write_atomic(to, &bytes)?;
    files.push(to.display().to_string());

    Ok(())
}

/// Copy every `*.toml` of a directory across. An empty directory exports nothing and is not an
/// error, which is the normal case for profiles until the user creates one.
fn many(from_dir: &Path, to_dir: &Path, files: &mut Vec<String>) -> Result<()> {
    let names = crate::rules::list_names(from_dir);

    if names.is_empty() {
        return Ok(());
    }

    std::fs::create_dir_all(to_dir)
        .with_context(|| format!("create directory {}", to_dir.display()))?;

    for name in names {
        one(
            &from_dir.join(format!("{name}.toml")),
            &to_dir.join(format!("{name}.toml")),
            files,
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::rules::Action;

    fn rule() -> Rule {
        Rule::plain("Block telemetry", Action::Deny, "C:\\Windows\\*")
    }

    #[test]
    fn a_shared_rule_survives_the_round_trip() {
        let original = rule();
        let text = encode(&original).expect("encode");

        assert!(
            text.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "{text} should be a Base64 alphabet"
        );

        assert_eq!(decode(&text).expect("decode"), original);
    }

    #[test]
    fn a_share_string_may_arrive_with_whitespace() {
        let text = format!("  {}\n", encode(&rule()).expect("encode"));

        assert_eq!(decode(&text).expect("decode"), rule());
    }

    #[test]
    fn a_share_string_that_is_not_a_rule_is_refused() {
        assert!(decode("not base64 at all !!").is_err());

        // Valid Base64, but it decodes to text rather than to a rule object.
        let encoded = BASE64_STANDARD.encode(b"hello");

        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn an_export_copies_the_files_of_the_chosen_area() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("export"));
        paths.ensure().expect("ensure");

        std::fs::write(&paths.rules, b"[rules]\n").expect("rules");
        std::fs::write(&paths.config, b"port = 8788\n").expect("config");

        let report = run(&paths, Area::All).expect("export");

        assert_eq!(report.files.len(), 2, "the Detected list does not exist");
        assert!(paths.export.join("rules.toml").is_file());
        assert!(paths.export.join("config.toml").is_file());
        assert!(!paths.export.join("learn.json").is_file());
    }

    #[test]
    fn an_export_copies_the_profiles_into_a_subdirectory() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("export-profiles"));
        paths.ensure().expect("ensure");

        std::fs::write(paths.profile_file("work"), b"[rules]\n").expect("work profile");
        std::fs::write(paths.profile_file("home"), b"[rules]\n").expect("home profile");

        let report = run(&paths, Area::All).expect("export");

        assert_eq!(report.files.len(), 2, "only the profiles are on disk");
        assert!(paths.export.join("profiles").join("home.toml").is_file());
        assert!(paths.export.join("profiles").join("work.toml").is_file());
    }

    #[test]
    fn an_export_of_the_profiles_area_ignores_the_single_files() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("export-profiles-one"));
        paths.ensure().expect("ensure");

        std::fs::write(&paths.rules, b"[rules]\n").expect("rules");
        std::fs::write(paths.profile_file("work"), b"[rules]\n").expect("work profile");

        let report = run(&paths, Area::Profiles).expect("export");

        assert_eq!(report.files.len(), 1);
        assert_eq!(
            report.files[0],
            paths
                .export
                .join("profiles")
                .join("work.toml")
                .display()
                .to_string()
        );
        assert!(!paths.export.join("rules.toml").is_file());
    }

    #[test]
    fn exporting_profiles_that_do_not_exist_creates_no_directory() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("export-profiles-empty"));
        paths.ensure().expect("ensure");

        let report = run(&paths, Area::Profiles).expect("export");

        assert!(report.files.is_empty());
        assert!(!paths.export.join("profiles").exists());
    }

    #[test]
    fn an_export_of_one_area_leaves_the_other_files_out() {
        let paths = DataPaths::under(crate::testutil::scratch_dir("export-one"));
        paths.ensure().expect("ensure");

        std::fs::write(&paths.rules, b"[rules]\n").expect("rules");
        std::fs::write(&paths.config, b"port = 8788\n").expect("config");

        let report = run(&paths, Area::Rules).expect("export");

        assert_eq!(report.files.len(), 1);
        assert!(!paths.export.join("config.toml").is_file());
    }
}
