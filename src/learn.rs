//! Learning mode: the applications this machine talks to that no rule speaks about yet.
//!
//! The C reference answers a new connection with a popup. A web UI has no modal to show while
//! nobody is looking at the page, so unknown applications are collected here instead and the user
//! decides later, from the browser (PLAN.md section 3).
//!
//! The unit is the application, not the connection: one executable that makes a hundred
//! connections is one decision, and the connection feed next to it is where the hundred are shown.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::monitor::NetEvent;
use crate::rules::{RuleFile, covered_by};

/// How many applications the Detected list holds. The newest is kept, the oldest falls out.
const DETECTED_CAP: usize = 100;

/// One application waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// The application path in the device form the firewall reports. This is the identity of the
    /// entry and what a new filter is built from.
    pub app: String,
    /// The same path in drive form, because that is what a human reads and types.
    pub display: String,
    /// Milliseconds since the epoch of the connection we last saw.
    pub seen_ms: u64,
    /// How often we saw it, so a chatty application is recognisable as one.
    pub hits: u64,
    /// Whether the last connection was allowed. Distinguishes "never seen" from "blocked right
    /// now", which are different problems.
    pub allowed: bool,
}

/// The file on disk. A wrapper struct keeps the format extensible without a rename later.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LearnFile {
    entry: Vec<Detected>,
}

/// The Detected list, shared between the monitor's callbacks and the request threads.
#[derive(Debug)]
pub struct Detector {
    inner: Mutex<LearnFile>,
    /// Where the list is persisted. Kept in the value so every change writes itself.
    path: PathBuf,
}

impl Detector {
    /// Read the Detected list, treating a missing file as an empty one.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = crate::store::read_if_exists(path)?.unwrap_or_default();

        let file: LearnFile = if bytes.is_empty() {
            LearnFile::default()
        } else {
            serde_json::from_slice(&bytes).context("parse learn.json")?
        };

        Ok(Self {
            inner: Mutex::new(file),
            path: path.to_path_buf(),
        })
    }

    /// Take one connection into account.
    ///
    /// An application an enabled rule already covers is not detected, whatever the store decided
    /// to do with it: a rule that blocks it is a decision the user already made. Returns whether
    /// the *file* changed, which is only the case when a new application appeared — refreshing a
    /// timestamp is not worth a write.
    pub fn observe(&self, event: &NetEvent, rules: &RuleFile) -> bool {
        if event.app.is_empty() {
            return false;
        }

        let display = crate::device::to_dos_path(&event.app);

        if covered_by(rules, &display) || covered_by(rules, &event.app) {
            return false;
        }

        let mut list = self.inner.lock().expect("learn lock poisoned");

        if let Some(existing) = list.entry.iter_mut().find(|entry| entry.app == event.app) {
            existing.seen_ms = event.time_ms;
            existing.hits += 1;
            existing.allowed = event.allowed;

            return false;
        }

        list.entry.insert(
            0,
            Detected {
                app: event.app.clone(),
                display,
                seen_ms: event.time_ms,
                hits: 1,
                allowed: event.allowed,
            },
        );
        list.entry.truncate(DETECTED_CAP);

        true
    }

    /// Persist the list. Called by the monitor when [`Detector::observe`] said the file changed.
    pub fn save(&self) -> Result<()> {
        let list = self.inner.lock().expect("learn lock poisoned");
        let text = serde_json::to_vec_pretty(&*list).context("serialize learn.json")?;

        crate::store::write_atomic(&self.path, &text)
    }

    /// The list as it stands, newest first.
    pub fn snapshot(&self) -> Vec<Detected> {
        self.inner
            .lock()
            .expect("learn lock poisoned")
            .entry
            .clone()
    }

    /// Take an application out of the list, as `dismiss` and a decided entry both do.
    pub fn dismiss(&self, app: &str) -> Result<bool> {
        let mut list = self.inner.lock().expect("learn lock poisoned");
        let before = list.entry.len();

        list.entry.retain(|entry| entry.app != app);

        let removed = list.entry.len() != before;

        if removed {
            let text = serde_json::to_vec_pretty(&*list).context("serialize learn.json")?;
            crate::store::write_atomic(&self.path, &text)?;
        }

        Ok(removed)
    }

    /// The application paths this tool has seen, in device form.
    ///
    /// These are the candidates a wildcard rule is expanded against: WFP compares an application
    /// path exactly, so a pattern with `*` only becomes a filter for paths that were actually
    /// observed.
    pub fn apps(&self) -> Vec<String> {
        self.inner
            .lock()
            .expect("learn lock poisoned")
            .entry
            .iter()
            .map(|entry| entry.app.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detector(name: &str) -> Detector {
        let path = crate::testutil::scratch_dir(name).join("learn.json");

        Detector::load(&path).expect("load")
    }

    fn event(app: &str, seq_time: u64) -> NetEvent {
        NetEvent {
            seq: 0,
            time_ms: seq_time,
            app: app.to_owned(),
            remote_port: 443,
            protocol: 6,
            allowed: true,
            kind: "allowed".to_owned(),
        }
    }

    fn rules(pattern: &str) -> RuleFile {
        RuleFile {
            rule: vec![crate::rules::Rule {
                name: "one".to_owned(),
                action: crate::rules::Action::Allow,
                pattern: pattern.to_owned(),
                enabled: true,
            }],
        }
    }

    #[test]
    fn an_uncovered_application_is_detected_once() {
        let detector = detector("detect-once");

        assert!(detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default()
        ));
        assert!(!detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 20),
            &RuleFile::default()
        ));

        let snapshot = detector.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].hits, 2);
        assert_eq!(snapshot[0].seen_ms, 20);
    }

    #[test]
    fn an_application_a_rule_covers_is_not_detected() {
        let detector = detector("detect-covered");

        let covered = detector.observe(
            &event("\\device\\harddiskvolume3\\windows\\a.exe", 10),
            &rules("\\device\\harddiskvolume3\\windows\\*"),
        );

        assert!(!covered);
        assert!(detector.snapshot().is_empty());
    }

    #[test]
    fn an_event_without_an_application_is_not_detected() {
        let detector = detector("detect-empty");

        assert!(!detector.observe(&event("", 10), &RuleFile::default()));
    }

    #[test]
    fn a_dismissed_application_leaves_no_entry() {
        let detector = detector("detect-dismiss");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );

        assert!(
            detector
                .dismiss("\\device\\harddiskvolume3\\a.exe")
                .expect("dismiss")
        );
        assert!(
            !detector
                .dismiss("\\device\\harddiskvolume3\\a.exe")
                .expect("dismiss again")
        );
    }

    #[test]
    fn the_list_survives_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("detect-round-trip").join("learn.json");
        let detector = Detector::load(&path).expect("load");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.save().expect("save");

        let loaded = Detector::load(&path).expect("reload");

        assert_eq!(loaded.snapshot(), detector.snapshot());
        assert_eq!(
            loaded.apps(),
            vec!["\\device\\harddiskvolume3\\a.exe".to_owned()]
        );
    }

    #[test]
    fn the_newest_application_is_first() {
        let detector = detector("detect-order");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.observe(
            &event("\\device\\harddiskvolume3\\b.exe", 20),
            &RuleFile::default(),
        );

        assert_eq!(
            detector.snapshot()[0].app,
            "\\device\\harddiskvolume3\\b.exe"
        );
    }
}
