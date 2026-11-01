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
use crate::rules::{RuleFile, covered_by, reaches};

/// How many applications the Detected list holds. The newest is kept, the oldest falls out.
const DETECTED_CAP: usize = 100;

/// How many application paths the seen list holds. It is the set a wildcard rule is expanded
/// against, so it is wider than the Detected list and grows whether or not learning mode is on.
const SEEN_CAP: usize = 512;

/// One application waiting for a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detected {
    /// The application path in the device form the firewall reports. This is the identity of the
    /// entry and what a new filter is built from.
    pub app: String,
    /// The same path in drive form, because that is what a human reads and types.
    pub display: String,
    /// The destination this entry waits for a decision about, in the text form the firewall
    /// reported it in, and `None` when the entry is about the application alone.
    ///
    /// An entry has a destination when a rule already speaks about the application but no rule of
    /// that application reaches this address. It is part of the entry's identity: one application
    /// reaching two undecided networks is two entries. `#[serde(default)]` keeps a `learn.json`
    /// written before 0.20.0 readable.
    #[serde(default)]
    pub remote: Option<String>,
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
    /// Every application path this tool has seen connecting, newest first.
    ///
    /// This is deliberately separate from `entry`: the Detected list is a to-do list that shrinks
    /// when a decision is made and stops growing when learning mode is off, while the set a
    /// wildcard rule is expanded against has to keep both. `#[serde(default)]` keeps a
    /// `learn.json` written by an earlier version readable.
    #[serde(default)]
    seen: Vec<String>,
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
    /// to do with it: a rule that blocks it is a decision the user already made. For an
    /// application that *is* covered, the destination is asked next, because a rule that allows
    /// one network does not decide the next one. Returns whether the *file* changed, which is
    /// only the case when a new entry appeared — refreshing a timestamp is not worth a write.
    pub fn observe(&self, event: &NetEvent, rules: &RuleFile) -> bool {
        if event.app.is_empty() {
            return false;
        }

        let display = crate::device::to_dos_path(&event.app);
        let covered = covered_by(rules, &display) || covered_by(rules, &event.app);

        // An application nobody has decided about yet is the decision, whatever it talks to, so
        // the entry carries no destination. For a covered one the address has to be undecided on
        // its own, and an event that names no address cannot offer a new one.
        let remote = if covered {
            match event.remote_addr.parse::<std::net::IpAddr>() {
                Ok(addr)
                    if !reaches(rules, &display, addr) && !reaches(rules, &event.app, addr) =>
                {
                    Some(event.remote_addr.clone())
                }
                _ => return false,
            }
        } else {
            None
        };

        let mut list = self.inner.lock().expect("learn lock poisoned");

        if let Some(existing) = list
            .entry
            .iter_mut()
            .find(|entry| entry.app == event.app && entry.remote == remote)
        {
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
                remote,
                seen_ms: event.time_ms,
                hits: 1,
                allowed: event.allowed,
            },
        );
        list.entry.truncate(DETECTED_CAP);

        true
    }

    /// Record that an application connected, whether or not a rule covers it and whether or not
    /// learning mode is on.
    ///
    /// This is the set a wildcard rule is expanded against, so it has to grow even for an
    /// application nobody has to decide about. Returns whether the application was new to the
    /// list, which is what tells the monitor a rebuild of the wildcard filters is worth doing.
    pub fn note_app(&self, app: &str) -> bool {
        if app.is_empty() {
            return false;
        }

        let mut list = self.inner.lock().expect("learn lock poisoned");

        if list.seen.iter().any(|known| known == app) {
            return false;
        }

        list.seen.insert(0, app.to_owned());
        list.seen.truncate(SEEN_CAP);

        true
    }

    /// Persist the list. Called by the monitor when [`Detector::observe`] or
    /// [`Detector::note_app`] said the file changed.
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

    /// Take one entry out of the list, as `dismiss` and a decided entry both do.
    ///
    /// `remote` has to be the entry's destination, or `None` for an entry about the application
    /// alone; the two are different entries of the same application.
    pub fn dismiss(&self, app: &str, remote: Option<&str>) -> Result<bool> {
        let mut list = self.inner.lock().expect("learn lock poisoned");
        let before = list.entry.len();

        list.entry
            .retain(|entry| entry.app != app || entry.remote.as_deref() != remote);

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
    /// observed. This is the seen list rather than the Detected list, because an application an
    /// existing rule already covers is exactly what a wildcard rule wants to match, and because
    /// collection continues when learning mode is off.
    pub fn apps(&self) -> Vec<String> {
        self.inner.lock().expect("learn lock poisoned").seen.clone()
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
            local_addr: String::new(),
            local_port: 49_152,
            remote_port: 443,
            remote_addr: String::new(),
            loopback: false,
            protocol: 6,
            allowed: true,
            kind: "allowed".to_owned(),
            filter_id: 0,
            rule: None,
        }
    }

    fn rules(pattern: &str) -> RuleFile {
        RuleFile {
            rule: vec![crate::rules::Rule::plain(
                "one",
                crate::rules::Action::Allow,
                pattern,
            )],
        }
    }

    /// The same application, but the rule only reaches one network.
    fn rules_reaching(pattern: &str, remote: &str) -> RuleFile {
        RuleFile {
            rule: vec![crate::rules::Rule {
                remote: Some(remote.parse().expect("parse a network")),
                ..crate::rules::Rule::plain("one", crate::rules::Action::Allow, pattern)
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

    /// The question learning mode asks is where a connection went, so the destination it offers is
    /// the remote end and never the local one: an event that names only a local address has nothing
    /// to offer, however unusual that address is.
    #[test]
    fn a_detected_destination_is_the_remote_end_and_never_the_local_one() {
        let detector = detector("detect-remote-not-local");
        let covered = rules_reaching("\\device\\harddiskvolume3\\windows\\*", "10.0.0.0/24");
        let app = "\\device\\harddiskvolume3\\windows\\a.exe";

        let local_only = NetEvent {
            local_addr: "93.184.216.34".to_owned(),
            ..event(app, 10)
        };

        assert!(
            !detector.observe(&local_only, &covered),
            "no remote address, no destination",
        );
        assert!(detector.snapshot().is_empty());

        let remote = NetEvent {
            remote_addr: "93.184.216.34".to_owned(),
            ..event(app, 20)
        };

        assert!(detector.observe(&remote, &covered));

        let snapshot = detector.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].remote.as_deref(), Some("93.184.216.34"));
    }

    /// The loopback marker tells a reader that a connection never left the machine, and it decides
    /// nothing on its own: a loopback destination no rule reaches is still worth asking about.
    #[test]
    fn a_loopback_connection_is_detected_by_its_destination_like_any_other() {
        let detector = detector("detect-loopback-still-counts");
        let covered = rules_reaching("\\device\\harddiskvolume3\\*", "10.0.0.0/24");

        let entry = NetEvent {
            remote_addr: "127.0.0.1".to_owned(),
            loopback: true,
            ..event("\\device\\harddiskvolume3\\b.exe", 10)
        };

        assert!(
            detector.observe(&entry, &covered),
            "the marker is not a filter"
        );
        assert_eq!(detector.snapshot()[0].remote.as_deref(), Some("127.0.0.1"));
    }

    /// An application a rule allows to one network is not decided about the next one, so the new
    /// destination is what the user is asked about, and the entry names it.
    #[test]
    fn an_allowed_application_reaching_a_new_network_is_detected_with_it() {
        let detector = detector("detect-destination");
        let covered = rules_reaching("\\device\\harddiskvolume3\\windows\\*", "10.0.0.0/24");

        let inside = NetEvent {
            remote_addr: "10.0.0.5".to_owned(),
            ..event("\\device\\harddiskvolume3\\windows\\a.exe", 10)
        };
        let outside = NetEvent {
            remote_addr: "93.184.216.34".to_owned(),
            ..event("\\device\\harddiskvolume3\\windows\\a.exe", 20)
        };

        assert!(!detector.observe(&inside, &covered));
        assert!(detector.snapshot().is_empty(), "the rule reaches this one");

        assert!(detector.observe(&outside, &covered));

        let snapshot = detector.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(
            snapshot[0].remote.as_deref(),
            Some("93.184.216.34"),
            "the destination is what the entry is about",
        );

        // The same destination again only refreshes the entry.
        assert!(!detector.observe(&outside, &covered));
        assert_eq!(detector.snapshot()[0].hits, 2);
    }

    /// An application nobody decided about is itself the decision, whatever it talks to, so its
    /// entry carries no destination. That entry and a destination entry of the same application are
    /// two entries, and dismissing one leaves the other alone.
    #[test]
    fn an_application_entry_and_a_destination_entry_are_separate() {
        let detector = detector("detect-two-entries");
        let app = "\\device\\harddiskvolume3\\b.exe";

        assert!(detector.observe(&event(app, 10), &RuleFile::default()));

        let covered = rules_reaching("\\device\\harddiskvolume3\\*", "10.0.0.0/24");

        assert!(detector.observe(
            &NetEvent {
                remote_addr: "93.184.216.34".to_owned(),
                ..event(app, 20)
            },
            &covered,
        ));

        let snapshot = detector.snapshot();

        assert_eq!(snapshot.len(), 2);
        assert_eq!(snapshot[0].remote.as_deref(), Some("93.184.216.34"));
        assert_eq!(snapshot[1].remote, None);

        assert!(
            detector
                .dismiss(app, None)
                .expect("dismiss the application entry")
        );

        assert_eq!(detector.snapshot().len(), 1, "the other entry stays");
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
                .dismiss("\\device\\harddiskvolume3\\a.exe", None)
                .expect("dismiss")
        );
        assert!(
            !detector
                .dismiss("\\device\\harddiskvolume3\\a.exe", None)
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
        detector.note_app("\\device\\harddiskvolume3\\a.exe");
        detector.save().expect("save");

        let loaded = Detector::load(&path).expect("reload");

        assert_eq!(loaded.snapshot(), detector.snapshot());
        assert_eq!(
            loaded.apps(),
            vec!["\\device\\harddiskvolume3\\a.exe".to_owned()]
        );
    }

    #[test]
    fn the_seen_list_grows_even_when_nothing_is_detected() {
        let detector = detector("detect-seen");

        // An application a rule covers is not detected, but it is seen, and a wildcard rule has
        // to be expanded against it.
        let covered = rules("\\device\\harddiskvolume3\\windows\\*");

        assert!(!detector.observe(
            &event("\\device\\harddiskvolume3\\windows\\a.exe", 10),
            &covered,
        ));
        assert!(detector.snapshot().is_empty());

        assert!(detector.note_app("\\device\\harddiskvolume3\\windows\\a.exe"));
        assert!(!detector.note_app("\\device\\harddiskvolume3\\windows\\a.exe"));
        assert!(!detector.note_app(""));

        assert_eq!(
            detector.apps(),
            vec!["\\device\\harddiskvolume3\\windows\\a.exe".to_owned()]
        );
    }

    #[test]
    fn a_decided_application_stays_a_wildcard_candidate() {
        let detector = detector("detect-dismiss-seen");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.note_app("\\device\\harddiskvolume3\\a.exe");
        detector
            .dismiss("\\device\\harddiskvolume3\\a.exe", None)
            .expect("dismiss");

        // Dismissing empties the Detected list, but the application was still seen, and a
        // wildcard rule written later must still be expanded against it.
        assert!(detector.snapshot().is_empty());
        assert_eq!(
            detector.apps(),
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
