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

/// Whether two application paths name the same application.
///
/// Windows paths are case-insensitive, and the firewall reports a device path in lower case while
/// a human types what the shell shows them, so `\Device\HarddiskVolume3\Windows\...` and
/// `\device\harddiskvolume3\windows\...` are the same program. Comparing them exactly would give
/// one application two Detected entries and let a dismiss miss the other.
fn same_app(one: &str, other: &str) -> bool {
    one.eq_ignore_ascii_case(other)
}

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
    /// The Detected list of the default profile in files written before 0.55.0. Loading moves it
    /// into `profiles` under the empty name, so a file written since then carries no `entry` at
    /// all, which is what `skip_serializing_if` expresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    entry: Vec<Detected>,
    /// Every profile's Detected list, keyed by profile name; the empty name is the default
    /// profile. The list of the profile that is live is always present, so an entry is collected
    /// into it rather than having to decide where it belongs.
    ///
    /// The lists are per profile because they hold decisions about rules, and rules are what a
    /// profile changes. `#[serde(default)]` keeps a `learn.json` written before 0.55.0 readable.
    #[serde(default)]
    profiles: std::collections::BTreeMap<String, Vec<Detected>>,
    /// Every application path this tool has seen connecting, newest first.
    ///
    /// This is deliberately outside the per-profile map: the Detected list is a to-do list that
    /// shrinks when a decision is made and stops growing when learning mode is off, while the set
    /// a wildcard rule is expanded against is a fact about the machine that has to keep both, and
    /// an application an inactive profile has seen is still an application that exists.
    #[serde(default)]
    seen: Vec<String>,
}

/// Fold the entries of one list that name the same application in another spelling together.
///
/// The list arrives newest first and stays that way: the merged entry keeps the position of the
/// newer one, while its `app` and `display` are taken from the older one, because that is the
/// spelling a human has already read on this screen. Hits are added and the newer timestamp wins,
/// so folding loses neither traffic nor recency.
fn merge_entries(entries: &mut Vec<Detected>) {
    let mut merged: Vec<Detected> = Vec::with_capacity(entries.len());

    for entry in entries.drain(..) {
        match merged
            .iter_mut()
            .find(|kept| same_app(&kept.app, &entry.app) && kept.remote == entry.remote)
        {
            Some(existing) => {
                existing.hits += entry.hits;

                if entry.seen_ms > existing.seen_ms {
                    existing.seen_ms = entry.seen_ms;
                    existing.allowed = entry.allowed;
                } else {
                    existing.app = entry.app;
                    existing.display = entry.display;
                }
            }
            None => merged.push(entry),
        }
    }

    *entries = merged;
}

/// Drop the paths of a seen list that repeat an application under another spelling.
///
/// The first occurrence is the newest and is the one kept, which is what a wildcard expansion is
/// built from: one filter per application rather than one per spelling.
fn merge_seen(seen: &mut Vec<String>) {
    let mut merged: Vec<String> = Vec::with_capacity(seen.len());

    for path in seen.drain(..) {
        if !merged.iter().any(|kept| same_app(kept, &path)) {
            merged.push(path);
        }
    }

    *seen = merged;
}

/// The Detected list, shared between the monitor's callbacks and the request threads.
#[derive(Debug)]
pub struct Detector {
    inner: Mutex<LearnFile>,
    /// The profile whose list is the live one. Mirrors the active profile of the tool, which is
    /// what tells the monitor thread where a new event belongs without asking the server.
    active: Mutex<String>,
    /// Where the list is persisted. Kept in the value so every change writes itself.
    path: PathBuf,
}

impl Detector {
    /// Read the Detected list for one profile, treating a missing file as an empty one.
    ///
    /// A file written before 0.55.0 holds a single list under `entry`; that list becomes the
    /// default profile's, because it was collected while the default profile was the only one.
    pub fn load(path: &Path, active: &str) -> Result<Self> {
        let bytes = crate::store::read_if_exists(path)?.unwrap_or_default();

        let mut file: LearnFile = if bytes.is_empty() {
            LearnFile::default()
        } else {
            serde_json::from_slice(&bytes).context("parse learn.json")?
        };

        if file.profiles.is_empty() {
            file.profiles
                .insert(String::new(), std::mem::take(&mut file.entry));
        } else {
            file.entry.clear();
        }
        file.profiles.entry(active.to_owned()).or_default();

        // A file written before the comparison ignored case can hold two entries for one
        // application, and a seen list with both spellings of a path would hand a wildcard rule the
        // same application twice. Merging on load is the whole migration; nothing is rewritten.
        for entries in file.profiles.values_mut() {
            merge_entries(entries);
        }
        merge_seen(&mut file.seen);

        Ok(Self {
            inner: Mutex::new(file),
            active: Mutex::new(active.to_owned()),
            path: path.to_path_buf(),
        })
    }

    /// Make another profile's list the live one, persisting the swap so a restart does not undo
    /// it in the file. The list left behind stays under its profile's name.
    pub fn set_profile(&self, name: &str) -> Result<()> {
        let mut active = self.active.lock().expect("active profile lock poisoned");

        if *active == name {
            return Ok(());
        }

        {
            let mut list = self.inner.lock().expect("learn lock poisoned");
            list.profiles.entry(active.clone()).or_default();
            list.profiles.entry(name.to_owned()).or_default();
            *active = name.to_owned();
        }

        self.save()
    }

    /// Move one profile's list to a new name, following the rules file the rename moved.
    pub fn rename_profile(&self, from: &str, to: &str) -> Result<()> {
        let mut active = self.active.lock().expect("active profile lock poisoned");
        let changed = {
            let mut list = self.inner.lock().expect("learn lock poisoned");

            match list.profiles.remove(from) {
                Some(entries) => {
                    list.profiles.insert(to.to_owned(), entries);
                    if *active == from {
                        *active = to.to_owned();
                    }
                    true
                }
                None => false,
            }
        };

        if changed { self.save() } else { Ok(()) }
    }

    /// Take one profile's list out, as deleting a profile does. The live list is not this path:
    /// the switch that follows decides what is live instead.
    pub fn drop_profile(&self, name: &str) -> Result<()> {
        let removed = {
            let mut list = self.inner.lock().expect("learn lock poisoned");
            list.profiles.remove(name).is_some()
        };

        if removed { self.save() } else { Ok(()) }
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

        let active = self.active.lock().expect("active profile lock poisoned");
        let mut list = self.inner.lock().expect("learn lock poisoned");
        let entries = list.profiles.entry(active.clone()).or_default();

        if let Some(existing) = entries
            .iter_mut()
            .find(|entry| same_app(&entry.app, &event.app) && entry.remote == remote)
        {
            existing.seen_ms = event.time_ms;
            existing.hits += 1;
            existing.allowed = event.allowed;

            return false;
        }

        entries.insert(
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
        entries.truncate(DETECTED_CAP);

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

        if list.seen.iter().any(|known| same_app(known, app)) {
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

    /// The live profile's list as it stands, newest first.
    pub fn snapshot(&self) -> Vec<Detected> {
        let active = self.active.lock().expect("active profile lock poisoned");
        let list = self.inner.lock().expect("learn lock poisoned");

        list.profiles.get(&*active).cloned().unwrap_or_default()
    }

    /// Take one entry out of the live profile's list, as `dismiss` and a decided entry both do.
    ///
    /// `remote` has to be the entry's destination, or `None` for an entry about the application
    /// alone; the two are different entries of the same application.
    pub fn dismiss(&self, app: &str, remote: Option<&str>) -> Result<bool> {
        let active = self.active.lock().expect("active profile lock poisoned");
        let mut list = self.inner.lock().expect("learn lock poisoned");
        let entries = list.profiles.entry(active.clone()).or_default();
        let before = entries.len();

        entries.retain(|entry| !same_app(&entry.app, app) || entry.remote.as_deref() != remote);

        let removed = entries.len() != before;

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

        Detector::load(&path, "").expect("load")
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
            local_network: false,
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
        let detector = Detector::load(&path, "").expect("load");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.note_app("\\device\\harddiskvolume3\\a.exe");
        detector.save().expect("save");

        let loaded = Detector::load(&path, "").expect("reload");

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

    /// The whole point of the per-profile lists: an undecided entry collected while one profile
    /// was live is not reported while another one is, because the decision it waits for belongs
    /// to rules that are no longer in the store.
    #[test]
    fn each_profile_collects_its_own_list() {
        let detector = detector("detect-per-profile");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.set_profile("work").expect("switch");

        assert!(
            detector.snapshot().is_empty(),
            "the new profile starts empty"
        );

        detector.observe(
            &event("\\device\\harddiskvolume3\\b.exe", 20),
            &RuleFile::default(),
        );

        assert_eq!(detector.snapshot().len(), 1);
        assert_eq!(
            detector.snapshot()[0].app,
            "\\device\\harddiskvolume3\\b.exe",
        );
    }

    /// Switching back returns exactly the list that was left behind — including the hits and the
    /// timestamps the entries had accumulated, because the swap moves the list rather than
    /// rebuilding it.
    #[test]
    fn switching_back_returns_the_list_that_was_left_behind() {
        let detector = detector("detect-switch-back");

        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 20),
            &RuleFile::default(),
        );
        detector.set_profile("work").expect("switch");
        detector.observe(
            &event("\\device\\harddiskvolume3\\b.exe", 30),
            &RuleFile::default(),
        );
        detector.set_profile("").expect("switch back");

        assert_eq!(
            detector.snapshot().len(),
            1,
            "the default list is whole again"
        );
        assert_eq!(detector.snapshot()[0].hits, 2, "and it kept its history");
    }

    /// The seen list is a fact about the machine, not about a profile: an application another
    /// profile has seen is still an application that exists, and a wildcard rule of the live
    /// profile has to expand against all of them.
    #[test]
    fn the_seen_pool_is_shared_between_the_profiles() {
        let detector = detector("detect-shared-pool");

        detector.note_app("\\device\\harddiskvolume3\\a.exe");
        detector.set_profile("work").expect("switch");

        assert_eq!(
            detector.apps(),
            vec!["\\device\\harddiskvolume3\\a.exe".to_owned()],
            "the pool does not follow the profile",
        );
    }

    /// A file written before the lists were per profile holds one list under `entry`; it was
    /// collected while the default profile was the only one, so that is where it belongs.
    #[test]
    fn a_file_written_before_profiles_keeps_its_list_as_the_default() {
        let path = crate::testutil::scratch_dir("detect-old-format").join("learn.json");

        std::fs::write(
            &path,
            r#"{"entry":[{"app":"\\device\\harddiskvolume3\\a.exe","display":"C:\\a.exe","remote":null,"seen_ms":10,"hits":1,"allowed":false}],"seen":["\\device\\harddiskvolume3\\a.exe"]}"#,
        )
        .expect("write the old file");

        let detector = Detector::load(&path, "work").expect("load the old file");

        assert_eq!(
            detector.snapshot().len(),
            0,
            "the new profile has no list yet"
        );

        detector.set_profile("").expect("switch back");

        assert_eq!(
            detector.snapshot().len(),
            1,
            "the old list is the default one"
        );
        assert_eq!(
            detector.apps(),
            vec!["\\device\\harddiskvolume3\\a.exe".to_owned()],
        );
    }

    /// Windows paths are case-insensitive, and the firewall lowercases the device path it reports,
    /// so the same program can arrive in two spellings. It is one decision, not two.
    #[test]
    fn two_spellings_of_one_application_are_one_entry() {
        let detector = detector("detect-spelling");
        let rules = RuleFile::default();

        assert!(
            detector.observe(&event("\\device\\HarddiskVolume3\\A.exe", 10), &rules),
            "the first spelling is a new entry",
        );
        assert!(
            !detector.observe(&event("\\DEVICE\\harddiskvolume3\\a.exe", 20), &rules),
            "the second one is the same application, so the file does not change",
        );

        let list = detector.snapshot();

        assert_eq!(list.len(), 1, "one application is one entry");
        assert_eq!(list[0].hits, 2, "both connections counted");
        assert_eq!(list[0].seen_ms, 20, "and the newer one is the timestamp");
        assert_eq!(
            list[0].app,
            "\\device\\HarddiskVolume3\\A.exe".to_owned(),
            "the entry keeps the spelling it was created with",
        );
    }

    /// A dismiss addresses the application, not the bytes someone typed, so it has to reach an
    /// entry that was collected under another spelling.
    #[test]
    fn a_dismiss_reaches_an_entry_collected_under_another_spelling() {
        let detector = detector("detect-dismiss-spelling");
        let rules = RuleFile::default();

        detector.observe(&event("\\device\\HarddiskVolume3\\A.exe", 10), &rules);
        detector.observe(&event("\\device\\harddiskvolume3\\a.exe", 20), &rules);

        assert!(
            detector
                .dismiss("\\DEVICE\\HARDDISKVOLUME3\\a.exe", None)
                .expect("dismiss"),
            "a third spelling dismisses it too",
        );
        assert!(
            detector.snapshot().is_empty(),
            "and there was only one entry to dismiss",
        );
    }

    /// The seen list is what a wildcard rule expands against. Two spellings of one application
    /// there would install two filters for one program, so the second spelling is not new.
    #[test]
    fn the_seen_pool_does_not_grow_on_another_spelling() {
        let detector = detector("detect-seen-spelling");

        assert!(
            detector.note_app("\\device\\HarddiskVolume3\\A.exe"),
            "the first spelling is new",
        );
        assert!(
            !detector.note_app("\\device\\harddiskvolume3\\a.exe"),
            "the other spelling of the same path is not",
        );
        assert_eq!(detector.apps().len(), 1, "and the pool holds one path");
    }

    /// A file written while the comparison was exact can hold both spellings of one application,
    /// in the Detected list as well as in the seen list. Loading folds them together per profile.
    #[test]
    fn a_file_holding_both_spellings_is_folded_on_load() {
        let path = crate::testutil::scratch_dir("detect-fold").join("learn.json");

        std::fs::write(
            &path,
            r#"{"profiles":{"":[{"app":"\\device\\HarddiskVolume3\\A.exe","display":"C:\\A.exe","remote":null,"seen_ms":20,"hits":1,"allowed":true},{"app":"\\device\\harddiskvolume3\\a.exe","display":"C:\\a.exe","remote":null,"seen_ms":10,"hits":4,"allowed":false}],"work":[{"app":"\\device\\HarddiskVolume3\\B.exe","display":"C:\\B.exe","remote":"8.8.8.8","seen_ms":5,"hits":1,"allowed":false}]},"seen":["\\device\\HarddiskVolume3\\A.exe","\\device\\harddiskvolume3\\b.exe","\\device\\harddiskvolume3\\a.exe"]}"#,
        )
        .expect("write the legacy file");

        let detector = Detector::load(&path, "").expect("load the legacy file");
        let list = detector.snapshot();

        assert_eq!(list.len(), 1, "the two spellings became one entry");
        assert_eq!(list[0].hits, 5, "and no connection was lost in the fold");
        assert_eq!(list[0].seen_ms, 20, "the newer timestamp is kept");
        assert_eq!(
            list[0].display, "C:\\a.exe",
            "the display keeps the spelling that was seen first",
        );
        assert_eq!(
            detector.apps(),
            vec![
                "\\device\\HarddiskVolume3\\A.exe".to_owned(),
                "\\device\\harddiskvolume3\\b.exe".to_owned(),
            ],
            "the seen list holds one path per application",
        );
    }

    /// A rename carries the list to the new name, and a delete takes it out: entries waiting for
    /// a decision about rules nobody can select again would be collected noise.
    #[test]
    fn a_renamed_profile_carries_its_list_and_a_deleted_oneloses_it() {
        let detector = detector("detect-rename-delete");

        detector.set_profile("before").expect("switch");
        detector.observe(
            &event("\\device\\harddiskvolume3\\a.exe", 10),
            &RuleFile::default(),
        );
        detector.rename_profile("before", "after").expect("rename");

        assert_eq!(
            detector.snapshot().len(),
            1,
            "the renamed profile is still live and still has its entry",
        );

        detector.drop_profile("after").expect("drop");

        assert!(
            detector.snapshot().is_empty(),
            "the list went with the profile"
        );
    }
}
