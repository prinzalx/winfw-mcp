//! The state a request handler may touch: the authoritative rules, the settings that stay live,
//! and the record the startup rebuild left behind.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tracing::warn;
use tracing_subscriber::EnvFilter;

use crate::LogFilterHandle;
use crate::config::{Policy, Settings, Theme};
use crate::learn::Detector;
use crate::monitor::{EventLog, MonitorStatus};
use crate::paths::DataPaths;
use crate::rules::{Fingerprint, RuleFile, write_stamp};

use super::routes::MonitorJson;
use super::worker::StoreOutcome;

/// Everything a request handler may touch.
///
/// The rules are the in-memory copy that the request handlers keep authoritative: a change is
/// applied to this value, written to disk, and only then pushed to the store, which is the order
/// plan section 2 asks for.
pub struct AppState {
    pub(super) paths: DataPaths,
    pub(super) settings: Settings,
    pub(super) rules: Arc<Mutex<RuleFile>>,
    /// The applications learning mode collected, waiting for a decision.
    pub(super) detector: Arc<Detector>,
    /// `learn_mode` and `default_policy` as they may change while the process runs. The monitor
    /// thread reads the same pair, which is why they are atomics rather than fields of
    /// `settings`.
    pub(super) live: Arc<Live>,
    /// The live connection feed, filled by the monitor thread.
    pub(super) events: Arc<EventLog>,
    /// The file the active rules are read from and written back to: `rules.toml` for the default
    /// profile, `profiles\<name>.toml` otherwise. A switch changes it.
    pub(super) active_file: Mutex<PathBuf>,
    /// The active profile name, or empty for `rules.toml` itself.
    pub(super) active_name: Mutex<String>,
    /// Kept set while the process should keep accepting connections. `POST /api/shutdown` and the
    /// tray's `Quit` both clear it, which is the only way either of them has of ending a process
    /// whose main thread is parked in the accept loop.
    pub(super) running: Arc<AtomicBool>,
    /// What the rebuild at startup made of the store. Never changes afterwards: it is the record of
    /// the difference the process found between the store and the rules file.
    pub(super) startup: Startup,
    /// The session token a writing request has to carry (plan section 11).
    ///
    /// It lives here and nowhere else: no file, no log, and — since 0.58.0 — no answer body. The
    /// browser learns it from the fragment of the URL the tray opened, and a request that wants to
    /// write carries it back in a header.
    pub(super) token: String,
    /// The contents of the rules file the tool wrote last, as a fingerprint.
    ///
    /// At startup this is the stamp the previous run left behind rather than the file on disk,
    /// which is exactly what makes a hand edit made while the tool was closed show up as a
    /// difference. Writing the file replaces the record, so the notice disappears with the edit
    /// that caused it and needs no bookkeeping of its own.
    rules_written: Mutex<Option<Fingerprint>>,
    /// How often this process has written the rules file.
    ///
    /// A page that holds an old copy of the list can name the generation it read in a whole-file
    /// write, and the server refuses the write when its own generation has moved on: the last
    /// writer no longer wins silently. The counter is per run, which is enough, because a restart
    /// hands every client a fresh state anyway.
    rules_generation: AtomicU64,
    /// The log level as the process understands it, which a settings change moves.
    ///
    /// It is kept apart from `settings` for the same reason `learn_mode` is: the value in
    /// `settings` is the one read at startup and is only ever written back to `config.toml`, so a
    /// report that used it would tell a page about the last run rather than this one.
    log: Mutex<String>,
    /// The handle that swaps the `tracing` filter, or `None` for a process that installed no
    /// subscriber, which is what every test is.
    log_filter: Mutex<Option<LogFilterHandle>>,
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paths: DataPaths,
        settings: Settings,
        rules: Arc<Mutex<RuleFile>>,
        detector: Arc<Detector>,
        events: Arc<EventLog>,
        live: Arc<Live>,
        active_file: PathBuf,
        active_name: String,
        startup: Startup,
        token: String,
        rules_written: Option<Fingerprint>,
        log_filter: Option<LogFilterHandle>,
    ) -> Self {
        // Read before `settings` moves into the struct below.
        let log_level = settings.log_level.clone();

        Self {
            paths,
            settings,
            rules,
            detector,
            events,
            live,
            active_file: Mutex::new(active_file),
            active_name: Mutex::new(active_name),
            running: Arc::new(AtomicBool::new(true)),
            startup,
            token,
            rules_written: Mutex::new(rules_written),
            rules_generation: AtomicU64::new(0),
            log: Mutex::new(log_level),
            log_filter: Mutex::new(log_filter),
        }
    }

    /// The handle the tray needs in order to stop the server. The same flag the routes set, so the
    /// two ways of quitting cannot disagree about whether the process is on its way out.
    pub fn stop_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Ask the process to stop, and report whether this call was the one that did it. A repeated
    /// request gets `false`, which is how a client tells "I stopped it" from "it was already
    /// on its way out".
    pub(super) fn request_stop(&self) -> bool {
        self.running
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// The file the active rules live in. Read on every save, because a switch changes it.
    pub(super) fn rules_path(&self) -> PathBuf {
        self.active_file
            .lock()
            .expect("rules path lock poisoned")
            .clone()
    }

    /// The active profile name, or empty for `rules.toml`.
    pub(super) fn active_name(&self) -> String {
        self.active_name
            .lock()
            .expect("active name lock poisoned")
            .clone()
    }

    /// The log level as the process understands it now, which is not necessarily what
    /// `config.toml` held at startup.
    pub(super) fn log_level(&self) -> String {
        self.log.lock().expect("log level lock poisoned").clone()
    }

    /// Adopt a log level the settings route just wrote, and hand it to `tracing`.
    ///
    /// The filter is swapped rather than reinstalled, so the next event is judged by the new level
    /// and nothing that is already logged is lost. A state built without a subscriber — which is
    /// every test — remembers the level and changes nothing else.
    pub(super) fn set_log_level(&self, level: &str) {
        {
            let mut current = self.log.lock().expect("log level lock poisoned");
            *current = level.to_owned();
        }

        let Ok(guard) = self.log_filter.lock() else {
            return;
        };

        match &*guard {
            Some(handle) => {
                if let Err(error) = handle.reload(EnvFilter::new(level)) {
                    warn!(reason = %error, "could not change the log level");
                }
            }
            None => drop(guard),
        }
    }

    /// The authoritative `learn_mode`: what the last `POST /api/settings` asked for, rather than
    /// what `config.toml` said at startup.
    pub(super) fn learn_mode(&self) -> bool {
        self.live.learning()
    }

    /// The authoritative `default_policy`, with the same caveat.
    pub(super) fn policy(&self) -> Policy {
        self.live.policy()
    }

    /// Whether the filters are in the store, which is what the protection switch answers.
    pub(super) fn protection(&self) -> bool {
        self.live.protection()
    }

    /// Ask for protection on or off and report what it became.
    pub(super) fn set_protection(&self, on: bool) -> bool {
        self.live.set_protection(on)
    }

    /// Record that the rules file on disk is now the tool's own work.
    ///
    /// Called after every write the tool does, so the next comparison measures the difference
    /// against what we wrote rather than against whatever a reader left behind. Writing the stamp
    /// is best effort: a stamp that cannot be written costs a lost notice, not a lost rule.
    pub(super) fn note_rules_written(&self) {
        self.rules_generation.fetch_add(1, Ordering::SeqCst);

        let file = self.rules_path();

        match Fingerprint::of_file(&file) {
            Ok(fingerprint) => {
                *self
                    .rules_written
                    .lock()
                    .expect("rules fingerprint lock poisoned") = fingerprint;
                write_stamp(&file, fingerprint);
            }
            Err(error) => {
                warn!(reason = %format!("{error:#}"), "could not fingerprint the rules file")
            }
        }
    }

    /// How often the rules file has been written during this run.
    pub(super) fn rules_generation(&self) -> u64 {
        self.rules_generation.load(Ordering::SeqCst)
    }

    /// Whether the rules file on disk is not the one the tool wrote.
    ///
    /// A file that has gone away counts as changed, because the rules the page shows are the ones in
    /// memory while the file that describes them is missing.
    pub(super) fn rules_changed_outside(&self) -> bool {
        let current = Fingerprint::of_file(&self.rules_path()).unwrap_or(None);
        let written = self
            .rules_written
            .lock()
            .expect("rules fingerprint lock poisoned");

        current != *written
    }

    /// What the event subscription did about being asked to listen.
    ///
    /// Both reports that answer "why is the connection list empty?" take it from here, so the
    /// page and an MCP client cannot be told different things about the same feed.
    pub(super) fn monitor(&self) -> MonitorJson {
        let status = self.live.monitor();

        MonitorJson {
            state: status.state,
            code: status.code,
            events: self.events.delivered(),
            last_event_ms: self.events.last_event_ms(),
        }
    }
}

/// The settings that may change while the process runs.
///
/// Everything else in `Settings` is read once at startup and cannot be honoured afterwards: only
/// the port is, because the listener is already bound. These are consulted again on every read, so
/// they live in atomics the monitor thread, the WFP worker and the request threads all see.
/// `settings` keeps the file-shaped copy, which is what gets written back to `config.toml`. The
/// protection switch is not in `Settings` at all: it is a pause for this run, and a start is
/// enforcing.
#[derive(Debug)]
pub struct Live {
    learning: AtomicBool,
    deny: AtomicBool,
    /// Whether the filters are in the store, which the tray and the page may pause.
    ///
    /// It is an atomic for the same reason the two above it are: the worker thread reads it on
    /// every piece of store work, so a value in `settings` would be the value the last run had.
    protection: AtomicBool,
    /// Which colour scheme the page should show, as the index of a [`Theme`] variant.
    ///
    /// A theme changes nothing the server itself does; it is published here so that a settings
    /// change is answered with the value the page will now render, rather than the one the file
    /// held when the process started.
    theme: AtomicU8,
    /// What the event subscription reported. A mutex rather than an atomic because the report
    /// carries the code that refused it, and only the monitor thread ever writes it.
    monitor: Mutex<MonitorStatus>,
    /// The addresses the names of the rules stood for when the filters were last built.
    ///
    /// Written by the worker that builds the store and read by the monitor, which has to know
    /// whether a destination a rule names by name is already spoken about. A mutex because the
    /// two threads are never the same one, and the value is a map rather than a word.
    answers: Mutex<crate::dns::Answers>,
}

impl Live {
    pub fn new(learning: bool, policy: Policy, theme: Theme) -> Self {
        Self {
            learning: AtomicBool::new(learning),
            deny: AtomicBool::new(policy == Policy::Deny),
            protection: AtomicBool::new(true),
            theme: AtomicU8::new(theme.index()),
            monitor: Mutex::new(MonitorStatus::default()),
            answers: Mutex::new(crate::dns::Answers::default()),
        }
    }

    pub fn learning(&self) -> bool {
        self.learning.load(Ordering::SeqCst)
    }

    /// The addresses the names of the rules stood for. Held as a guard so a reader cannot see a
    /// map that a rebuild is in the middle of replacing.
    pub fn answers(&self) -> std::sync::MutexGuard<'_, crate::dns::Answers> {
        self.answers.lock().expect("answers lock poisoned")
    }

    /// Publish the answers a rebuild worked from, so the monitor judges a name by the same
    /// addresses the store was built with.
    pub fn set_answers(&self, answers: crate::dns::Answers) {
        *self.answers.lock().expect("answers lock poisoned") = answers;
    }

    pub fn policy(&self) -> Policy {
        if self.deny.load(Ordering::SeqCst) {
            Policy::Deny
        } else {
            Policy::Allow
        }
    }

    /// Publish both at once, as a settings change writes them.
    pub fn set(&self, learning: bool, policy: Policy) {
        self.learning.store(learning, Ordering::SeqCst);
        self.deny.store(policy == Policy::Deny, Ordering::SeqCst);
    }

    /// Flip learning mode alone, which is what the tray's pause does, and report what it became.
    ///
    /// Unlike a settings change through the web this writes no file: a pause is meant to last for
    /// this run only, which is how the reference's pause button behaves too.
    pub fn toggle_learning(&self) -> bool {
        !self.learning.fetch_not(Ordering::SeqCst)
    }

    /// Whether our filters are in the store right now.
    ///
    /// Pausing protection is not a setting and reaches no file: it is the run-time switch the plan,
    /// section 1, promises, and a restart is enforcing again, which is what a firewall is for.
    pub fn protection(&self) -> bool {
        self.protection.load(Ordering::SeqCst)
    }

    /// Ask for protection on or off and report what it became.
    pub fn set_protection(&self, on: bool) -> bool {
        self.protection.store(on, Ordering::SeqCst);

        on
    }

    /// What the event subscription did about being asked to listen.
    pub fn monitor(&self) -> MonitorStatus {
        self.monitor
            .lock()
            .expect("monitor status lock poisoned")
            .clone()
    }

    /// Publish what the subscription did. The monitor thread is the only writer.
    pub fn set_monitor(&self, status: MonitorStatus) {
        *self.monitor.lock().expect("monitor status lock poisoned") = status;
    }

    /// Which colour scheme the page should show right now.
    pub fn theme(&self) -> Theme {
        Theme::from_index(self.theme.load(Ordering::SeqCst))
    }

    /// Publish a theme on its own, which is what a settings change that names only one does.
    pub fn set_theme(&self, theme: Theme) {
        self.theme.store(theme.index(), Ordering::SeqCst);
    }
}

impl Default for Live {
    /// The same theme and policy `config.toml` is written with, so a state built without a
    /// settings file cannot report values the tool would never have started with. Protection is
    /// on, because that is what a start means.
    fn default() -> Self {
        Self::new(false, Policy::default(), Theme::default())
    }
}

/// What the rebuild at startup made of the store, kept for the page and for MCP `status`.
///
/// The store holds the filters the previous run left behind; the rules file describes the filters
/// the user wants. When the two counts differ, something changed while the tool was not running,
/// which plan section 6 asks to surface rather than only log. A refused store keeps its own
/// counts at zero, because nothing was read and nothing was written either.
#[derive(Debug, Clone, Serialize)]
pub struct Startup {
    /// Whether a startup rebuild was attempted at all. A state built in a test never touches the
    /// store, and its banner must not claim a diff the process never measured.
    pub(super) measured: bool,
    /// Whether the store took the rebuild.
    pub(super) ok: bool,
    /// Our filters the previous run left in the store.
    pub(super) removed: usize,
    /// Filters the rules file describes.
    pub(super) installed: usize,
    /// Rules the file gained while the tool was closed. Names only, and only as far as the store
    /// can tell: an edit that keeps a rule's name, its action and its filter count leaves the
    /// same trace as no edit at all.
    pub(super) added: Vec<String>,
    /// Rules whose name stayed and whose action or filter count did not.
    pub(super) changed: Vec<String>,
    /// Rules the file lost while the tool was closed.
    pub(super) gone: Vec<String>,
    /// Why the store refused, when it did.
    pub(super) reason: Option<String>,
    /// Whether the page has anything to say: the counts differ, or a name is in one of the three
    /// lists. A first run, where the store was empty, is news once; an unchanged restart is not.
    pub(super) differs: bool,
}

impl Startup {
    /// The answer a startup rebuild made.
    pub(crate) fn from_outcome(outcome: &StoreOutcome) -> Self {
        Self {
            measured: true,
            ok: outcome.ok,
            removed: outcome.removed,
            installed: outcome.installed,
            added: outcome.diff.added.clone(),
            changed: outcome.diff.changed.clone(),
            gone: outcome.diff.gone.clone(),
            reason: outcome.reason.clone(),
            differs: outcome.ok
                && (outcome.removed != outcome.installed || !outcome.diff.is_empty()),
        }
    }

    /// The rebuild never reached the engine, so the counts stay at zero and the reason stands in
    /// for them.
    pub(crate) fn refused(reason: String) -> Self {
        Self {
            measured: true,
            ok: false,
            removed: 0,
            installed: 0,
            added: Vec::new(),
            changed: Vec::new(),
            gone: Vec::new(),
            reason: Some(reason),
            differs: false,
        }
    }

    /// A state that did not come through a startup rebuild, which is every state a test builds.
    #[cfg(test)]
    pub(super) fn unmeasured() -> Self {
        Self {
            measured: false,
            ok: false,
            removed: 0,
            installed: 0,
            added: Vec::new(),
            changed: Vec::new(),
            gone: Vec::new(),
            reason: None,
            differs: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::worker::{InventorySummary, RuleDiff, StoreOutcome};
    use super::*;

    /// The tray's pause flips the flag and reports the new value, leaving the policy alone.
    #[test]
    fn toggling_learning_reports_what_it_became_and_keeps_the_policy() {
        let live = Live::new(true, Policy::Deny, Theme::Dark);

        assert!(!live.toggle_learning());
        assert_eq!(live.policy(), Policy::Deny);
        assert!(live.toggle_learning());
    }

    /// The report of the startup rebuild is only worth a line when the store held something other
    /// than what the rules describe. A refused store has no counts to compare, and a first run with
    /// an empty store and an unchanged restart are both cases where nothing went wrong.
    #[test]
    fn a_startup_rebuild_claims_a_diff_only_when_the_counts_differ() {
        let changed = StoreOutcome {
            ok: true,
            removed: 3,
            installed: 5,
            diff: RuleDiff::default(),
            inventory: InventorySummary::default(),
            reason: None,
        };

        assert!(Startup::from_outcome(&changed).differs);

        let same = StoreOutcome {
            installed: 3,
            ..changed.clone()
        };

        assert!(
            !Startup::from_outcome(&same).differs,
            "an unchanged restart is not news",
        );

        let refused = StoreOutcome::refused(InventorySummary::default(), "access denied");

        assert!(
            !Startup::from_outcome(&refused).differs,
            "a refused store has nothing counted",
        );
        assert!(
            !Startup::unmeasured().differs,
            "a state that never rebuilt must say nothing",
        );
    }

    /// Equal counts are no longer the whole news. A rule that flipped its action while the tool
    /// was closed leaves the counts alone, and only the named diff tells the user the store was
    /// rebuilt from something different than they left.
    #[test]
    fn a_startup_rebuild_with_equal_counts_but_a_named_change_is_news_too() {
        let outcome = StoreOutcome {
            ok: true,
            removed: 4,
            installed: 4,
            diff: RuleDiff {
                added: Vec::new(),
                changed: vec!["web server".to_owned()],
                gone: Vec::new(),
            },
            inventory: InventorySummary::default(),
            reason: None,
        };

        let startup = Startup::from_outcome(&outcome);

        assert!(
            startup.differs,
            "a named change is news without a count change"
        );
        assert_eq!(startup.changed, ["web server".to_owned()]);
    }
}
