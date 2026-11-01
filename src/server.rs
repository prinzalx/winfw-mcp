//! The web server: a tiny HTTP/1.1 implementation on top of `std`.
//!
//! PLAN.md section 6 suggested axum and tokio, to be confirmed at implementation time. The
//! confirmation is that they are not needed: every interesting call below ends in a blocking WFP
//! call, so an async runtime would only move the blocking into `spawn_blocking`. A thread per
//! connection with the standard library keeps the binary small, starts instantly, and gives
//! milestone 5 (SSE) exactly the long-lived connection it needs.
//!
//! `winfw-core` rule from PLAN.md section 6: this module is a transport. It reads and writes the
//! files and forwards store work to the WFP worker, but it decides nothing about the firewall.
//!
//! ## Routes
//!
//! | method | path | purpose |
//! |---|---|---|
//! | GET | `/` | the single-page UI |
//! | GET | `/api/state` | settings, rules, store summary, recent events |
//! | GET | `/api/events` | the event log as a server-sent event stream |
//! | GET | `/api/health` | liveness, no state involved |
//! | POST | `/api/rules` | replace the rules, write the file, rebuild the store |
//! | POST | `/api/detected` | turn a detected application into a rule and rebuild the store |
//! | POST | `/api/detected/dismiss` | drop a detected application without allowing it |
//! | POST | `/api/clear` | remove our filters from the store |
//! | POST | `/api/shutdown` | stop the server, which ends the process |
//! | POST | `/api/export` | copy rules, config, the Detected list and the profiles into `export\` |
//! | POST | `/api/rules/share` | one rule as a Base64 string, for copy and paste |
//! | POST | `/api/rules/import` | append the rule a Base64 string carries |
//! | POST | `/api/rules/replace` | replace the rules with a whole file's text, the restore half of an export |
//! | POST | `/api/profiles/create` | create a profile from the current rules and switch to it |
//! | POST | `/api/profiles/rename` | rename a profile, keeping it live when it was live |
//! | POST | `/api/profiles/delete` | remove a profile, falling back to the default rules |
//! | POST | `/mcp` | JSON-RPC 2.0 for an MCP client: see `crate::mcp` |
//!
//! Every route answers to a loopback `Host` header, and every writing one to the session token as
//! well, which is what keeps a web page that is not ours from editing the firewall. The MCP
//! endpoint is the exception on purpose: it has no token and no writing tools. See
//! `docs/10-security-model.md`.
//!
//! ## Threading
//!
//! A WFP transaction belongs to a thread rather than to a handle (see `wfp::Engine::transaction`),
//! so exactly one thread owns the engine handle: the WFP worker. Request threads hand their work
//! over a channel and wait for the reply, which is what makes the arrangement safe rather than
//! merely convenient.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::{Policy, Settings, Theme};
use crate::export::{self, Area};
use crate::learn::{Detected, Detector};
use crate::mcp;
use crate::monitor::{EventLog, MonitorStatus, NetEvent};
use crate::paths::DataPaths;
use crate::rules::{Action, Cidr, Fingerprint, Rule, RuleFile, validate_pattern, write_stamp};

/// The page served at `/`, embedded so the binary stays a single file.
const INDEX_HTML: &str = include_str!("../web/index.html");

/// The icon for the browser tab: the same file `build.rs` compiles into the executable's resources,
/// so the tray, the shell and the tab all show one logo from one source.
const FAVICON_ICO: &[u8] = include_bytes!("../assets/winfw-mcp.ico");

/// How many consecutive ports `Server::bind` walks through before it gives up on a busy
/// configured port.
const PORT_ATTEMPTS: u16 = 8;

/// How long the accept loop blocks before it checks whether the process is shutting down.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// How long the accept loop waits after a stop request before it lets the process end.
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

/// How often an SSE connection looks at the event log. A poll, not a wake-up: the callbacks come
/// from RPC threads and the log is the only shared state, which keeps the locking trivial.
const EVENT_POLL: Duration = Duration::from_millis(500);

/// How many recent events `/api/state` carries, enough for the panel to render without a second
/// request.
const STATE_EVENTS: usize = 50;

/// How many detected applications `/api/state` carries. Pi-hole-like: a short list of what needs a
/// decision, not the whole history.
const STATE_DETECTED: usize = 20;

/// Everything a request handler may touch.
///
/// The rules are the in-memory copy that the request handlers keep authoritative: a change is
/// applied to this value, written to disk, and only then pushed to the store, which is the order
/// PLAN.md section 2 asks for.
pub struct AppState {
    paths: DataPaths,
    settings: Settings,
    rules: Arc<Mutex<RuleFile>>,
    /// The applications learning mode collected, waiting for a decision.
    detector: Arc<Detector>,
    /// `learn_mode` and `default_policy` as they may change while the process runs. The monitor
    /// thread reads the same pair, which is why they are atomics rather than fields of
    /// `settings`.
    live: Arc<Live>,
    /// The live connection feed, filled by the monitor thread.
    events: Arc<EventLog>,
    /// The file the active rules are read from and written back to: `rules.toml` for the default
    /// profile, `profiles\<name>.toml` otherwise. A switch changes it.
    active_file: Mutex<PathBuf>,
    /// The active profile name, or empty for `rules.toml` itself.
    active_name: Mutex<String>,
    /// Kept set while the process should keep accepting connections. `POST /api/shutdown` and the
    /// tray's `Quit` both clear it, which is the only way either of them has of ending a process
    /// whose main thread is parked in the accept loop.
    running: Arc<AtomicBool>,
    /// What the rebuild at startup made of the store. Never changes afterwards: it is the record of
    /// the difference the process found between the store and the rules file.
    startup: Startup,
    /// The session token a writing request has to carry (PLAN.md section 11).
    ///
    /// It lives here and nowhere else: no file, no log, no answer on `/mcp`. The browser learns it
    /// from the URL the tray opened, or from the state body when a human typed the address.
    token: String,
    /// The contents of the rules file the tool wrote last, as a fingerprint.
    ///
    /// At startup this is the stamp the previous run left behind rather than the file on disk,
    /// which is exactly what makes a hand edit made while the tool was closed show up as a
    /// difference. Writing the file replaces the record, so the notice disappears with the edit
    /// that caused it and needs no bookkeeping of its own.
    rules_written: Mutex<Option<Fingerprint>>,
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
    ) -> Self {
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
    fn request_stop(&self) -> bool {
        self.running
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// The file the active rules live in. Read on every save, because a switch changes it.
    fn rules_path(&self) -> PathBuf {
        self.active_file
            .lock()
            .expect("rules path lock poisoned")
            .clone()
    }

    /// The active profile name, or empty for `rules.toml`.
    fn active_name(&self) -> String {
        self.active_name
            .lock()
            .expect("active name lock poisoned")
            .clone()
    }

    /// The authoritative `learn_mode`: what the last `POST /api/settings` asked for, rather than
    /// what `config.toml` said at startup.
    fn learn_mode(&self) -> bool {
        self.live.learning()
    }

    /// The authoritative `default_policy`, with the same caveat.
    fn policy(&self) -> Policy {
        self.live.policy()
    }

    /// Record that the rules file on disk is now the tool's own work.
    ///
    /// Called after every write the tool does, so the next comparison measures the difference
    /// against what we wrote rather than against whatever a reader left behind. Writing the stamp
    /// is best effort: a stamp that cannot be written costs a lost notice, not a lost rule.
    fn note_rules_written(&self) {
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

    /// Whether the rules file on disk is not the one the tool wrote.
    ///
    /// A file that has gone away counts as changed, because the rules the page shows are the ones in
    /// memory while the file that describes them is missing.
    fn rules_changed_outside(&self) -> bool {
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
    fn monitor(&self) -> MonitorJson {
        let status = self.live.monitor();

        MonitorJson {
            state: status.state,
            code: status.code,
            events: self.events.delivered(),
        }
    }
}

/// The three settings that may change while the process runs.
///
/// Everything else in `Settings` is read once at startup and cannot be honoured afterwards: the
/// port is already bound and the log level is the filter `tracing` installed. The other three are
/// consulted again on every read, so they live in atomics the monitor thread and the request
/// threads both see. `settings` keeps the file-shaped copy, which is what gets written back to
/// `config.toml`.
#[derive(Debug)]
pub struct Live {
    learning: AtomicBool,
    deny: AtomicBool,
    /// Which colour scheme the page should show, as the index of a [`Theme`] variant.
    ///
    /// A theme changes nothing the server itself does; it is published here so that a settings
    /// change is answered with the value the page will now render, rather than the one the file
    /// held when the process started.
    theme: AtomicU8,
    /// What the event subscription reported. A mutex rather than an atomic because the report
    /// carries the code that refused it, and only the monitor thread ever writes it.
    monitor: Mutex<MonitorStatus>,
}

impl Live {
    pub fn new(learning: bool, policy: Policy, theme: Theme) -> Self {
        Self {
            learning: AtomicBool::new(learning),
            deny: AtomicBool::new(policy == Policy::Deny),
            theme: AtomicU8::new(theme.index()),
            monitor: Mutex::new(MonitorStatus::default()),
        }
    }

    pub fn learning(&self) -> bool {
        self.learning.load(Ordering::SeqCst)
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
    /// The same theme `config.toml` is written with, so a state built without a settings file
    /// cannot report a theme the tool would never have started with.
    fn default() -> Self {
        Self::new(false, Policy::default(), Theme::default())
    }
}

/// The request headers the guards read.
///
/// Only these four matter to this server, and they are matched case-insensitively because a guard
/// that is not would be a guard a client could confuse by capitalising differently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    host: Option<String>,
    origin: Option<String>,
    content_type: Option<String>,
    token: Option<String>,
}

impl Headers {
    /// Pick the four interesting fields out of the lines the transport read, in order.
    ///
    /// A field sent twice keeps the first value: that is what a browser sends, and it is the
    /// reading least likely to turn a confused proxy into a surprise.
    fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut headers = Self::default();

        for (name, value) in pairs {
            let value = value.trim().to_owned();

            match name.to_ascii_lowercase().as_str() {
                "host" if headers.host.is_none() => headers.host = Some(value),
                "origin" if headers.origin.is_none() => headers.origin = Some(value),
                "content-type" if headers.content_type.is_none() => {
                    headers.content_type = Some(value);
                }
                "x-winfw-token" if headers.token.is_none() => headers.token = Some(value),
                _ => {}
            }
        }

        headers
    }
}

/// A parsed request. Only the parts a local, single-user server needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
    headers: Headers,
}

impl Request {
    #[allow(dead_code)] // the tests route a request directly; the socket path uses `from_parts`
    pub fn new(method: &str, path: &str, body: Vec<u8>) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body,
            headers: Headers::default(),
        }
    }

    /// A request as the transport read it, headers included.
    pub fn with_headers(method: &str, path: &str, body: Vec<u8>, headers: Headers) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body,
            headers,
        }
    }
}

/// A response ready to be written on the wire.
pub struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn text(status: u16, body: impl Into<String>) -> Self {
        let body = body.into();

        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    fn json<T: Serialize>(status: u16, value: &T) -> Result<Self> {
        Ok(Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value)?,
        })
    }

    /// The status line plus framing, for the tests and for `write_all`.
    fn header(&self) -> String {
        format!(
            "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n",
            status_text(self.status),
            self.content_type,
            self.body.len(),
        )
    }
}

/// What the WFP worker does on behalf of a request thread.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum StoreWork {
    /// Rebuild the filters from these rules, expanding wildcards against the applications the
    /// detector has seen, under the given default policy.
    Apply {
        rules: RuleFile,
        known: Vec<String>,
        policy: crate::config::Policy,
    },
    /// Take our filters out of the store.
    Clear,
    /// Report what the store says without changing it.
    Inventory,
}

/// The answer a store operation made.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct StoreOutcome {
    /// `None` when the store refused us: not elevated, or no engine.
    ok: bool,
    removed: usize,
    installed: usize,
    /// Providers, sublayers and filters we could read, or why we could not.
    inventory: InventorySummary,
    reason: Option<String>,
}

impl StoreOutcome {
    /// Nothing reached the engine, so nothing was installed or removed either.
    fn refused(inventory: InventorySummary, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            removed: 0,
            installed: 0,
            inventory,
            reason: Some(reason.into()),
        }
    }

    /// One line about what the store did, for a log message from outside this module.
    pub(crate) fn describe(&self) -> String {
        if self.ok {
            format!("removed {}, installed {}", self.removed, self.installed)
        } else {
            format!(
                "refused: {}",
                self.reason
                    .clone()
                    .unwrap_or_else(|| "no reason given".to_owned())
            )
        }
    }
}

/// What the rebuild at startup made of the store, kept for the page and for MCP `status`.
///
/// The store holds the filters the previous run left behind; the rules file describes the filters
/// the user wants. When the two counts differ, something changed while the tool was not running,
/// which PLAN.md section 6 asks to surface rather than only log. A refused store keeps its own
/// counts at zero, because nothing was read and nothing was written either.
#[derive(Debug, Clone, Serialize)]
pub struct Startup {
    /// Whether a startup rebuild was attempted at all. A state built in a test never touches the
    /// store, and its banner must not claim a diff the process never measured.
    measured: bool,
    /// Whether the store took the rebuild.
    ok: bool,
    /// Our filters the previous run left in the store.
    removed: usize,
    /// Filters the rules file describes.
    installed: usize,
    /// Why the store refused, when it did.
    reason: Option<String>,
    /// Whether the page has anything to say: the two counts differ. A first run, where the store
    /// was empty, is news once; an unchanged restart is not.
    differs: bool,
}

impl Startup {
    /// The answer a startup rebuild made.
    pub(crate) fn from_outcome(outcome: &StoreOutcome) -> Self {
        Self {
            measured: true,
            ok: outcome.ok,
            removed: outcome.removed,
            installed: outcome.installed,
            reason: outcome.reason.clone(),
            differs: outcome.ok && outcome.removed != outcome.installed,
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
            reason: Some(reason),
            differs: false,
        }
    }

    /// A state that did not come through a startup rebuild, which is every state a test builds.
    #[cfg(test)]
    fn unmeasured() -> Self {
        Self {
            measured: false,
            ok: false,
            removed: 0,
            installed: 0,
            reason: None,
            differs: false,
        }
    }
}

/// The readable part of the store, summarized for the UI.
#[derive(Debug, Clone, Default, Serialize)]
struct InventorySummary {
    providers: Option<usize>,
    sublayers: Option<usize>,
    filters: Option<usize>,
}

/// One unit of work plus the channel its answer goes back on.
pub(crate) type WorkItem = (StoreWork, SyncSender<Result<StoreOutcome>>);

/// The single thread that owns the engine handle.
pub struct WfpWorker {
    sender: Option<SyncSender<WorkItem>>,
    join: Option<JoinHandle<()>>,
    /// The filter-id to rule-name table, republished on every rebuild so the monitor can name the
    /// rule an event blames. Owned here because this thread is the only one that changes it.
    owners: Arc<Mutex<crate::monitor::Attribution>>,
}

impl WfpWorker {
    /// Start the worker. On non-Windows builds the worker still runs, so the server behaves the
    /// same and reports the store as unavailable.
    pub fn start() -> Self {
        // A bounded queue of one is deliberate: a second change waits for the first to be carried
        // out, which is also what keeps two full filter rebuilds from racing.
        let (sender, receiver) = sync_channel::<WorkItem>(1);

        // The attribution table the monitor reads. The worker republishes it after each rebuild,
        // so the table always describes the store that is in there right now.
        let owners = Arc::new(Mutex::new(crate::monitor::Attribution::new()));
        let shared_owners = Arc::clone(&owners);

        let join = thread::spawn(move || {
            // On non-Windows the table is never read but still has to stay alive with the worker.
            #[cfg(not(windows))]
            let _ = &shared_owners;

            #[cfg(windows)]
            let engine = match crate::wfp::Engine::open_retrying() {
                Ok(engine) => Some(engine),
                Err(error) => {
                    warn!(reason = %format!("{error:#}"), "could not open the WFP engine");
                    None
                }
            };

            while let Ok((work, reply)) = receiver.recv() {
                let outcome = handle_work(
                    #[cfg(windows)]
                    engine.as_ref(),
                    #[cfg(windows)]
                    &shared_owners,
                    work,
                );

                // A closed reply channel only means the request thread gave up.
                let _ = reply.send(outcome);
            }
        });

        Self {
            sender: Some(sender),
            join: Some(join),
            owners,
        }
    }

    /// A second handle on the request queue, for a caller that has work but no interest in the
    /// answer. The monitor uses it to rebuild the wildcard filters when an application turns up
    /// that no filter knows yet.
    pub fn handle(&self) -> Option<SyncSender<WorkItem>> {
        self.sender.clone()
    }

    /// The live filter-id to rule-name table. Cloning the `Arc` hands the monitor a view of the
    /// store that the worker republishes on every rebuild.
    pub fn owners(&self) -> Arc<Mutex<crate::monitor::Attribution>> {
        Arc::clone(&self.owners)
    }

    /// Hand one unit of work to the worker and wait for the answer.
    ///
    /// Blocking is deliberate: the caller is a request thread of its own, and a firewall change
    /// that has not been answered yet is not a change the UI should report as done.
    pub fn ask(&self, work: StoreWork) -> Result<StoreOutcome> {
        // One slot is enough: exactly one answer comes back for exactly one request.
        let (reply_sender, reply_receiver) = sync_channel(1);

        self.sender
            .as_ref()
            .context("WFP worker is gone")?
            .send((work, reply_sender))
            .context("WFP worker is gone")?;

        match reply_receiver.recv_timeout(Duration::from_secs(30)) {
            Ok(outcome) => outcome,
            Err(RecvTimeoutError::Timeout) => bail!("WFP did not answer within 30 s"),
            Err(RecvTimeoutError::Disconnected) => bail!("WFP worker died while answering"),
        }
    }
}

impl Drop for WfpWorker {
    fn drop(&mut self) {
        // Dropping the last sender ends the worker's `recv` loop, and the engine handle goes with
        // it: the worker thread is the thread that opened it.
        drop(self.sender.take());

        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Carry out one unit of store work.
///
/// Access denied is the interesting case: it is a supported degraded state, reported as
/// `ok: false` with the reason, and the UI shows a banner instead of an empty list. Any other
/// failure is a real one and reaches the browser the same way, but is logged at warn level.
#[cfg(windows)]
fn handle_work(
    #[cfg(windows)] engine: Option<&crate::wfp::Engine>,
    #[cfg(windows)] owners: &Mutex<crate::monitor::Attribution>,
    work: StoreWork,
) -> Result<StoreOutcome> {
    #[cfg(windows)]
    let Some(engine) = engine else {
        return Ok(StoreOutcome::refused(
            InventorySummary::default(),
            "no engine handle",
        ));
    };

    let (_removed, _installed, result) = match work {
        StoreWork::Apply {
            rules,
            known,
            policy,
        } => {
            let result = engine.apply(&rules, &known, policy).map(|applied| {
                // The rebuild wrote the whole store, so its table replaces ours wholesale rather
                // than being merged; a filter the rebuild dropped is no longer in the store.
                *owners.lock().expect("owners lock poisoned") = applied.owners;

                (applied.removed, applied.installed)
            });

            (0, 0, result)
        }
        StoreWork::Clear => {
            let result = engine.clear().map(|removed| {
                owners.lock().expect("owners lock poisoned").clear();

                (removed, 0)
            });

            (0, 0, result)
        }
        StoreWork::Inventory => (0, 0, Ok((0, 0))),
    };

    // Reading the counts after the change is what lets one response both confirm the operation
    // and refresh the banner.
    let raw = engine.inventory();
    let inventory = summary(&raw);
    let unreadable = inventory.providers.is_none()
        && inventory.sublayers.is_none()
        && inventory.filters.is_none();

    match result {
        // An operation WFP accepted is still not a store we could read. Saying so keeps the banner
        // honest instead of celebrating counts of nothing.
        Ok((removed, installed)) if unreadable => Ok(StoreOutcome {
            ok: false,
            removed,
            installed,
            inventory,
            reason: first_read_error(&raw),
        }),
        Ok((removed, installed)) => Ok(StoreOutcome {
            ok: true,
            removed,
            installed,
            inventory,
            reason: None,
        }),
        Err(error) => {
            let reason = format!("{error:#}");

            if !reason.contains("0x00000005") {
                warn!(reason, "WFP operation failed");
            }

            Ok(StoreOutcome {
                ok: false,
                removed: 0,
                installed: 0,
                inventory,
                reason: Some(reason),
            })
        }
    }
}

/// The first reason the store gave for refusing a read, which is the one worth showing.
#[cfg(windows)]
fn first_read_error(inventory: &crate::wfp::Inventory) -> Option<String> {
    [
        inventory.providers.as_ref().err(),
        inventory.sublayers.as_ref().err(),
        inventory.filters.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    .map(|error| format!("{error:#}"))
    .next()
}

/// Count what the store let us read. A class we were refused stays `None`.
#[cfg(windows)]
fn summary(inventory: &crate::wfp::Inventory) -> InventorySummary {
    InventorySummary {
        providers: inventory.providers.as_ref().ok().map(Vec::len),
        sublayers: inventory.sublayers.as_ref().ok().map(Vec::len),
        filters: inventory.filters.as_ref().ok().map(Vec::len),
    }
}

/// The non-Windows answer exists so the server can be exercised by a doc build.
#[cfg(not(windows))]
fn handle_work(work: StoreWork) -> Result<StoreOutcome> {
    Ok(StoreOutcome {
        ok: false,
        removed: 0,
        installed: 0,
        inventory: InventorySummary::default(),
        reason: Some(format!("no WFP on this platform, asked for {work:?}")),
    })
}

/// The server itself: a listener, the shared state and the worker.
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    state: Arc<AppState>,
    worker: Arc<WFPWorkerAlias>,
}

/// Name chosen so the call sites read as what they are.
type WFPWorkerAlias = WfpWorker;

impl Server {
    /// Bind `127.0.0.1:{port}`. Port 0 is allowed and resolves to an ephemeral port, which is what
    /// the tests use.
    pub fn bind(port: u16, state: AppState, worker: Arc<WfpWorker>) -> Result<Self> {
        // A conflict on the configured port must not kill the tray app (PLAN.md section 9), so a
        // busy port is answered by the next one. Port 0 asks the OS for an ephemeral port and
        // cannot meaningfully fall forward.
        let attempts = if port == 0 { 1 } else { PORT_ATTEMPTS };

        let mut failures = Vec::new();

        for offset in 0..attempts {
            let Some(candidate) = port.checked_add(offset) else {
                break;
            };

            let addr = SocketAddr::from(([127, 0, 0, 1], candidate));

            let listener = match TcpListener::bind(addr) {
                Ok(listener) => listener,
                Err(error) => {
                    failures.push(format!("{addr}: {error}"));

                    continue;
                }
            };

            if offset > 0 {
                warn!(
                    configured = port,
                    actual = candidate,
                    "configured port was busy, listened on the next free one instead"
                );
            }

            listener
                .set_nonblocking(true)
                .context("could not switch the listener to non-blocking")?;

            let bound = listener.local_addr().context("local_addr failed")?;

            return Ok(Self {
                listener,
                addr: bound,
                state: Arc::new(state),
                worker,
            });
        }

        bail!(
            "bind {port} failed: {}",
            if failures.is_empty() {
                "no port in range".to_owned()
            } else {
                failures.join(", ")
            }
        )
    }

    /// The address we actually listen on, useful when port 0 was requested.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Accept and serve until the process is stopped.
    ///
    /// Each connection gets its own thread, so a browser that keeps a connection open for SSE
    /// cannot block the request behind it.
    pub fn serve(&self) -> Result<()> {
        info!(addr = %self.addr, "listening");

        while self.state.running.load(Ordering::SeqCst) {
            match self.listener.accept() {
                Ok((stream, peer)) => {
                    let state = Arc::clone(&self.state);
                    let worker = Arc::clone(&self.worker);

                    thread::spawn(move || {
                        if let Err(error) = handle_connection(stream, state, worker) {
                            debug!(reason = %format!("{error:#}"), "connection ended badly");
                        }

                        debug!(%peer, "connection closed");
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) => return Err(error).context("accept failed"),
            }
        }

        info!(addr = %self.addr, "accept loop stopped");

        // The request thread that asked to stop is still writing its response when the loop notices,
        // and the process ends as soon as this function returns. Without the pause the client that
        // asked would see the connection cut instead of the reply it was waiting for.
        thread::sleep(SHUTDOWN_GRACE);

        Ok(())
    }

    /// Answer exactly one connection. Intended for tests, where an infinite loop would hang.
    #[cfg(test)]
    pub fn serve_once(&self) -> Result<()> {
        loop {
            match self.listener.accept() {
                Ok((stream, _peer)) => {
                    return handle_connection(
                        stream,
                        Arc::clone(&self.state),
                        Arc::clone(&self.worker),
                    );
                }
                // The listener is non-blocking, so the connection may not have arrived yet.
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL);
                }
                Err(error) => return Err(error).context("accept failed"),
            }
        }
    }

    /// Route a request. Public so the routing can be tested without a socket.
    pub fn route(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", "/") => Ok(Response {
                status: 200,
                content_type: "text/html; charset=utf-8",
                body: INDEX_HTML.as_bytes().to_vec(),
            }),
            ("GET", "/favicon.ico") => Ok(Response {
                status: 200,
                content_type: "image/x-icon",
                body: FAVICON_ICO.to_vec(),
            }),
            ("GET", "/api/state") => {
                let outcome = worker.ask(StoreWork::Inventory)?;

                let state_json = StateJson::new(state, &outcome);

                Response::json(200, &state_json)
            }
            ("POST", "/api/settings") => {
                let edit: SettingsEdit = parse_or_default(&request.body)?;

                let outcome = apply_settings(state, worker, edit)?;

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/rules") => {
                let rules: RuleFile = parse_body(&request.body, "a rule file object")?;

                for rule in &rules.rule {
                    validate_pattern(&rule.pattern)
                        .with_context(|| format!("rule '{}'", rule.name))?;
                }

                // File first, then store: a store that refuses us must not lose the user's edit.
                {
                    let mut current = state.rules.lock().expect("rules lock poisoned");
                    *current = rules.clone();
                }

                state
                    .rules
                    .lock()
                    .expect("rules lock poisoned")
                    .save(&state.rules_path())
                    .context("write the rules file")?;

                // The file on disk is the tool's own work again, which is what the notice on the
                // page compares against.
                state.note_rules_written();

                let outcome = worker.ask(StoreWork::Apply {
                    rules,
                    known: state.detector.apps(),
                    policy: state.policy(),
                })?;
                let state_json = StateJson::new(state, &outcome);

                Response::json(200, &state_json)
            }
            ("POST", "/api/detected") => {
                let decision: Decision = parse_body(&request.body, "a detected decision object")?;

                let pattern = decision.pattern.unwrap_or_else(|| {
                    // No edited pattern given: the drive form of what the firewall reported.
                    crate::device::to_dos_path(&decision.app)
                });

                validate_pattern(&pattern)?;

                let name = match decision.name {
                    Some(name) if !name.trim().is_empty() => name,
                    _ => decision
                        .app
                        .rsplit(['\\', '/'])
                        .next()
                        .unwrap_or("detected")
                        .to_owned(),
                };

                // A detected application becomes an ordinary rule, so nothing downstream has to
                // know where a rule came from.
                let applied = {
                    let mut current = state.rules.lock().expect("rules lock poisoned");

                    let mut rule = Rule::plain(name, decision.action, pattern);

                    // A destination entry is decided by a rule that reaches that address and no
                    // other, which is the whole point of asking about it.
                    if let Some(text) = decision.remote.as_deref() {
                        rule.remote = Some(
                            text.parse::<Cidr>()
                                .map_err(anyhow::Error::msg)
                                .with_context(|| format!("'{text}' is not an address"))?,
                        );
                    }

                    current.rule.push(rule);

                    current
                        .save(&state.rules_path())
                        .context("write the rules file")?;
                    state.note_rules_written();
                    current.clone()
                };

                let outcome = worker.ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
                    policy: state.policy(),
                })?;

                // Only after the store accepted the rule: a refused write leaves the entry on the
                // list so the user can try again.
                if outcome.ok {
                    state
                        .detector
                        .dismiss(&decision.app, decision.remote.as_deref())?;
                }

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/detected/dismiss") => {
                let body: Dismissal = parse_body(&request.body, "a dismissal object")?;

                let removed = state.detector.dismiss(&body.app, body.remote.as_deref())?;

                Response::json(200, &serde_json::json!({ "removed": removed }))
            }
            // `/api/events` is answered by `stream_events`, because a response that never ends
            // cannot be a buffered body.
            // Stopping is a flag rather than a signal: the main thread is parked in `accept`, and
            // only the accept loop itself can leave it.
            ("POST", "/api/shutdown") => {
                let stopping = state.request_stop();

                info!(first = stopping, "shutdown requested");

                Response::json(200, &serde_json::json!({ "stopping": stopping }))
            }
            ("GET", "/api/health") => Ok(Response::text(200, "ok")),
            ("POST", "/api/clear") => {
                let outcome = worker.ask(StoreWork::Clear)?;

                Response::json(200, &outcome)
            }
            ("POST", "/api/export") => {
                // An empty body exports everything, which is what the button in the UI sends.
                let body: Backup = parse_or_default(&request.body)?;
                let report = export::run(&state.paths, body.area.unwrap_or(Area::All))?;

                Response::json(200, &report)
            }
            ("POST", "/api/rules/share") => {
                let body: ShareIndex = parse_body(&request.body, "a rule index")?;
                let rules = state.rules.lock().expect("rules lock poisoned").clone();

                let Some(rule) = rules.rule.get(body.index) else {
                    bail!("there is no rule at index {}", body.index);
                };

                Ok(Response::text(200, export::encode(rule)?))
            }
            ("POST", "/api/rules/import") => {
                let body: Share = parse_body(&request.body, "a share string")?;
                let incoming = export::decode(&body.share)?;

                validate_pattern(&incoming.pattern)?;

                let applied = {
                    let mut current = state.rules.lock().expect("rules lock poisoned");

                    // Appended rather than merged: an import must never replace something the user
                    // already has, whatever the Base64 string came from.
                    current.rule.push(incoming);
                    current
                        .save(&state.rules_path())
                        .context("write the rules file")?;
                    state.note_rules_written();
                    current.clone()
                };

                let outcome = worker.ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
                    policy: state.policy(),
                })?;

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/rules/replace") => {
                let body: Import = parse_body(&request.body, "the rules file text")?;
                let incoming = RuleFile::from_text(&body.text)?;

                // Every pattern goes through the check a single rule goes through, because a file
                // that was edited by hand after an export has not been read by anything since.
                for rule in &incoming.rule {
                    validate_pattern(&rule.pattern)?;
                }

                let applied = {
                    let mut current = state.rules.lock().expect("rules lock poisoned");

                    // The write keeps the generation it replaces, so a restore of the wrong file
                    // is one more restore away from being undone.
                    incoming
                        .save(&state.rules_path())
                        .context("write the rules file")?;
                    state.note_rules_written();
                    *current = incoming;
                    current.clone()
                };

                let outcome = worker.ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
                    policy: state.policy(),
                })?;

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("GET", "/api/profiles") => {
                let body = serde_json::json!({
                    "active": state.active_name(),
                    "names": crate::rules::list_names(&state.paths.profiles),
                });

                Response::json(200, &body)
            }
            ("POST", "/api/profiles/create") => {
                let body: ProfileSwitch = parse_or_default(&request.body)?;
                let outcome = create_profile(state, worker, &body.name)?;

                // A profile operation can move which file is the active one, and the notice on the
                // page has to compare against the file that is active afterwards.
                state.note_rules_written();

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/profiles/delete") => {
                let body: ProfileSwitch = parse_or_default(&request.body)?;
                let outcome = delete_profile(state, worker, &body.name)?;

                // A profile operation can move which file is the active one, and the notice on the
                // page has to compare against the file that is active afterwards.
                state.note_rules_written();

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/profiles/rename") => {
                let body: ProfileRename = parse_or_default(&request.body)?;
                let outcome = rename_profile(state, worker, &body.name, &body.new_name)?;

                // A profile operation can move which file is the active one, and the notice on the
                // page has to compare against the file that is active afterwards.
                state.note_rules_written();

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/profiles/switch") => {
                let body: ProfileSwitch = parse_or_default(&request.body)?;
                let outcome = switch_profile(state, worker, &body.name)?;

                // A profile operation can move which file is the active one, and the notice on the
                // page has to compare against the file that is active afterwards.
                state.note_rules_written();

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/mcp") => mcp_endpoint(state, worker, request),
            _ => Ok(Response::text(404, "not found")),
        }
    }
}

/// Answer one JSON-RPC 2.0 call for an MCP client.
///
/// Everything the endpoint knows is in `state`, so the transport stays thin: it decodes the call,
/// asks the same core the web UI asks, and puts the answer into the shape MCP clients read. A
/// failure to speak JSON-RPC is still answered with HTTP 200, because in JSON-RPC the failure is
/// part of the conversation rather than a delivery problem.
fn mcp_endpoint(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let call = match mcp::parse(&request.body) {
        Ok(call) => call,
        Err(reply) => return Response::json(200, &reply),
    };

    let id = call.id.clone();

    // A notification wants no answer, but HTTP needs a body, so it gets an empty result. Both the
    // missing id and the `notifications/` prefix mean the same thing here.
    if call.is_notification() || call.method.starts_with("notifications/") {
        return Response::json(200, &mcp::Response::acknowledged(id));
    }

    let reply = match call.method.as_str() {
        "initialize" => serde_json::json!({
            "protocolVersion": mcp::PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
            },
        }),
        "ping" => serde_json::json!({}),
        "tools/list" => serde_json::json!({ "tools": tool_list() }),
        "tools/call" => match mcp_tool(state, worker, &call) {
            Err(error) => {
                return Response::json(200, &mcp::Response::error(id, error.0, error.1));
            }
            Ok(value) => value,
        },
        // A tool may also be called by its own name, which is the shortest form an agent can
        // choose, so it is answered here rather than sent to the "unknown method" branch.
        other if is_tool(other) => match mcp_tool(state, worker, &call) {
            Err(error) => {
                return Response::json(200, &mcp::Response::error(id, error.0, error.1));
            }
            Ok(value) => value,
        },
        other => {
            return Response::json(
                200,
                &mcp::Response::error(id, mcp::METHOD_NOT_FOUND, format!("unknown method {other}")),
            );
        }
    };

    Response::json(200, &mcp::Response::result(id, reply))
}

/// Whether a method name is one of the tools, which makes it callable without `tools/call`.
fn is_tool(name: &str) -> bool {
    tool_list()
        .iter()
        .any(|tool| tool["name"].as_str() == Some(name))
}

/// The tools the endpoint offers, in the shape `tools/list` wants.
///
/// Every one of them reads (PLAN.md section 10). A tool that would change a file or the store is
/// not offered at all rather than refused at call time, so an agent cannot be tempted to write
/// something it has no business writing, and the page keeps the editing to itself.
/// The six tools the endpoint offers, and nothing else. Every one of them reads. Writing was
/// removed with `0.36.0`: an agent that can write can hand itself a rule, and a rule is the way
/// out to the network, so a tool that reaches the internet could open its own gate.
fn tool_list() -> Vec<serde_json::Value> {
    /// The schema of a tool that takes no arguments at all.
    fn no_arguments() -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }

    let index = serde_json::json!({
        "type": "object",
        "properties": {
            "index": { "type": "integer", "description": "the rule `rules.share` should encode, counted as rules.list orders them" }
        }
    });

    let tools = [
        (
            "status",
            "settings, the rule count, the store, and the monitor",
            no_arguments(),
        ),
        (
            "rules.list",
            "every rule, in the order the firewall reads it",
            no_arguments(),
        ),
        (
            "rules.share",
            "one rule as a Base64 string; takes an index",
            index,
        ),
        (
            "detected.list",
            "the applications learning mode collected, newest first",
            no_arguments(),
        ),
        (
            "events.list",
            "the connections the firewall reported recently, with their destination",
            no_arguments(),
        ),
        (
            "profiles.list",
            "the active profile and the names of the stored profiles",
            no_arguments(),
        ),
    ];

    tools
        .into_iter()
        .map(|(name, description, schema)| {
            serde_json::json!({ "name": name, "description": description, "inputSchema": schema })
        })
        .collect()
}

/// The secret a writing request has to carry, made once when the server starts.
///
/// Sixteen bytes from the operating system, printed as hex so the tray can put it in a URL without
/// escaping. A process that cannot read random bytes has no business handing out a secret, but it
/// serves anyway with a value that is merely guessable, and says so in the log. The token itself is
/// never logged.
pub fn session_token() -> String {
    let mut bytes = [0u8; 16];

    match getrandom::fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        Err(error) => {
            warn!(reason = %error, "could not read random bytes for the session token");

            "loopback-session".to_owned()
        }
    }
}

/// Reject a request the wire says should not reach a route (PLAN.md section 11).
///
/// The three checks answer three different mistakes, so they answer with three different codes:
///
/// * a `Host` that is not loopback is DNS rebinding — a page under another name talked to us
///   because the name resolved here, and it may read nothing but it certainly may not write;
/// * an `Origin` that is not ours is a cross-site request: the page is somewhere else and the
///   browser sent the request anyway;
/// * a missing or wrong token is a page that does not know the secret the tray handed out.
///
/// `GET` is held to the `Host` check only, which is what lets the page, the event stream and an
/// MCP client ask questions without carrying anything. `/mcp` is exempt from the rest of it: the
/// endpoint has no token, and since 0.36.0 it has no writing tools either, so it cannot reach a
/// route that changes a file.
fn guard(request: &Request, token: &str) -> Option<Response> {
    let headers = &request.headers;

    if let Some(host) = &headers.host
        && !is_loopback_host(host)
    {
        return Some(Response::text(
            403,
            format!("host '{host}' is not 127.0.0.1 or localhost"),
        ));
    }

    // A missing Host header is left alone on purpose. HTTP/1.1 asks every request for one and a
    // browser always sends it, so the check can only ever catch a name that is wrong, which is the
    // rebinding case, rather than a command line client that omitted it.
    if request.method == "GET" || request.method == "HEAD" || request.path == "/mcp" {
        return None;
    }

    if let Some(origin) = &headers.origin
        && !is_loopback_origin(origin)
    {
        return Some(Response::text(
            403,
            format!("origin '{origin}' is not this page"),
        ));
    }

    match &headers.content_type {
        Some(text)
            if text
                .trim()
                .to_ascii_lowercase()
                .starts_with("application/json") => {}
        Some(text) => {
            return Some(Response::text(
                415,
                format!("content-type '{text}' is not application/json"),
            ));
        }
        None => {
            return Some(Response::text(
                415,
                "a writing request needs content-type: application/json",
            ));
        }
    }

    match &headers.token {
        Some(given) if given == token => None,
        Some(_) => Some(Response::text(
            401,
            "the session token is not the one issued",
        )),
        None => Some(Response::text(
            401,
            "a writing request needs the session token",
        )),
    }
}

/// Whether a `Host` header names this machine on the loopback interface.
///
/// The port is not checked: a request only reaches the process on the port it listens on, so a
/// page that got the port wrong never arrived in the first place, and a DNS-rebinding page arrives
/// with a name rather than with a port we could usefully have compared.
fn is_loopback_host(host: &str) -> bool {
    let name = host
        .rsplit_once(']')
        .map_or(host, |(_, rest)| rest)
        .trim_start_matches(['[', ':']);

    let name = name.split(':').next().unwrap_or(name);

    name.eq_ignore_ascii_case("localhost")
        || name.parse::<Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || name == "::1"
}

/// Whether an `Origin` header is the page this server serves.
///
/// `null` is refused: it is what a sandboxed frame or a `file://` page sends, and neither is the
/// page the tray opened.
fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin
        .trim()
        .strip_prefix("http://")
        .or_else(|| origin.trim().strip_prefix("https://"))
    else {
        return false;
    };

    is_loopback_host(rest.trim_end_matches('/'))
}

/// The method behind a `tools/call`, with the code and message of a protocol error.
type ToolError = (i32, String);

/// Run one MCP tool.
///
/// Every tool here reads. What a client cannot find is no longer a tool that refused a write but a
/// tool that never existed: an endpoint that offers only questions cannot grant itself a firewall
/// change it then has to explain (PLAN.md section 10).
fn mcp_tool(
    state: &AppState,
    worker: &WfpWorker,
    call: &mcp::Request,
) -> std::result::Result<serde_json::Value, ToolError> {
    match call.tool_name().as_str() {
        "status" => {
            let outcome = worker
                .ask(StoreWork::Inventory)
                .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;
            let rules = state.rules.lock().expect("rules lock poisoned").rule.len();
            let detected = state.detector.snapshot().len();

            Ok(mcp::tool_json(serde_json::json!({
                "port": state.settings.port,
                "learn_mode": state.learn_mode(),
                "default_policy": state.settings.default_policy.name(),
                "theme": state.live.theme().name(),
                "profile": state.active_name(),
                "rules": rules,
                "detected": detected,
                "store": {
                    "readable": outcome.ok,
                    "providers": outcome.inventory.providers,
                    "sublayers": outcome.inventory.sublayers,
                    "filters": outcome.inventory.filters,
                    "reason": outcome.reason,
                },
                "monitor": state.monitor(),
                "startup": state.startup.clone(),
            })))
        }
        "rules.list" => {
            let rules = state.rules.lock().expect("rules lock poisoned").clone();

            Ok(mcp::tool_json(
                serde_json::to_value(rules).map_err(|error| (mcp::REFUSED, error.to_string()))?,
            ))
        }
        "rules.share" => {
            let index = call
                .arg("index")
                .and_then(|value| value.as_u64())
                .ok_or((mcp::INVALID_PARAMS, "rules.share needs an index".to_owned()))?
                as usize;
            let rules = state.rules.lock().expect("rules lock poisoned").clone();

            match rules.rule.get(index) {
                Some(rule) => Ok(mcp::tool_text(
                    export::encode(rule).map_err(|error| (mcp::REFUSED, format!("{error:#}")))?,
                )),
                None => Err((
                    mcp::INVALID_PARAMS,
                    format!("there is no rule at index {index}"),
                )),
            }
        }
        "detected.list" => Ok(mcp::tool_json(
            serde_json::to_value(state.detector.snapshot())
                .map_err(|error| (mcp::REFUSED, error.to_string()))?,
        )),
        "events.list" => {
            let mut events = state.events.snapshot();

            events.reverse();
            events.truncate(STATE_EVENTS);

            Ok(mcp::tool_json(
                serde_json::to_value(events).map_err(|error| (mcp::REFUSED, error.to_string()))?,
            ))
        }
        "profiles.list" => Ok(mcp::tool_json(serde_json::json!({
            "active": state.active_name(),
            "names": crate::rules::list_names(&state.paths.profiles),
        }))),
        other => Err((
            mcp::METHOD_NOT_FOUND,
            format!("this endpoint has no tool named {other}"),
        )),
    }
}

/// The JSON body of `/api/state`.
#[derive(Debug, Clone, Serialize)]
struct StateJson {
    port: u16,
    learn_mode: bool,
    /// `allow` or `deny`: what an application no rule mentions gets.
    default_policy: &'static str,
    /// Whether the installed filters go out with the process. Read at startup; changing it takes
    /// a restart.
    volatile_filters: bool,
    log_level: String,
    /// Which colour scheme the page should show. Reported from the live value rather than from the
    /// settings snapshot, so a change made a moment ago is not answered with the old name.
    theme: &'static str,
    profile: String,
    rules: RuleFile,
    store: StoreOutcome,
    /// The newest events first, so the panel shows the interesting end even when it is truncated.
    events: Vec<NetEvent>,
    /// The applications waiting for a decision, newest first.
    detected: Vec<Detected>,
    /// Whether the feed behind the events is running, with how much it delivered.
    monitor: MonitorJson,
    /// What the rebuild at startup found, so the page can say what changed while it was closed.
    startup: Startup,
    /// The secret a writing request has to carry, so that the page the tray opened can post.
    ///
    /// It is in the answer of a route every page load makes, which is what lets a tab the human
    /// typed the address into learn it without the tray. A page that reached us under another name
    /// is refused by the `Host` check before it could read this.
    token: String,
    /// Whether `rules.toml` on disk is not the file this process wrote.
    ///
    /// True for a hand edit made while the tool was closed as well as for one made a moment ago,
    /// and it clears when the tool writes the file again.
    rules_changed: bool,
}

/// The monitor's state together with the count the log holds, so an empty list can be told apart
/// from a feed that was never open.
#[derive(Debug, Clone, Serialize)]
struct MonitorJson {
    /// `starting`, `running`, `refused` or `stopped`.
    state: &'static str,
    /// The code that refused the subscription, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    /// Events the callback handed over since the process started.
    events: u64,
}

impl StateJson {
    fn new(state: &AppState, store: &StoreOutcome) -> Self {
        let rules = state.rules.lock().expect("rules lock poisoned").clone();

        let mut events = state.events.snapshot();
        events.reverse();
        events.truncate(STATE_EVENTS);

        let mut detected = state.detector.snapshot();
        detected.truncate(STATE_DETECTED);

        Self {
            port: state.settings.port,
            learn_mode: state.learn_mode(),
            default_policy: state.policy().name(),
            volatile_filters: state.settings.volatile_filters,
            log_level: state.settings.log_level.clone(),
            theme: state.live.theme().name(),
            profile: state.active_name(),
            rules,
            store: store.clone(),
            events,
            detected,
            monitor: state.monitor(),
            startup: state.startup.clone(),
            token: state.token.clone(),
            rules_changed: state.rules_changed_outside(),
        }
    }
}

/// The body of `POST /api/detected`: what to do with one detected application.
#[derive(Debug, Clone, Deserialize)]
struct Decision {
    /// The application in device form, which together with `remote` is the identity of the
    /// detected entry.
    app: String,
    /// The destination the entry is about, when it is a destination entry rather than one about
    /// the application alone.
    ///
    /// It is answered with a rule that reaches exactly this address, so the entry does not come
    /// back the next time the application reaches a different one. `#[serde(default)]` keeps a
    /// client that sends no destination deciding an application entry, which is what it was.
    #[serde(default)]
    remote: Option<String>,
    /// The pattern to write into the rule. The UI sends the editable drive form; when it is left
    /// out the drive form of `app` is used.
    #[serde(default)]
    pattern: Option<String>,
    action: Action,
    /// Optional rule name, so an edit can name the rule instead of taking the file name.
    #[serde(default)]
    name: Option<String>,
}

/// The body of `POST /api/detected/dismiss`.
#[derive(Debug, Clone, Deserialize)]
struct Dismissal {
    app: String,
    /// The destination of the entry to drop, when it has one.
    #[serde(default)]
    remote: Option<String>,
}

/// The body of `POST /api/export`.
#[derive(Debug, Clone, Default, Deserialize)]
struct Backup {
    #[serde(default)]
    area: Option<Area>,
}

/// The body of `POST /api/rules/share`: which rule to encode.
#[derive(Debug, Clone, Deserialize)]
struct ShareIndex {
    index: usize,
}

/// The body of `POST /api/rules/import`.
#[derive(Debug, Clone, Deserialize)]
struct Share {
    share: String,
}

/// The body of `POST /api/rules/replace`: a whole rules file, as text.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    text: String,
}

/// The body of `POST /api/profiles/switch`: which profile to make live. An empty name selects
/// `rules.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
struct ProfileSwitch {
    #[serde(default)]
    name: String,
}

/// The body of `POST /api/profiles/rename`: the profile to rename and the name it should have.
#[derive(Debug, Clone, Default, Deserialize)]
struct ProfileRename {
    #[serde(default)]
    name: String,
    #[serde(default)]
    new_name: String,
}

/// The body of `POST /api/settings`. Every field is optional and an absent field keeps its value,
/// so a client can flip one thing without having to know the rest.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsEdit {
    learn_mode: Option<bool>,
    default_policy: Option<Policy>,
    theme: Option<Theme>,
    log_level: Option<String>,
}

/// Write a settings change to `config.toml`, publish the parts that take effect now, and rebuild
/// the store.
///
/// `learn_mode` and `default_policy` are consulted while the process runs, so they go into the
/// atomics the monitor thread reads. `theme` takes effect at once too, because it is the page that
/// renders it and the page reloads the state after every settings change. `log_level` is the filter
/// `tracing` installed at startup, so it alone is written for the next run.
fn apply_settings(
    state: &AppState,
    worker: &WfpWorker,
    edit: SettingsEdit,
) -> Result<StoreOutcome> {
    let mut next = state.settings.clone();

    // The snapshot in `settings` is taken at startup and does not follow a profile switch, so
    // writing it back must not undo the profile the tool is actually on.
    next.active_profile = state.active_name();

    if let Some(learn_mode) = edit.learn_mode {
        next.learn_mode = learn_mode;
    }

    if let Some(policy) = edit.default_policy {
        next.default_policy = policy;
    }

    if let Some(theme) = edit.theme {
        next.theme = theme;
    }

    if let Some(log_level) = edit.log_level {
        next.log_level = log_level;
    }

    next.save(&state.paths.config)
        .context("write the settings file")?;

    state.live.set(next.learn_mode, next.default_policy);
    state.live.set_theme(next.theme);

    let rules = state.rules.lock().expect("rules lock poisoned").clone();

    let outcome = worker.ask(StoreWork::Apply {
        rules,
        known: state.detector.apps(),
        policy: next.default_policy,
    })?;

    info!(
        learn_mode = next.learn_mode,
        default_policy = next.default_policy.name(),
        store = %outcome.describe(),
        "settings changed",
    );

    Ok(outcome)
}

/// Persist the current rules, point the tool at another profile, and rebuild the store.
///
/// The rules being left are written back first, so a change made in the browser survives the
/// switch. An empty name selects `rules.toml`; any other name must be a single file stem, and its
/// file is created empty when it does not exist yet.
fn switch_profile(state: &AppState, worker: &WfpWorker, name: &str) -> Result<StoreOutcome> {
    if !name.is_empty() && !crate::rules::is_valid_profile_name(name) {
        bail!("'{name}' is not a valid profile name");
    }

    let leaving = state.rules.lock().expect("rules lock poisoned").clone();
    let old = state.rules_path();
    leaving
        .save(&old)
        .context("write the rules before switching")?;

    let incoming = make_live(state, name)?;

    worker.ask(StoreWork::Apply {
        rules: incoming,
        known: state.detector.apps(),
        policy: state.policy(),
    })
}

/// Point the tool at one profile's file and hand back the rules it now holds.
///
/// This writes no rules of its own: a rename or a delete of the live file must not write the old
/// name back and bring a file that is gone back to life.
fn make_live(state: &AppState, name: &str) -> Result<RuleFile> {
    let new_file = if name.is_empty() {
        state.paths.rules.clone()
    } else {
        state.paths.profile_file(name)
    };

    let incoming = RuleFile::load_or_create(&new_file)?;

    {
        let mut current = state.rules.lock().expect("rules lock poisoned");
        *current = incoming.clone();
    }
    *state.active_file.lock().expect("rules path lock poisoned") = new_file;
    *state.active_name.lock().expect("active name lock poisoned") = name.to_owned();

    // The active profile is a setting, so it belongs in config.toml. Nothing else changes while
    // the server runs, so the in-memory copy is accurate apart from this one field.
    let mut next = state.settings.clone();
    next.active_profile = name.to_owned();
    next.save(&state.paths.config)
        .context("write the active profile")?;

    Ok(incoming)
}

/// Create a named profile out of the rules that are live, and make the new one live.
///
/// A new profile starts as a copy of what the user is looking at rather than as an empty file,
/// because "new profile" in a browser means "I want to run this set of rules differently", and an
/// empty profile that has to be filled rule by rule is a chore nobody asked for.
fn create_profile(state: &AppState, worker: &WfpWorker, name: &str) -> Result<StoreOutcome> {
    if !crate::rules::is_valid_profile_name(name) {
        bail!("'{name}' is not a valid profile name");
    }

    let file = state.paths.profile_file(name);

    if file.exists() {
        bail!("profile '{name}' already exists");
    }

    let rules = state.rules.lock().expect("rules lock poisoned").clone();
    rules.save(&file).context("create the profile file")?;

    switch_profile(state, worker, name)
}

/// Remove a named profile, falling back to `rules.toml` when the one removed was the live one.
///
/// The file and its backup go together: a backup left behind under a name nothing can select is
/// not a safety net but a stray file in the data directory.
fn delete_profile(state: &AppState, worker: &WfpWorker, name: &str) -> Result<StoreOutcome> {
    if name.is_empty() {
        bail!("the default rules are not a profile, so there is nothing to delete");
    }

    if !crate::rules::is_valid_profile_name(name) {
        bail!("'{name}' is not a valid profile name");
    }

    let file = state.paths.profile_file(name);

    if !file.is_file() {
        bail!("profile '{name}' does not exist");
    }

    std::fs::remove_file(&file).with_context(|| format!("delete profile '{name}'"))?;

    // A backup that will not go away is not worth failing over: the profile is gone, which is
    // what was asked, and what remains is inert.
    let _ = std::fs::remove_file(crate::store::backup_path(&file));

    if state.active_name() != name {
        // The live rules are untouched, so the store is reported rather than rebuilt.
        return worker.ask(StoreWork::Inventory);
    }

    let incoming = make_live(state, "")?;

    worker.ask(StoreWork::Apply {
        rules: incoming,
        known: state.detector.apps(),
        policy: state.policy(),
    })
}

/// Give a profile another name, carrying its backup along and keeping the store honest when the
/// renamed profile was the live one.
fn rename_profile(
    state: &AppState,
    worker: &WfpWorker,
    name: &str,
    new_name: &str,
) -> Result<StoreOutcome> {
    if !crate::rules::is_valid_profile_name(name) {
        bail!("'{name}' is not a valid profile name");
    }

    if !crate::rules::is_valid_profile_name(new_name) {
        bail!("'{new_name}' is not a valid profile name");
    }

    let from = state.paths.profile_file(name);
    let to = state.paths.profile_file(new_name);

    if !from.is_file() {
        bail!("profile '{name}' does not exist");
    }

    if to.exists() {
        bail!("profile '{new_name}' already exists");
    }

    // A rename of the live profile is the only write it gets before the same rules are read back
    // under the new name, so whatever the browser holds has to be on disk first.
    let rules = state.rules.lock().expect("rules lock poisoned").clone();
    rules
        .save(&from)
        .context("write the rules before renaming")?;

    std::fs::rename(&from, &to).with_context(|| format!("rename profile '{name}'"))?;

    // The backup belongs to the file rather than to the name it had, so it moves with it.
    let backup = crate::store::backup_path(&from);

    if backup.is_file() {
        let _ = std::fs::rename(&backup, crate::store::backup_path(&to));
    }

    if state.active_name() != name {
        return worker.ask(StoreWork::Inventory);
    }

    let incoming = make_live(state, new_name)?;

    worker.ask(StoreWork::Apply {
        rules: incoming,
        known: state.detector.apps(),
        policy: state.policy(),
    })
}

/// A request body the server could not read. The client sent it and the client can fix it, so a
/// route that fails this way answers `400` rather than `500`.
#[derive(Debug)]
struct BadRequest(String);

impl std::fmt::Display for BadRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadRequest {}

/// Parse a JSON request body. Anything the server cannot read — a syntax error, a wrong field
/// type, a name outside an enum — is the client's mistake, not the server's.
fn parse_body<T>(body: &[u8], what: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(body)
        .map_err(|error| anyhow::Error::new(BadRequest(format!("body must be {what}: {error}"))))
}

/// Parse a JSON body that may legitimately be empty, as `curl -d ''` and a UI button that sends no
/// payload both produce.
fn parse_or_default<T>(body: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if body.is_empty() {
        return Ok(T::default());
    }

    parse_body(body, "a JSON object")
}

/// Turn a routed result into a response. A body the server could not read answers `400`; any
/// other failure — a store that refused the change, a file that would not write — is `500`.
fn respond(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| {
        let status = if error.downcast_ref::<BadRequest>().is_some() {
            400
        } else {
            500
        };

        Response::text(status, format!("{error:#}"))
    })
}

/// Push the event stream until the client goes away.
///
/// Each connection gets its own thread already, so the only cost of a poll loop is the latency,
/// and a write failure is how a closed browser tab is noticed.
fn stream_events(stream: &mut TcpStream, log: &EventLog) -> Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
              cache-control: no-store\r\nconnection: close\r\n\r\n",
        )
        .context("write event stream header")?;

    let mut last = 0;

    loop {
        let new_events = log.since(last);

        if new_events.is_empty() {
            // An SSE comment is the keepalive. Writing something every poll is also how a client
            // that went away is noticed: flushing an idle socket with nothing to send reports no
            // error, so without this a closed tab would keep its thread forever.
            stream
                .write_all(b": keepalive\n\n")
                .context("event stream closed")?;
        }

        for event in new_events {
            let body = serde_json::to_string(&event).context("serialize event")?;

            stream
                .write_all(format!("data: {body}\n\n").as_bytes())
                .context("write event")?;

            last = event.seq;
        }

        stream.flush().context("flush event stream")?;
        thread::sleep(EVENT_POLL);
    }
}

/// Read one request, write one response.
fn handle_connection(
    mut stream: TcpStream,
    state: Arc<AppState>,
    worker: Arc<WfpWorker>,
) -> Result<()> {
    // The listener is non-blocking for the accept loop's sake; a connection is not, or reading
    // the request would fail with `WouldBlock` before the browser has sent it.
    stream
        .set_nonblocking(false)
        .context("could not switch the connection to blocking")?;

    let mut reader = BufReader::new(stream.try_clone().context("clone stream for reading")?);

    let mut request_line = String::new();
    let read = reader
        .read_line(&mut request_line)
        .context("read request line")?;

    if read == 0 {
        // The peer closed without saying anything, which a prefetcher does.
        return Ok(());
    }

    let mut fields = request_line.split_whitespace();

    let (Some(method), Some(target)) = (fields.next(), fields.next()) else {
        let response = Response::text(400, "malformed request line");
        return write_response(stream, &response);
    };

    // Headers are read to the blank line. Content-length is read here because a POST body must not
    // stay in the socket buffer, and the fields `guard` reads are collected on the way past.
    let mut content_length = 0usize;
    let mut fields = Vec::new();

    loop {
        let mut line = String::new();

        if reader.read_line(&mut line).context("read headers")? == 0 {
            break;
        }

        let trimmed = line.trim_end();

        if trimmed.is_empty() {
            break;
        }

        if let Some(value) = trimmed
            .strip_prefix("content-length:")
            .or_else(|| trimmed.strip_prefix("Content-Length:"))
        {
            content_length = value.trim().parse().unwrap_or(0);
        }

        if let Some((name, value)) = trimmed.split_once(':') {
            fields.push((name.to_owned(), value.to_owned()));
        }
    }

    let mut body = vec![0u8; content_length];

    if content_length > 0 {
        reader.read_exact(&mut body).context("read request body")?;
    }

    let path = target.split('?').next().unwrap_or(target).to_owned();
    let request = Request::with_headers(method, &path, body, Headers::from_pairs(&fields));

    debug!(method = %request.method, path = %request.path, "request");

    // Refused before the event stream is opened: a response that never ends is the worst way to
    // answer a page that is not allowed to ask.
    if let Some(refused) = guard(&request, &state.token) {
        return write_response(stream, &refused);
    }

    if request.path == "/api/events" {
        return stream_events(&mut stream, &state.events);
    }

    let response = respond(Server::route(&state, &worker, &request));

    write_response(stream, &response)
}

fn write_response(mut stream: TcpStream, response: &Response) -> Result<()> {
    stream
        .write_all(response.header().as_bytes())
        .context("write response header")?;
    stream
        .write_all(&response.body)
        .context("write response body")?;
    stream.flush().context("flush response")?;

    Ok(())
}

/// Map a status code to the reason phrase we send.
fn status_text(status: u16) -> &'static str {
    match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        415 => "415 Unsupported Media Type",
        _ => "500 Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn state() -> AppState {
        state_with(Arc::new(EventLog::new()), Live::default())
    }

    /// The token is the whole defence a writing request has, so it is worth pinning down that what
    /// the operating system hands out is long enough to guess nothing and different every run.
    #[test]
    fn a_session_token_is_long_and_different_every_time() {
        let first = session_token();
        let second = session_token();

        assert_eq!(first.len(), 32, "sixteen bytes as hex is 128 bits of token");
        assert!(
            first.chars().all(|c| c.is_ascii_hexdigit()),
            "the token has to survive a URL query: {first}"
        );
        assert_ne!(first, second, "two starts must not share a token");
    }
    /// The guard is what stands between a page on another machine and a rule written to disk, so
    /// each of its checks gets a test of its own rather than one test that happens to pass.
    fn guarded(
        method: &str,
        host: Option<&str>,
        origin: Option<&str>,
        ctype: Option<&str>,
        token: Option<&str>,
    ) -> Response {
        let pairs: Vec<(String, String)> = [
            host.map(|value| ("host".to_owned(), value.to_owned())),
            origin.map(|value| ("origin".to_owned(), value.to_owned())),
            ctype.map(|value| ("content-type".to_owned(), value.to_owned())),
            token.map(|value| ("x-winfw-token".to_owned(), value.to_owned())),
        ]
        .into_iter()
        .flatten()
        .collect();

        let request = Request::with_headers(
            method,
            "/api/rules",
            br#"{"rule":[]}"#.to_vec(),
            Headers::from_pairs(&pairs),
        );

        guard(&request, TEST_TOKEN).unwrap_or_else(|| Response::text(200, "allowed"))
    }

    #[test]
    fn a_writing_request_without_a_token_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://127.0.0.1:8788"),
            Some("application/json"),
            None,
        );

        assert_eq!(
            response.status, 401,
            "the token is what identifies the page"
        );
    }

    #[test]
    fn a_writing_request_with_the_wrong_token_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://127.0.0.1:8788"),
            Some("application/json"),
            Some("some-other-token"),
        );

        assert_eq!(response.status, 401);
    }

    /// A page on another host can still reach the socket; what it may not do is write.
    #[test]
    fn a_writing_request_from_another_origin_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://example.com"),
            Some("application/json"),
            Some(TEST_TOKEN),
        );

        assert_eq!(response.status, 403, "a wrong origin is the CSRF case");
    }

    /// DNS rebinding makes `example.com` resolve to `127.0.0.1` *after* the page loaded, so the
    /// `Host` header of the requests that follow is the only thing that names the name in use.
    #[test]
    fn a_request_for_another_host_is_refused() {
        let response = guarded("GET", Some("example.com"), None, None, None);

        assert_eq!(
            response.status, 403,
            "a read is guarded against rebinding too"
        );
    }

    #[test]
    fn a_writing_request_without_a_json_body_is_refused() {
        let response = guarded(
            "POST",
            Some("localhost:8788"),
            Some("http://localhost:8788"),
            Some("text/plain"),
            Some(TEST_TOKEN),
        );

        assert_eq!(response.status, 415);
    }

    /// The browser learns the token from the URL the tray opens, and a `GET` is what reads it
    /// back, so a read must never be refused for not carrying it.
    #[test]
    fn a_reading_request_is_allowed_without_token_or_content_type() {
        let response = guarded("GET", Some("127.0.0.1:8788"), None, None, None);

        assert_eq!(response.status, 200);
    }

    /// The MCP endpoint is deliberately outside the token: an agent is configured with a URL
    /// rather than with a session, and it only reads.
    #[test]
    fn the_mcp_endpoint_is_allowed_without_a_token() {
        let request = Request::with_headers(
            "POST",
            "/mcp",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
            Headers::from_pairs(&[]),
        );

        assert!(guard(&request, TEST_TOKEN).is_none());
    }

    /// The writing tools are gone from the endpoint, so a client that still calls one hears
    /// `method not found` rather than watching a file change behind its back.
    #[test]
    fn calling_a_removed_tool_is_a_method_not_found() {
        let server_state = state();
        let worker = WfpWorker::start();
        let rules_path = server_state.rules_path();

        let before = std::fs::read_to_string(&rules_path).ok();

        let response = Server::route(
                &server_state,
                &worker,
                &Request::new(
                    "POST",
                    "/mcp",
                    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rules.allow","arguments":{"app":"notepad.exe"}}}"#.to_vec(),
                ),
            )
            .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains("-32601"),
            "a removed tool is not a tool any more: {body}",
        );
        assert_eq!(
            std::fs::read_to_string(&rules_path).ok(),
            before,
            "an MCP call must not write a rule file",
        );
    }
    /// The tray's pause flips the flag and reports the new value, leaving the policy alone.
    #[test]
    fn toggling_learning_reports_what_it_became_and_keeps_the_policy() {
        let live = Live::new(true, Policy::Deny, Theme::Dark);

        assert!(!live.toggle_learning());
        assert_eq!(live.policy(), Policy::Deny);
        assert!(live.toggle_learning());
    }

    /// The token the test states hand out, so a test can write the header a browser would write.
    const TEST_TOKEN: &str = "test-token";

    fn state_with(events: Arc<EventLog>, live: Live) -> AppState {
        let scratch = crate::testutil::scratch_dir("server");
        let paths = DataPaths::under(scratch.join("data"));

        paths.ensure().expect("create the data directories");

        let detector = Detector::load(&paths.learn).expect("load the detected list");

        let active_file = paths.rules.clone();

        AppState::new(
            paths,
            Settings::default(),
            Arc::new(Mutex::new(RuleFile {
                rule: vec![Rule::plain(
                    "browser",
                    crate::rules::Action::Allow,
                    "C:\\Program Files\\*\\browser.exe",
                )],
            })),
            Arc::new(detector),
            events,
            Arc::new(live),
            active_file,
            String::new(),
            Startup::unmeasured(),
            TEST_TOKEN.to_owned(),
            None,
        )
    }

    /// Whether the store accepted the work a route just did. Only an accepted write takes an entry
    /// off the Detected list, and an unelevated run is refused by the store, which is a fact about
    /// the machine rather than about the code. The store tests cover the accepted case.
    fn store_accepted(body: &str) -> bool {
        serde_json::from_str::<serde_json::Value>(body)
            .expect("a state body is JSON")
            .pointer("/store/ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    fn connection(app: &str) -> crate::monitor::NetEvent {
        crate::monitor::NetEvent {
            seq: 0,
            time_ms: 0,
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

    /// A decided application becomes an ordinary rule, leaves the detected list, and the rules
    /// file carries the new entry.
    #[test]
    fn a_detected_application_becomes_a_rule() {
        let server_state = state();
        let worker = WfpWorker::start();

        server_state.detector.observe(
            &connection("\\device\\harddiskvolume3\\windows\\system32\\thing.exe"),
            &RuleFile::default(),
        );

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/detected",
                br#"{"app":"\\device\\harddiskvolume3\\windows\\system32\\thing.exe","pattern":"C:\\Windows\\System32\\thing.exe","action":"allow","name":"thing"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert_eq!(response.status, 200, "{body}");
        assert!(
            body.contains("thing.exe"),
            "the rule is in the state: {body}"
        );
        assert_eq!(
            server_state
                .detector
                .snapshot()
                .iter()
                .any(|entry| entry.app.contains("thing.exe")),
            !store_accepted(&body),
            "a decided entry leaves the Detected list only when the store accepted the rule",
        );

        let written = std::fs::read_to_string(&server_state.paths.rules).expect("rules.toml");

        assert!(
            written.contains("C:\\Windows\\System32\\thing.exe"),
            "the drive form is what the file holds: {written}"
        );
    }

    /// A detected destination is answered with a rule that reaches exactly that address, which is
    /// the only way the entry does not come back on the next connection somewhere else.
    #[test]
    fn a_detected_destination_becomes_a_rule_that_reaches_it() {
        let server_state = state();
        let worker = WfpWorker::start();

        let covered = RuleFile {
            rule: vec![Rule {
                remote: Some("10.0.0.0/24".parse().expect("parse a network")),
                ..Rule::plain("thing", Action::Allow, "C:\\Windows\\System32\\thing.exe")
            }],
        };

        *server_state.rules.lock().expect("rules lock") = covered.clone();

        server_state.detector.observe(
            &crate::monitor::NetEvent {
                remote_addr: "93.184.216.34".to_owned(),
                ..connection("\\device\\harddiskvolume3\\windows\\system32\\thing.exe")
            },
            &covered,
        );

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/detected",
                br#"{"app":"\\device\\harddiskvolume3\\windows\\system32\\thing.exe","pattern":"C:\\Windows\\System32\\thing.exe","remote":"93.184.216.34","action":"deny","name":"thing cdn"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert_eq!(response.status, 200, "{body}");

        let written = std::fs::read_to_string(&server_state.paths.rules).expect("rules.toml");

        assert!(
            written.contains("remote = \"93.184.216.34\""),
            "the rule reaches the destination it was offered for: {written}",
        );
        assert_eq!(
            server_state
                .detector
                .snapshot()
                .iter()
                .filter(|entry| entry.app.contains("thing.exe"))
                .count(),
            usize::from(!store_accepted(&body)),
            "a decided entry leaves the Detected list only when the store accepted the rule",
        );
    }

    /// Switching to a new profile keeps the rules we had in the file they came from, points the
    /// tool at the new (empty) file, and lists the new profile as the active one.
    #[test]
    fn switching_profile_moves_the_live_rules_to_a_new_file() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/switch",
                br#"{"name":"work"}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        let left = std::fs::read_to_string(&server_state.paths.rules).expect("rules.toml");
        assert!(
            left.contains("browser"),
            "the file we left keeps its rules: {left}"
        );

        let listed = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/profiles", vec![]),
        )
        .expect("route");
        let body = String::from_utf8_lossy(&listed.body).into_owned();

        assert!(
            body.contains(r#""active":"work""#),
            "the new profile is active: {body}",
        );
        assert!(body.contains("work"), "the new profile is listed: {body}");
    }

    /// Creating a profile is a copy of what is on screen made live, which is what "new profile"
    /// means in a browser: the alternative is an empty file the user has to fill rule by rule.
    #[test]
    fn a_new_profile_copies_the_rules_it_was_made_from_and_becomes_live() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/create",
                br#"{"name":"trial"}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""profile":"trial""#),
            "the new profile is the live one: {body}",
        );

        let file = server_state.paths.profile_file("trial");
        let copied = std::fs::read_to_string(&file).expect("the profile file");

        assert!(
            copied.contains("browser"),
            "the profile starts out as the rules on screen: {copied}",
        );
    }

    /// A name that is already taken is refused rather than quietly overwritten, because overwriting
    /// would throw away rules the user cannot see from the page they are on.
    #[test]
    fn creating_a_profile_that_exists_is_refused() {
        let server_state = state();
        let worker = WfpWorker::start();

        for attempt in 0..2 {
            let response = Server::route(
                &server_state,
                &worker,
                &Request::new(
                    "POST",
                    "/api/profiles/create",
                    br#"{"name":"twice"}"#.to_vec(),
                ),
            );

            if attempt == 0 {
                response.expect("the first create");
            } else {
                assert!(response.is_err(), "the second create must be refused");
            }
        }
    }

    /// Deleting the live profile falls back to `rules.toml` and takes the file with it, so the data
    /// directory does not fill up with profiles nobody can select.
    #[test]
    fn deleting_the_live_profile_falls_back_to_the_default_rules() {
        let server_state = state();
        let worker = WfpWorker::start();

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/create",
                br#"{"name":"gone"}"#.to_vec(),
            ),
        )
        .expect("create");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/delete",
                br#"{"name":"gone"}"#.to_vec(),
            ),
        )
        .expect("delete");

        assert_eq!(response.status, 200);

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""profile":"""#),
            "the default rules are live again: {body}",
        );
        assert!(
            !server_state.paths.profile_file("gone").is_file(),
            "the file goes with the profile",
        );
    }

    /// The default is not a profile, so there is nothing to delete; saying so beats removing
    /// `rules.toml`, which is the file the tool falls back to.
    #[test]
    fn the_default_rules_cannot_be_deleted_as_a_profile() {
        let server_state = state();
        let worker = WfpWorker::start();

        let error = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/profiles/delete", br#"{"name":""}"#.to_vec()),
        )
        .err()
        .expect("the default is not a profile");

        assert!(format!("{error:#}").contains("default"), "{error:#}");
    }

    /// Renaming the live profile keeps it live under the new name, and the file that held it is
    /// gone rather than left behind with the old one.
    #[test]
    fn renaming_the_live_profile_keeps_it_live_under_the_new_name() {
        let server_state = state();
        let worker = WfpWorker::start();

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/create",
                br#"{"name":"before"}"#.to_vec(),
            ),
        )
        .expect("create");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/rename",
                br#"{"name":"before","new_name":"after"}"#.to_vec(),
            ),
        )
        .expect("rename");

        assert_eq!(response.status, 200);

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""profile":"after""#),
            "the renamed profile is still live: {body}",
        );
        assert!(
            server_state.paths.profile_file("after").is_file(),
            "the rules moved to the new name",
        );
        assert!(
            !server_state.paths.profile_file("before").is_file(),
            "the old name is not left behind",
        );
    }

    /// `tools/list` is what an agent reads before it acts, so the list *is* the surface: a writing
    /// tool that is not listed cannot be called, and `shutdown` is proof that it is really gone.
    #[test]
    fn the_tool_list_offers_only_reading_tools() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        for name in [
            "status",
            "rules.list",
            "rules.share",
            "detected.list",
            "events.list",
            "profiles.list",
        ] {
            assert!(
                body.contains(&format!(r#""name":"{name}""#)),
                "{name} is a tool an agent can discover: {body}",
            );
        }

        for name in ["shutdown", "settings.set", "rules.allow", "rules.decode"] {
            assert!(
                !body.contains(&format!(r#""name":"{name}""#)),
                "{name} wrote to a file or the store, so it is not offered any more: {body}",
            );
        }
    }

    /// A settings change is written to `config.toml`, published to the atomics the monitor reads,
    /// and answered with the state the server actually settled on.
    #[test]
    fn the_settings_endpoint_writes_the_file_and_takes_effect_at_once() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/settings",
                br#"{"default_policy": "deny", "learn_mode": false}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""default_policy":"deny""#), "{body}");
        assert!(body.contains(r#""learn_mode":false"#), "{body}");

        let written =
            std::fs::read_to_string(server_state.paths.config.clone()).expect("read the config");

        assert!(
            written.contains(r#"default_policy = "deny""#),
            "the change must survive a restart: {written}",
        );

        assert!(
            !server_state.live.learning() && server_state.live.policy() == Policy::Deny,
            "the monitor has to see the change without a restart",
        );
    }

    /// The page can only send the token back if the state carries it, which is how a second tab
    /// that was opened without `?token=` still learns how it may write.
    #[test]
    fn the_state_endpoint_carries_the_session_token() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""token":"test-token""#),
            "the page reads the token out of the state: {body}",
        );
    }

    /// A save by the tool is not a change from outside, so the page must not be told otherwise.
    #[test]
    fn a_save_by_the_tool_leaves_no_notice() {
        let server_state = state();
        let worker = WfpWorker::start();

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true}]}"#.to_vec(),
            ),
        )
        .expect("route");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""rules_changed":false"#),
            "the file on disk is our own work: {body}",
        );
    }

    /// Someone edited `rules.toml` while we were not looking — or while we were running — and the
    /// page has to say so rather than quietly keep showing the rules in memory.
    #[test]
    fn a_change_to_the_rules_file_is_noticed() {
        let server_state = state();
        let worker = WfpWorker::start();

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true}]}"#.to_vec(),
            ),
        )
        .expect("route");

        let file = server_state.rules_path();
        let edited = format!(
            "{}\n",
            std::fs::read_to_string(&file).expect("read the rules file we just wrote")
        );
        std::fs::write(&file, edited).expect("write the edited rules file");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""rules_changed":true"#),
            "a file edited by hand is a file the page must mention: {body}",
        );
    }
    /// The theme is the one setting the page renders, so it has to arrive with the state rather
    /// than live only in the file the page cannot read.
    #[test]
    fn the_state_endpoint_reports_the_theme() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""theme":"dark""#),
            "the theme the settings file is written with: {body}",
        );
    }

    /// A theme change is answered with the new name and lands in `config.toml`, which is what makes
    /// it take effect in the browser without a restart while `log_level` still waits for one.
    #[test]
    fn a_theme_change_takes_effect_at_once_and_reaches_the_file() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/settings", br#"{"theme":"light"}"#.to_vec()),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""theme":"light""#),
            "the page is told the new scheme: {body}",
        );

        let written =
            std::fs::read_to_string(server_state.paths.config.clone()).expect("read the config");

        assert!(
            written.contains(r#"theme = "light""#),
            "the choice has to survive a restart: {written}",
        );

        // `auto` is the value the live setting cannot hold the same way, because it is the number
        // the fallback for an unknown value answers with. A change that reaches the file but not
        // the answer would be invisible to every test that stops at "light".
        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/settings", br#"{"theme":"auto"}"#.to_vec()),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains(r#""theme":"auto""#),
            "following the operating system has to be reported as itself: {body}",
        );
    }

    /// A theme the server cannot name is refused rather than written to the file, where it would
    /// sit unreadable and make the next startup parse a value the page has no colours for.
    #[test]
    fn the_settings_endpoint_refuses_a_theme_it_cannot_read() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/settings", br#"{"theme":"neon"}"#.to_vec()),
        );

        assert!(response.is_err(), "a theme is one of three names");

        assert_eq!(
            server_state.live.theme(),
            crate::config::Theme::Dark,
            "a refused theme changes nothing",
        );
    }

    /// An unknown field in a settings body is refused rather than ignored, so a client that
    /// misspells a setting learns about it instead of watching nothing happen.
    #[test]
    fn the_settings_endpoint_refuses_a_field_it_does_not_know() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/settings",
                br#"{"defualt_policy": "deny"}"#.to_vec(),
            ),
        );

        assert!(response.is_err(), "a typo must not be accepted silently");
    }

    /// A body the server could not read is the client's mistake and must answer as one. Found by
    /// a live run of 0.32.0: an unreadable theme answered `500`, which told the user the server
    /// had broken rather than that the value was wrong.
    #[test]
    fn an_unreadable_settings_body_answers_bad_request() {
        let server_state = state();
        let worker = WfpWorker::start();

        for body in [r#"{"theme":"neon"}"#, r#"{"policy":"deny"}"#, "{"] {
            let response = respond(Server::route(
                &server_state,
                &worker,
                &Request::new("POST", "/api/settings", body.as_bytes().to_vec()),
            ));

            assert_eq!(response.status, 400, "not the server's fault: {body}");
        }
    }

    /// The other half of the mapping: a failure that is not a bad body stays a `500`. Naming an
    /// index outside the rule list parses fine, so only the refusal path can answer for it.
    #[test]
    fn a_failure_that_is_not_a_bad_body_stays_internal() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = respond(Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/share", br#"{"index":40}"#.to_vec()),
        ));

        assert_eq!(response.status, 500, "a refusal is not a parse error");
    }

    /// A rule narrowed by protocol, direction, port and remote address travels through the API,
    /// lands in `rules.toml`, and comes back in the state, which is what the four narrowing
    /// columns of the page rely on.
    #[test]
    fn a_narrowed_rule_travels_through_the_api() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"protocol":"tcp","direction":"out","port":"1024-2048","remote":"192.168.1.0/24"}]}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""protocol":"tcp""#), "{body}");
        assert!(body.contains(r#""direction":"out""#), "{body}");
        assert!(body.contains(r#""port":"1024-2048""#), "{body}");
        assert!(body.contains(r#""remote":"192.168.1.0/24""#), "{body}");

        let written = std::fs::read_to_string(server_state.rules_path()).expect("read the rules");

        assert!(
            written.contains(r#"protocol = "tcp""#),
            "the narrowing has to survive a restart: {written}",
        );
    }

    /// A remote address the server cannot read is refused rather than read as any address, and a
    /// network written with host bits comes back as the network.
    #[test]
    fn the_rules_endpoint_refuses_an_address_it_cannot_read() {
        let server_state = state();
        let worker = WfpWorker::start();

        let refused = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"remote":"192.168.1.0/33"}]}"#.to_vec(),
            ),
        );

        assert!(refused.is_err(), "a prefix has a maximum");

        let accepted = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"remote":"10.0.0.5/24"}]}"#.to_vec(),
            ),
        )
        .expect("route the network");

        let body = String::from_utf8_lossy(&accepted.body).into_owned();

        assert!(
            body.contains(r#""remote":"10.0.0.0/24""#),
            "the host bits are dropped: {body}",
        );
    }

    /// A port the server cannot read is refused rather than read as no port, so a typo in the page
    /// cannot silently widen a rule to every port.
    #[test]
    fn the_rules_endpoint_refuses_a_port_it_cannot_read() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"port":"http"}]}"#.to_vec(),
            ),
        );

        assert!(response.is_err(), "a port must be a port");
    }

    /// An agent may name a tool directly rather than wrapping it in `tools/call`, which is the
    /// shortest form it can send and therefore the one it is most likely to guess.
    #[test]
    fn a_tool_can_be_called_by_its_own_name() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"profiles.list"}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            !body.contains("unknown method"),
            "a tool name is a method too: {body}"
        );
        assert!(
            body.contains("structuredContent"),
            "the tool itself answered: {body}",
        );
    }

    #[test]
    fn an_unknown_path_is_not_found() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/nope", vec![]),
        )
        .expect("route");

        assert_eq!(response.status, 404);
    }

    /// `POST /api/shutdown` clears the flag the accept loop waits on, which is what lets the
    /// process end rather than run on with no tray icon and no way to stop it.
    #[test]
    fn a_shutdown_request_stops_the_accept_loop() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/shutdown", vec![]),
        )
        .expect("route");

        assert_eq!(response.status, 200);
        assert!(
            !server_state.running.load(Ordering::SeqCst),
            "the flag the accept loop waits on must be cleared",
        );

        // A second request says it was not the one that stopped the loop, so a client can tell a
        // first quit from a repeated one.
        let repeated = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/shutdown", vec![]),
        )
        .expect("route");

        let body: serde_json::Value =
            serde_json::from_slice(&repeated.body).expect("the shutdown answer is json");

        assert_eq!(body["stopping"], false, "only the first request stops");
    }

    #[test]
    fn the_index_page_is_served_from_the_binary() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(&server_state, &worker, &Request::new("GET", "/", vec![]))
            .expect("route");

        assert_eq!(response.status, 200);
        assert!(
            String::from_utf8_lossy(&response.body).contains("<html"),
            "the embedded page must be a document",
        );
    }

    /// The browser asks for this on every page load, and a missing file would mean a 404 in the
    /// developer console for a page that otherwise has nothing to complain about.
    #[test]
    fn the_favicon_is_served_from_the_binary_too() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/favicon.ico", vec![]),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        // An ICO file starts with the reserved zero, the type 1 and a count, so six bytes already
        // say whether the asset made it into the binary at all.
        assert!(
            response.body.len() > 4096,
            "the icon must be a real file, not an empty asset",
        );
        assert_eq!(&response.body[..4], &[0, 0, 1, 0], "an ICO header");
    }

    #[test]
    fn the_export_endpoint_copies_the_files_of_every_area() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/export", br#"{}"#.to_vec()),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert_eq!(response.status, 200, "{body}");
        assert!(body.contains("\"files\""), "{body}");
    }

    #[test]
    fn a_rule_can_be_shared_and_imported_again() {
        let server_state = state();
        let worker = WfpWorker::start();

        let shared = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/share", br#"{"index":0}"#.to_vec()),
        )
        .expect("route");

        assert_eq!(shared.status, 200);

        let text = String::from_utf8(shared.body).expect("share is text");

        // Importing it has to add a second rule, and the added rule must be the shared one.
        let imported = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules/import",
                format!(r#"{{"share":"{text}"}}"#).into_bytes(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&imported.body).into_owned();

        assert_eq!(imported.status, 200, "{body}");
        assert_eq!(
            body.matches(r#""name":"browser""#).count(),
            2,
            "the shared rule must be appended, not replace the existing one: {body}",
        );
    }

    /// A rules file handed over whole replaces the list rather than adding to it, which is what
    /// turns an export into something a person can put back.
    #[test]
    fn a_whole_file_replaces_the_rule_list() {
        let server_state = state();
        let worker = WfpWorker::start();

        let text = r#"version = 1

[[rule]]
name = "one"
action = "allow"
pattern = "C:\\Windows\\one.exe"

[[rule]]
name = "two"
action = "deny"
pattern = "C:\\Windows\\two.exe"
"#;

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules/replace",
                serde_json::json!({ "text": text }).to_string().into_bytes(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert_eq!(response.status, 200, "{body}");
        assert!(
            body.contains(r#""name":"one""#),
            "the file's rules are on screen: {body}"
        );
        assert!(
            body.contains(r#""name":"two""#),
            "the file's rules are on screen: {body}"
        );

        assert!(
            !body.contains(r#""name":"browser""#),
            "a replacement takes what the file does not name: {body}",
        );

        let written =
            std::fs::read_to_string(server_state.rules_path()).expect("read the rules file");

        assert!(
            written.contains("one") && written.contains("two"),
            "the replacement has to survive a restart: {written}",
        );
    }

    /// A file this build cannot read is refused before the one on disk is touched, because the
    /// point of a restore is not to lose the set it was meant to fix.
    #[test]
    fn a_whole_file_that_cannot_be_read_leaves_the_rules_alone() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules/replace",
                serde_json::json!({ "text": "version = 99\n" })
                    .to_string()
                    .into_bytes(),
            ),
        );

        assert!(
            response.is_err(),
            "a version this build does not know is not a rule list",
        );

        assert_eq!(
            server_state.rules.lock().expect("rules lock").rule.len(),
            1,
            "a refused import changes nothing",
        );
    }

    #[test]
    fn an_index_outside_the_rule_list_is_refused() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/share", br#"{"index":9}"#.to_vec()),
        )
        .err()
        .expect("index 9 does not exist");

        assert!(format!("{response:#}").contains("index 9"), "{response:#}");
    }

    #[test]
    fn the_state_endpoint_answers_with_the_loaded_rules() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert_eq!(response.status, 200);
        assert!(body.contains("\"browser\""), "{body}");
        assert!(body.contains("\"rules\""), "{body}");
    }

    /// An empty connection list has to come with the reason for being empty, which is what the
    /// monitor reports: a refused subscription is a supported state, and a page that hides it
    /// reads as a quiet machine.
    #[test]
    fn the_state_endpoint_reports_the_monitor_and_what_it_delivered() {
        let server_state = state();
        let worker = WfpWorker::start();

        let body = |label: &str| {
            let response = Server::route(
                &server_state,
                &worker,
                &Request::new("GET", "/api/state", vec![]),
            )
            .expect(label);

            String::from_utf8_lossy(&response.body).into_owned()
        };

        let before = body("state before the monitor reported");

        assert!(before.contains("\"monitor\""), "{before}");
        assert!(
            before.contains("\"starting\""),
            "nothing reported yet: {before}"
        );

        server_state
            .live
            .set_monitor(crate::monitor::MonitorStatus::refused(format!(
                "{:#010x}",
                5
            )));

        let after = body("state after a refusal");

        assert!(after.contains("\"refused\""), "{after}");
        assert!(
            after.contains("0x00000005"),
            "the code has to be named: {after}"
        );
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

    /// The page cannot show the diff the process found before the listener existed unless the state
    /// carries it, which is what PLAN.md section 6 asks for.
    #[test]
    fn the_state_endpoint_carries_the_startup_diff() {
        let mut server_state = state();

        server_state.startup = Startup {
            measured: true,
            ok: true,
            removed: 2,
            installed: 6,
            reason: None,
            differs: true,
        };

        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains("\"startup\""), "{body}");
        assert!(body.contains("\"removed\":2"), "the store's count: {body}");
        assert!(body.contains("\"installed\":6"), "the rules' count: {body}");
        assert!(body.contains("\"differs\":true"), "{body}");
    }

    /// A state that never went through a startup rebuild says so, rather than letting the page read
    /// two zeros as a store that was found empty.
    #[test]
    fn a_state_that_never_rebuilt_the_store_says_the_startup_was_not_measured() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains("\"measured\":false"),
            "a test state never touched the store: {body}"
        );
    }

    /// The state response carries the newest events first, so the panel renders in one request.
    #[test]
    fn the_state_endpoint_carries_recent_events() {
        let events = Arc::new(EventLog::new());
        events.push(connection("older.exe"));
        events.push(connection("newer.exe"));

        let server_state = state_with(Arc::clone(&events), Live::default());
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains("newer.exe"), "{body}");
        assert!(
            body.find("newer.exe") < body.find("older.exe"),
            "the newest event must come first: {body}",
        );
    }

    /// An event that names a filter carries both the raw id and the rule it resolved to, which is
    /// what lets the panel say which of our rules decided a connection.
    #[test]
    fn the_state_endpoint_carries_the_rule_an_event_blames() {
        let events = Arc::new(EventLog::new());

        let mut event = connection("blamed.exe");
        event.filter_id = 42;
        event.rule = Some("browser".to_owned());
        events.push(event);

        let server_state = state_with(Arc::clone(&events), Live::default());
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""filter_id":42"#), "{body}");
        assert!(body.contains(r#""rule":"browser""#), "{body}");
    }

    /// The destination is what tells two connections from one application apart, so it has to
    /// reach the browser rather than stop in the callback.
    #[test]
    fn the_state_endpoint_carries_the_address_an_event_went_to() {
        let events = Arc::new(EventLog::new());

        let mut event = connection("dialer.exe");
        event.remote_addr = "93.184.216.34".to_owned();
        events.push(event);

        let server_state = state_with(Arc::clone(&events), Live::default());
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""remote_addr":"93.184.216.34""#), "{body}");
    }

    /// Which socket answered and whether the traffic left the machine are the other two things a
    /// reader needs to make sense of a connection, so they travel with it.
    #[test]
    fn the_state_endpoint_carries_the_local_end_and_the_loopback_marker() {
        let events = Arc::new(EventLog::new());

        let mut event = connection("listener.exe");
        event.local_addr = "127.0.0.1".to_owned();
        event.remote_addr = "127.0.0.1".to_owned();
        event.loopback = true;
        events.push(event);

        let server_state = state_with(Arc::clone(&events), Live::default());
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""local_addr":"127.0.0.1""#), "{body}");
        assert!(body.contains(r#""local_port":49152"#), "{body}");
        assert!(body.contains(r#""loopback":true"#), "{body}");
    }

    /// The stream is not a buffered response, so it is exercised over a socket.
    #[test]
    fn the_event_stream_serves_headers_and_then_events() {
        let events = Arc::new(EventLog::new());
        let server = Server::bind(
            0,
            state_with(Arc::clone(&events), Live::default()),
            Arc::new(WfpWorker::start()),
        )
        .expect("bind");
        let addr = server.addr();

        let join = thread::spawn(move || server.serve_once());

        let mut socket = TcpStream::connect(addr).expect("connect");
        socket
            .write_all(b"GET /api/events HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .expect("send request");

        // The first read can only see what had been written by then, which is the header.
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");

        let mut header = [0u8; 20];
        socket.read_exact(&mut header).expect("read stream header");
        assert_eq!(
            &header,
            b"HTTP/1.1 200 OK\r\ncon",
            "{}",
            String::from_utf8_lossy(&header),
        );

        events.push(connection("late.exe"));

        // The remaining header bytes are already buffered, so reading until the event shows up is
        // what the stream actually promises rather than one read returning it.
        let mut text = String::new();
        let mut chunk = [0u8; 512];

        while !text.contains("late.exe") {
            let read = socket.read(&mut chunk).expect("read event");

            assert_ne!(
                read, 0,
                "the stream closed before the event arrived: {text}"
            );
            text.push_str(&String::from_utf8_lossy(&chunk[..read]));
        }

        assert!(text.contains("data: "), "{text}");

        drop(socket);

        // The stream only ends because the client went away, which is reported as a write error.
        let outcome = join.join().expect("the serving thread panicked");
        assert!(outcome.is_err(), "a closed client must end the stream");
    }

    /// The whole loop over a real socket, on an ephemeral port.
    #[test]
    fn a_real_socket_answers_the_state_request() {
        let server = Server::bind(0, state(), Arc::new(WfpWorker::start())).expect("bind");
        let addr = server.addr();

        let join = thread::spawn(move || server.serve_once());

        let mut socket = TcpStream::connect(addr).expect("connect");
        socket
            .write_all(b"GET /api/state HTTP/1.1\r\nhost: localhost\r\n\r\n")
            .expect("send request");

        let mut raw = String::new();
        socket.read_to_string(&mut raw).expect("read response");

        join.join()
            .expect("the serving thread panicked")
            .expect("serve_once failed");

        assert!(raw.starts_with("HTTP/1.1 200 OK"), "{raw}");
        assert!(raw.contains("\"rules\""), "{raw}");
    }

    /// A busy configured port is answered by the next free one rather than by an error, which is
    /// what keeps a port conflict from killing the tray app.
    #[test]
    fn a_busy_port_makes_the_server_fall_forward() {
        let blocker = TcpListener::bind("127.0.0.1:0").expect("blocker");
        let port = blocker.local_addr().expect("blocker address").port();

        let server = Server::bind(port, state(), Arc::new(WfpWorker::start())).expect("bind");
        let bound = server.addr().port();

        assert_ne!(bound, port, "the busy port cannot be taken twice");
        assert!(
            bound > port && bound < port + PORT_ATTEMPTS,
            "fell forward to {bound} from a busy {port}"
        );
    }
}
