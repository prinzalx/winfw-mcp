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
//! | POST | `/api/export` | copy rules, config and the Detected list into `export\` |
//! | POST | `/api/rules/share` | one rule as a Base64 string, for copy and paste |
//! | POST | `/api/rules/import` | append the rule a Base64 string carries |
//! | POST | `/mcp` | JSON-RPC 2.0 for an MCP client: see `crate::mcp` |
//!
//! ## Threading
//!
//! A WFP transaction belongs to a thread rather than to a handle (see `wfp::Engine::transaction`),
//! so exactly one thread owns the engine handle: the WFP worker. Request threads hand their work
//! over a channel and wait for the reply, which is what makes the arrangement safe rather than
//! merely convenient.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::config::{Settings, Writes};
use crate::export::{self, Area};
use crate::learn::{Detected, Detector};
use crate::mcp;
use crate::monitor::{EventLog, NetEvent};
use crate::paths::DataPaths;
use crate::rules::{Action, Rule, RuleFile};

/// The page served at `/`, embedded so the binary stays a single file.
const INDEX_HTML: &str = include_str!("../web/index.html");

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
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        paths: DataPaths,
        settings: Settings,
        rules: Arc<Mutex<RuleFile>>,
        detector: Arc<Detector>,
        events: Arc<EventLog>,
        active_file: PathBuf,
        active_name: String,
    ) -> Self {
        Self {
            paths,
            settings,
            rules,
            detector,
            events,
            active_file: Mutex::new(active_file),
            active_name: Mutex::new(active_name),
            running: Arc::new(AtomicBool::new(true)),
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
}

/// A parsed request. Only the parts a local, single-user server needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    path: String,
    body: Vec<u8>,
}

impl Request {
    pub fn new(method: &str, path: &str, body: Vec<u8>) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body,
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
    /// detector has seen.
    Apply { rules: RuleFile, known: Vec<String> },
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
}

impl WfpWorker {
    /// Start the worker. On non-Windows builds the worker still runs, so the server behaves the
    /// same and reports the store as unavailable.
    pub fn start() -> Self {
        // A bounded queue of one is deliberate: a second change waits for the first to be carried
        // out, which is also what keeps two full filter rebuilds from racing.
        let (sender, receiver) = sync_channel::<WorkItem>(1);

        let join = thread::spawn(move || {
            #[cfg(windows)]
            let engine = match crate::wfp::Engine::open() {
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
                    work,
                );

                // A closed reply channel only means the request thread gave up.
                let _ = reply.send(outcome);
            }
        });

        Self {
            sender: Some(sender),
            join: Some(join),
        }
    }

    /// A second handle on the request queue, for a caller that has work but no interest in the
    /// answer. The monitor uses it to rebuild the wildcard filters when an application turns up
    /// that no filter knows yet.
    pub fn handle(&self) -> Option<SyncSender<WorkItem>> {
        self.sender.clone()
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
fn handle_work(engine: Option<&crate::wfp::Engine>, work: StoreWork) -> Result<StoreOutcome> {
    let Some(engine) = engine else {
        return Ok(StoreOutcome::refused(
            InventorySummary::default(),
            "no engine handle",
        ));
    };

    let (_removed, _installed, result) = match work {
        StoreWork::Apply { rules, known } => {
            let result = engine
                .apply(&rules, &known)
                .map(|applied| (applied.removed, applied.installed));

            (0, 0, result)
        }
        StoreWork::Clear => {
            let result = engine.clear().map(|removed| (removed, 0));

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
            ("GET", "/api/state") => {
                let outcome = worker.ask(StoreWork::Inventory)?;

                let state_json = StateJson::new(state, &outcome);

                Response::json(200, &state_json)
            }
            ("POST", "/api/rules") => {
                let rules: RuleFile = serde_json::from_slice(&request.body)
                    .context("body must be a rule file object")?;

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

                let outcome = worker.ask(StoreWork::Apply {
                    rules,
                    known: state.detector.apps(),
                })?;
                let state_json = StateJson::new(state, &outcome);

                Response::json(200, &state_json)
            }
            ("POST", "/api/detected") => {
                let decision: Decision = serde_json::from_slice(&request.body)
                    .context("body must be a detected decision object")?;

                let pattern = decision.pattern.unwrap_or_else(|| {
                    // No edited pattern given: the drive form of what the firewall reported.
                    crate::device::to_dos_path(&decision.app)
                });

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

                    current.rule.push(Rule {
                        name,
                        action: decision.action,
                        pattern,
                        enabled: true,
                    });

                    current
                        .save(&state.rules_path())
                        .context("write the rules file")?;
                    current.clone()
                };

                let outcome = worker.ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
                })?;

                // Only after the store accepted the rule: a refused write leaves the entry on the
                // list so the user can try again.
                if outcome.ok {
                    state.detector.dismiss(&decision.app)?;
                }

                Response::json(200, &StateJson::new(state, &outcome))
            }
            ("POST", "/api/detected/dismiss") => {
                let body: Dismissal = serde_json::from_slice(&request.body)
                    .context("body must be a dismissal object")?;

                let removed = state.detector.dismiss(&body.app)?;

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
                let body: ShareIndex =
                    serde_json::from_slice(&request.body).context("body must name a rule index")?;
                let rules = state.rules.lock().expect("rules lock poisoned").clone();

                let Some(rule) = rules.rule.get(body.index) else {
                    bail!("there is no rule at index {}", body.index);
                };

                Ok(Response::text(200, export::encode(rule)?))
            }
            ("POST", "/api/rules/import") => {
                let body: Share = serde_json::from_slice(&request.body)
                    .context("body must carry a share string")?;
                let incoming = export::decode(&body.share)?;

                let applied = {
                    let mut current = state.rules.lock().expect("rules lock poisoned");

                    // Appended rather than merged: an import must never replace something the user
                    // already has, whatever the Base64 string came from.
                    current.rule.push(incoming);
                    current
                        .save(&state.rules_path())
                        .context("write the rules file")?;
                    current.clone()
                };

                let outcome = worker.ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
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
            ("POST", "/api/profiles/switch") => {
                let body: ProfileSwitch = parse_or_default(&request.body)?;
                let outcome = switch_profile(state, worker, &body.name)?;

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
/// The schema is deliberately loose: every argument is optional, and a tool that needs one says so
/// in its refusal rather than letting the transport reject a call it could have answered.
fn tool_list() -> Vec<serde_json::Value> {
    [
        (
            "status",
            "settings, the rule count, the store, and how much the endpoint may write",
        ),
        (
            "rules.list",
            "every rule, in the order the firewall reads it",
        ),
        ("rules.share", "one rule as a Base64 string; takes an index"),
        (
            "rules.allow",
            "append an allow rule; takes app, pattern, name",
        ),
        ("rules.deny", "append a deny rule; takes app, pattern, name"),
        (
            "detected.list",
            "the applications learning mode collected, newest first",
        ),
        (
            "events.list",
            "the connections the firewall reported recently",
        ),
        ("export", "copy the data files into export\\; takes an area"),
        (
            "profiles.list",
            "the active profile and the names of the stored profiles",
        ),
        (
            "profile.use",
            "switch the live profile; takes a name (empty selects rules.toml)",
        ),
        (
            "shutdown",
            "stop the process; the filters stay in the firewall",
        ),
    ]
    .into_iter()
    .map(|(name, description)| {
        serde_json::json!({
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {
                    "index": { "type": "integer" },
                    "app": { "type": "string" },
                    "pattern": { "type": "string" },
                    "name": { "type": "string" },
                    "area": {
                        "type": "string",
                        "enum": ["rules", "config", "detected", "all"],
                    },
                },
            },
        })
    })
    .collect()
}

/// The method behind a `tools/call`, with the code and message of a protocol error.
type ToolError = (i32, String);

/// Run one MCP tool.
///
/// Reads are always allowed. A write depends on `Settings.mcp_writes`, which is checked here rather
/// than in the transport, so a second transport cannot talk its way past the policy (PLAN.md
/// section 10).
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
                "learn_mode": state.settings.learn_mode,
                "mcp_writes": state.settings.mcp_writes,
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
        name @ ("rules.allow" | "rules.deny") => {
            let action = if name == "rules.deny" {
                Action::Deny
            } else {
                Action::Allow
            };

            if state.settings.mcp_writes == Writes::None {
                return Ok(mcp::tool_refusal(format!(
                    "{name} refused: mcp_writes is none"
                )));
            }

            let app = call
                .string_arg("app")
                .or_else(|| call.string_arg("pattern"))
                .ok_or((mcp::INVALID_PARAMS, format!("{name} needs an app")))?;

            // The pattern defaults to the application itself, which is the narrowest rule an agent
            // can ask for; widening it to a wildcard stays a human decision in the browser.
            let pattern = call.string_arg("pattern").unwrap_or_else(|| app.clone());

            let name = call
                .string_arg("name")
                .filter(|name| !name.trim().is_empty())
                .unwrap_or_else(|| app.rsplit(['\\', '/']).next().unwrap_or("agent").to_owned());

            let applied = {
                let mut current = state.rules.lock().expect("rules lock poisoned");

                current.rule.push(Rule {
                    name: name.clone(),
                    action,
                    pattern,
                    enabled: true,
                });
                current
                    .save(&state.rules_path())
                    .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;
                current.clone()
            };

            let outcome = worker
                .ask(StoreWork::Apply {
                    rules: applied,
                    known: state.detector.apps(),
                })
                .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;

            Ok(mcp::tool_json(serde_json::json!({
                "added": { "name": name, "action": action, "app": app },
                "installed": outcome.installed,
                "store": outcome.ok,
            })))
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
        "profile.use" => {
            // A profile switch rewrites the settings as well as the rules, so it needs the widest
            // write permission rather than the `rules` one.
            if state.settings.mcp_writes != Writes::All {
                return Ok(mcp::tool_refusal(
                    "profile.use refused: mcp_writes is not all",
                ));
            }

            let name = call.string_arg("name").unwrap_or_default();
            let outcome = switch_profile(state, worker, &name)
                .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;

            Ok(mcp::tool_json(serde_json::json!({
                "active": state.active_name(),
                "installed": outcome.installed,
                "store": outcome.ok,
            })))
        }
        "export" => {
            let area = match call.string_arg("area") {
                Some(text) => serde_json::from_value::<Area>(serde_json::Value::String(text))
                    .map_err(|error| (mcp::INVALID_PARAMS, format!("bad area: {error}")))?,
                None => Area::All,
            };

            let report = export::run(&state.paths, area)
                .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;

            Ok(mcp::tool_json(
                serde_json::to_value(report).map_err(|error| (mcp::REFUSED, error.to_string()))?,
            ))
        }
        "shutdown" => {
            // Stopping is gated as a write, because a process that ends at the wrong moment
            // surprises an agent more than a rule it has to redo does.
            if state.settings.mcp_writes == Writes::None {
                return Ok(mcp::tool_refusal("shutdown refused: mcp_writes is none"));
            }

            Ok(mcp::tool_json(serde_json::json!({
                "stopping": state.request_stop(),
            })))
        }
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
    log_level: String,
    profile: String,
    rules: RuleFile,
    store: StoreOutcome,
    /// The newest events first, so the panel shows the interesting end even when it is truncated.
    events: Vec<NetEvent>,
    /// The applications waiting for a decision, newest first.
    detected: Vec<Detected>,
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
            learn_mode: state.settings.learn_mode,
            log_level: state.settings.log_level.clone(),
            profile: state.active_name(),
            rules,
            store: store.clone(),
            events,
            detected,
        }
    }
}

/// The body of `POST /api/detected`: what to do with one detected application.
#[derive(Debug, Clone, Deserialize)]
struct Decision {
    /// The application in device form, which is the identity of the detected entry.
    app: String,
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

/// The body of `POST /api/profiles/switch`: which profile to make live. An empty name selects
/// `rules.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
struct ProfileSwitch {
    #[serde(default)]
    name: String,
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

    worker.ask(StoreWork::Apply {
        rules: incoming,
        known: state.detector.apps(),
    })
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

    Ok(serde_json::from_slice(body).context("body must be a JSON object")?)
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

    // Headers are read to the blank line; only content-length matters, and it is read here so a
    // POST body does not stay in the socket buffer.
    let mut content_length = 0usize;

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
    }

    let mut body = vec![0u8; content_length];

    if content_length > 0 {
        reader.read_exact(&mut body).context("read request body")?;
    }

    let path = target.split('?').next().unwrap_or(target).to_owned();
    let request = Request::new(method, &path, body);

    debug!(method = %request.method, path = %request.path, "request");

    if request.path == "/api/events" {
        return stream_events(&mut stream, &state.events);
    }

    let response = Server::route(&state, &worker, &request)
        .unwrap_or_else(|error| Response::text(500, format!("{error:#}")));

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
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        _ => "500 Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    fn state() -> AppState {
        state_with(Arc::new(EventLog::new()))
    }

    fn state_with(events: Arc<EventLog>) -> AppState {
        let scratch = crate::testutil::scratch_dir("server");
        let paths = DataPaths::under(scratch.join("data"));

        paths.ensure().expect("create the data directories");

        let detector = Detector::load(&paths.learn).expect("load the detected list");

        let active_file = paths.rules.clone();

        AppState::new(
            paths,
            Settings::default(),
            Arc::new(Mutex::new(RuleFile {
                rule: vec![Rule {
                    name: "browser".to_owned(),
                    action: crate::rules::Action::Allow,
                    pattern: "C:\\Program Files\\*\\browser.exe".to_owned(),
                    enabled: true,
                }],
            })),
            Arc::new(detector),
            events,
            active_file,
            String::new(),
        )
    }

    fn connection(app: &str) -> crate::monitor::NetEvent {
        crate::monitor::NetEvent {
            seq: 0,
            time_ms: 0,
            app: app.to_owned(),
            remote_port: 443,
            protocol: 6,
            allowed: true,
            kind: "allowed".to_owned(),
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
        assert!(
            !server_state
                .detector
                .snapshot()
                .iter()
                .any(|entry| entry.app.contains("thing.exe")),
            "the decided application left the detected list",
        );

        let written = std::fs::read_to_string(&server_state.paths.rules).expect("rules.toml");

        assert!(
            written.contains("C:\\Windows\\System32\\thing.exe"),
            "the drive form is what the file holds: {written}"
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

    /// `tools/list` is what an agent reads before it acts, so a tool that exists must be in it:
    /// `shutdown` is reachable as a method only because `is_tool` finds it in this list.
    #[test]
    fn the_tool_list_offers_shutdown() {
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

        assert!(
            body.contains(r#""name":"shutdown""#),
            "a tool that is not listed cannot be discovered: {body}"
        );
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
            "the tool itself answered: {body}"
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

    /// The endpoint can be asked to stop as well, but only at a write level that permits it:
    /// `mcp_writes = none` is what keeps an agent from switching the tool off.
    #[test]
    fn the_mcp_shutdown_tool_stops_the_process() {
        let worker = WfpWorker::start();

        let mut allowed = state();
        allowed.settings.mcp_writes = Writes::All;

        let response = Server::route(
            &allowed,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"shutdown"}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);
        assert!(
            !allowed.running.load(Ordering::SeqCst),
            "the tool must clear the flag the accept loop waits on",
        );

        let refused = state();

        let response = Server::route(
            &refused,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":2,"method":"shutdown"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains("mcp_writes is none"),
            "the refusal must say why: {body}"
        );
        assert!(
            refused.running.load(Ordering::SeqCst),
            "a refused shutdown must leave the process running",
        );
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

    /// The state response carries the newest events first, so the panel renders in one request.
    #[test]
    fn the_state_endpoint_carries_recent_events() {
        let events = Arc::new(EventLog::new());
        events.push(connection("older.exe"));
        events.push(connection("newer.exe"));

        let server_state = state_with(Arc::clone(&events));
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

    /// The stream is not a buffered response, so it is exercised over a socket.
    #[test]
    fn the_event_stream_serves_headers_and_then_events() {
        let events = Arc::new(EventLog::new());
        let server = Server::bind(
            0,
            state_with(Arc::clone(&events)),
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
