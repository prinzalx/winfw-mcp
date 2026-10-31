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
//! ## Threading
//!
//! A WFP transaction belongs to a thread rather than to a handle (see `wfp::Engine::transaction`),
//! so exactly one thread owns the engine handle: the WFP worker. Request threads hand their work
//! over a channel and wait for the reply, which is what makes the arrangement safe rather than
//! merely convenient.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tracing::{debug, info, warn};

use crate::config::Settings;
use crate::paths::DataPaths;
use crate::rules::RuleFile;

/// The page served at `/`, embedded so the binary stays a single file.
const INDEX_HTML: &str = include_str!("../web/index.html");

/// How long the accept loop blocks before it checks whether the process is shutting down.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// Everything a request handler may touch.
///
/// The rules are the in-memory copy that the request handlers keep authoritative: a change is
/// applied to this value, written to disk, and only then pushed to the store, which is the order
/// PLAN.md section 2 asks for.
pub struct AppState {
    paths: DataPaths,
    settings: Settings,
    rules: Mutex<RuleFile>,
}

impl AppState {
    pub fn new(paths: DataPaths, settings: Settings, rules: RuleFile) -> Self {
        Self {
            paths,
            settings,
            rules: Mutex::new(rules),
        }
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
    /// Rebuild the filters from these rules.
    Apply { rules: RuleFile },
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
}

/// The readable part of the store, summarized for the UI.
#[derive(Debug, Clone, Default, Serialize)]
struct InventorySummary {
    providers: Option<usize>,
    sublayers: Option<usize>,
    filters: Option<usize>,
}

/// One unit of work plus the channel its answer goes back on.
type WorkItem = (StoreWork, SyncSender<Result<StoreOutcome>>);

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
        StoreWork::Apply { rules } => {
            let result = engine
                .apply(&rules)
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
        let addr = SocketAddr::from(([127, 0, 0, 1], port));

        let listener = TcpListener::bind(addr).with_context(|| format!("bind {addr} failed"))?;
        listener
            .set_nonblocking(true)
            .context("could not switch the listener to non-blocking")?;

        let bound = listener.local_addr().context("local_addr failed")?;

        Ok(Self {
            listener,
            addr: bound,
            state: Arc::new(state),
            worker,
        })
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

        loop {
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
                    .save(&state.paths.rules)
                    .context("write rules.toml")?;

                let outcome = worker.ask(StoreWork::Apply { rules })?;
                let state_json = StateJson::new(state, &outcome);

                Response::json(200, &state_json)
            }
            ("GET", "/api/health") => Ok(Response::text(200, "ok")),
            ("POST", "/api/clear") => {
                let outcome = worker.ask(StoreWork::Clear)?;

                Response::json(200, &outcome)
            }
            _ => Ok(Response::text(404, "not found")),
        }
    }
}

/// The JSON body of `/api/state`.
#[derive(Debug, Clone, Serialize)]
struct StateJson {
    port: u16,
    learn_mode: bool,
    log_level: String,
    rules: RuleFile,
    store: StoreOutcome,
}

impl StateJson {
    fn new(state: &AppState, store: &StoreOutcome) -> Self {
        let rules = state.rules.lock().expect("rules lock poisoned").clone();

        Self {
            port: state.settings.port,
            learn_mode: state.settings.learn_mode,
            log_level: state.settings.log_level.clone(),
            rules,
            store: store.clone(),
        }
    }
}

/// Read one request, write one response.
fn handle_connection(
    stream: TcpStream,
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
        let scratch = crate::testutil::scratch_dir("server");
        let paths = DataPaths::under(scratch.join("data"));

        AppState::new(
            paths,
            Settings::default(),
            RuleFile {
                rule: vec![Rule {
                    name: "browser".to_owned(),
                    action: crate::rules::Action::Allow,
                    pattern: "C:\\Program Files\\*\\browser.exe".to_owned(),
                    enabled: true,
                }],
            },
        )
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
}
