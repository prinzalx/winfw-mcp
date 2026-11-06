//! The web server: a tiny HTTP/1.1 implementation on top of `std`.
//!
//! Plan section 6 suggested axum and tokio, to be confirmed at implementation time. The
//! confirmation is that they are not needed: every interesting call below ends in a blocking WFP
//! call, so an async runtime would only move the blocking into `spawn_blocking`. A thread per
//! connection with the standard library keeps the binary small, starts instantly, and gives
//! milestone 5 (SSE) exactly the long-lived connection it needs.
//!
//! `winfw-core` rule from plan section 6: the `server` modules are a transport. They read and
//! write the files and forward store work to the WFP worker, but decide nothing about the
//! firewall.
//!
//! ## Routes
//!
//! | method | path | purpose |
//! |---|---|---|
//! | GET | `/` | the single-page UI |
//! | GET | `/favicon.ico` | the tab icon, from the same file the executable's resources use |
//! | GET | `/api/state` | settings, rules, store summary, recent events |
//! | GET | `/api/events` | the event log as a server-sent event stream |
//! | GET | `/api/reverse?ip=<address>` | the name the DNS client cache or the reverse lookup answers for one address, cached for the life of the process |
//! | GET | `/api/health` | liveness, no state involved |
//! | GET | `/api/profiles` | the active profile and the names of the stored profiles |
//! | POST | `/api/settings` | write learn mode, the default policy, the theme or the log level to `config.toml` |
//! | POST | `/api/rules` | replace the rules, write the file, rebuild the store |
//! | POST | `/api/detected` | turn a detected application into a rule and rebuild the store |
//! | POST | `/api/detected/dismiss` | drop a detected application without allowing it |
//! | POST | `/api/clear` | remove our filters from the store |
//! | POST | `/api/protection` | pause or resume protection: a rebuild while it is paused clears instead |
//! | POST | `/api/shutdown` | stop the server and leave the installed filters in place |
//! | POST | `/api/quit` | take our filters out of the store, then stop the process |
//! | POST | `/api/export` | copy rules, config, the Detected list and the profiles into `export\` |
//! | POST | `/api/rules/share` | one rule as a Base64 string, for copy and paste |
//! | POST | `/api/rules/import` | append the rule a Base64 string carries |
//! | POST | `/api/rules/replace` | replace the rules with a whole file's text, the restore half of an export |
//! | POST | `/api/rules/move` | move one rule to another position: order decides which rule wins |
//! | POST | `/api/relaunch` | ask the shell for an elevated start and stop this process |
//! | POST | `/api/profiles/switch` | make another profile, or the default rules, the live one |
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

mod guard;
mod http;
mod mcp_tools;
mod profiles;
mod routes;
mod settings;
mod state;
mod temporary;
mod worker;

pub use guard::session_token;
pub use http::{Headers, Request, Response};
pub use state::{AppState, Live, Startup};
pub use worker::WfpWorker;

// `StoreOutcome` is re-exported only so that the path `server::StoreOutcome` keeps working for a
// caller added later; nothing in the crate uses it from outside this module today.
#[allow(unused_imports)]
pub(crate) use worker::{StoreOutcome, StoreWork, WorkItem};

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use guard::guard;
use http::respond;

use crate::monitor::EventLog;

/// The page served at `/`, embedded so the binary stays a single file.
const INDEX_HTML: &str = include_str!("../../web/index.html");

/// The icon for the browser tab: the same file `build.rs` compiles into the executable's resources,
/// so the tray, the shell and the tab all show one logo from one source.
const FAVICON_ICO: &[u8] = include_bytes!("../../assets/winfw-mcp.ico");

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

/// How long the sweep of the temporary rules waits between two looks at the running programs.
///
/// The question a temporary rule asks is "is its program still running?", and a process that quit
/// does not announce itself to us. A poll is enough: the rule goes out within this interval of the
/// program leaving, and a poll costs nothing when there is no temporary rule at all.
const SWEEP_POLL: Duration = Duration::from_secs(5);

/// How many recent events `/api/state` carries, enough for the panel to render without a second
/// request.
const STATE_EVENTS: usize = 50;

/// How many detected applications `/api/state` carries: the whole Detected list, which is capped at
/// the same number on disk. Twenty meant a queue of forty asked the page to decide on twenty and
/// the rest was invisible with no way to reach it (§62.1).
const STATE_DETECTED: usize = crate::learn::DETECTED_CAP;

/// The server itself: a listener, the shared state and the worker.
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    state: Arc<AppState>,
    worker: Arc<WfpWorker>,
}

impl Server {
    /// Bind `127.0.0.1:{port}`. Port 0 is allowed and resolves to an ephemeral port, which is what
    /// the tests use.
    pub fn bind(port: u16, state: AppState, worker: Arc<WfpWorker>) -> Result<Self> {
        // A conflict on the configured port must not kill the tray app (plan section 9), so a
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

        // The temporary rules are retired on a poll, taken here because this loop is what the
        // process does while it is idle. A connection that arrives during a sweep waits out the
        // sweep rather than the other way round: one is milliseconds, the other is a page that
        // asked for a firewall change.
        let mut next_sweep = Instant::now() + SWEEP_POLL;

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

                    if Instant::now() >= next_sweep {
                        next_sweep += SWEEP_POLL;

                        if let Err(error) = temporary::sweep(&self.state, &self.worker) {
                            warn!(
                                reason = %format!("{error:#}"),
                                "could not retire the temporary rules",
                            );
                        }
                    }
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

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let request = Request::with_headers(method, path, query, body, Headers::from_pairs(&fields));

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

/// The helpers every module of this one shares: the state a route is tested against, and the
/// connection that fills its event log.
#[cfg(test)]
pub(crate) mod testsupport {
    use super::{AppState, Live, Startup};
    use crate::config::Settings;
    use crate::learn::Detector;
    use crate::monitor::EventLog;
    use crate::paths::DataPaths;
    use crate::rules::{Rule, RuleFile};
    use std::sync::{Arc, Mutex};

    /// The token the test states hand out, so a test can write the header a browser would write.
    pub(crate) const TEST_TOKEN: &str = "test-token";

    pub(crate) fn state() -> AppState {
        state_with(Arc::new(EventLog::new()), Live::default())
    }

    pub(crate) fn state_with(events: Arc<EventLog>, live: Live) -> AppState {
        let scratch = crate::testutil::scratch_dir("server");
        let paths = DataPaths::under(scratch.join("data"));

        paths.ensure().expect("create the data directories");

        let detector = Detector::load(&paths.learn, "").expect("load the detected list");

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
            // A test state installs no subscriber, so there is no filter to swap.
            None,
        )
    }

    pub(crate) fn connection(app: &str) -> crate::monitor::NetEvent {
        crate::monitor::NetEvent {
            seq: 0,
            time_ms: 0,
            display: app.to_owned(),
            app: app.to_owned(),
            user: None,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::testsupport::{connection, state, state_with};

    /// The stream is not a buffered response, so it is exercised over a socket.
    #[test]
    fn the_event_stream_serves_headers_and_then_events() {
        let events = Arc::new(EventLog::new());
        let server = Server::bind(
            0,
            state_with(Arc::clone(&events), Live::default()),
            Arc::new(WfpWorker::start_enforcing()),
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
        let server =
            Server::bind(0, state(), Arc::new(WfpWorker::start_enforcing())).expect("bind");
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

        let server =
            Server::bind(port, state(), Arc::new(WfpWorker::start_enforcing())).expect("bind");
        let bound = server.addr().port();

        assert_ne!(bound, port, "the busy port cannot be taken twice");
        assert!(
            bound > port && bound < port + PORT_ATTEMPTS,
            "fell forward to {bound} from a busy {port}"
        );
    }

    /// The token reaches the page in the fragment of the URL and in no answer body, so the page has
    /// to read it out of the fragment and take it out of the address again. Were either of the two
    /// missing, the write right would be lost the moment the tray URL is opened.
    #[test]
    fn the_page_reads_the_token_from_the_fragment_and_hides_it_again() {
        assert!(
            INDEX_HTML.contains("window.location.hash"),
            "the page has to read the fragment it is opened on",
        );
        assert!(
            INDEX_HTML.contains("history.replaceState"),
            "and take it out of the address again",
        );
        assert!(
            !INDEX_HTML.contains("state.token"),
            "it must not read a token out of the state body any more",
        );
    }

    #[test]
    fn the_page_names_the_default_policy_in_the_header() {
        assert!(
            INDEX_HTML.contains("id=\"policy-note\""),
            "the policy has to have a place of its own in the header, not only in the settings",
        );
        assert!(
            INDEX_HTML.contains("Programs without a rule are blocked"),
            "deny has to be explained in plain text",
        );
        assert!(
            INDEX_HTML.contains("they only appear in the Detected list"),
            "and allow has to be explained as well",
        );
        assert!(
            INDEX_HTML.contains("Unknown programs are blocked"),
            "an empty rules list under deny has to warn about it",
        );
    }

    /// `appendChild` answers with the child it inserted, not with the node it was called on, so
    /// building the target table of a connection through its return value left the table without a
    /// `tbody`, and the row that was looking for one took the whole state render with it (§62.4).
    /// The page stayed empty on every tab while the state behind it was full. The reconciler holds
    /// the body as `row.tbody` now, which is the same lesson in a new shape.
    #[test]
    fn the_connection_targets_keep_a_body_of_their_own() {
        assert!(
            INDEX_HTML.contains("row.tbody.insertBefore(tr"),
            "the target rows have to go into a body the script holds itself",
        );
        assert!(
            !INDEX_HTML.contains("querySelector(\"tbody\")"),
            "looking the body up again is what failed: the table never had one",
        );
    }

    /// A row that is assembled but never handed to its container is the quiet failure of a page
    /// built without a framework: the counters stay right, the panels stay empty, and the browser
    /// reports nothing at all. Every list that opens a container has to fill it (§62.4).
    #[test]
    fn every_list_appends_the_rows_it_builds() {
        let page = script_body(INDEX_HTML);

        for name in ["renderRules", "renderDetected"] {
            let from = page
                .find(&format!("function {name}()"))
                .unwrap_or_else(|| panic!("the page lost {name}()"));
            let rest = &page[from..];
            let end = rest.find("\n      }").unwrap_or(rest.len());

            assert!(
                rest[..end].contains("body.appendChild(row);"),
                "{name}() assembles rows but never hands one to its container"
            );
        }
    }

    /// A temporary rule has to be marked in the dialog, written back by the save, and shown in
    /// the table: a rule that quietly disappears when its program quits is only honest if the page
    /// said it was one.
    #[test]
    fn the_page_marks_temporary_rules() {
        assert!(
            INDEX_HTML.contains("id=\"rule-temporary\""),
            "the rule dialog has to offer the mark",
        );
        assert!(
            INDEX_HTML.contains("rule.temporary = el(\"rule-temporary\").checked"),
            "and the save has to write it back",
        );
        assert!(
            INDEX_HTML.contains("if (rule.temporary)"),
            "and the table has to show it",
        );
    }

    /// The element ids the page's script asks for by name.
    ///
    /// The script names an element in two ways: `el("id")` at the call site, and the
    /// `WRITE_CONTROLS` list it walks to enable or disable every write control. Both are read here.
    /// A name built at runtime is not, and the two places that do it pass a variable holding one of
    /// these names, which is why the list of what is asked for can be complete at all.
    fn element_ids(page: &str) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();

        let mut rest = page;
        while let Some(at) = rest.find("el(\"") {
            rest = &rest[at + 4..];

            let Some(end) = rest.find('\"') else {
                break;
            };

            ids.push(rest[..end].to_owned());
            rest = &rest[end..];
        }

        let list = page
            .find("const WRITE_CONTROLS = [")
            .map(|start| &page[start..])
            .and_then(|from| from.find("];").map(|end| &from[..end]))
            .expect("the write control list exists and is closed");

        ids.extend(list.split('\"').skip(1).step_by(2).map(str::to_owned));

        ids.sort();
        ids.dedup();
        ids
    }

    /// Nothing but a test can notice that the page's script asks for an element the markup does not
    /// hold, because the page is one embedded file with no build step and no parser in front of it.
    /// A script that stopped parsing shipped for twelve releases (§62.2), and a renamed id fails the
    /// same quiet way: the page renders, the button does nothing, and the suite passes.
    ///
    /// What this does not catch is the parse failure itself, only the disagreement between the two
    /// halves of the file.
    #[test]
    fn every_element_the_page_script_asks_for_exists() {
        let asked = element_ids(INDEX_HTML);

        assert!(
            asked.len() >= 40,
            "the scan found {asked:?}, which is too few to be the whole page"
        );

        for id in &asked {
            assert!(
                INDEX_HTML.contains(&format!("id=\"{id}\"")),
                "the script asks for #{id}, the markup does not declare it"
            );
        }
    }

    /// The text of the page's one script block, without the tags around it.
    fn script_body(page: &str) -> &str {
        let start = page
            .find("<script>")
            .expect("the page holds one script block")
            + "<script>".len();
        let rest = &page[start..];
        let end = rest.find("</script>").expect("the script block is closed");

        &rest[..end]
    }

    /// The first bracket of the script that does not match, if there is one.
    ///
    /// String literals, template literals and comments are skipped, which is all the scanner has to
    /// know: the page holds no regular expression literal, so a slash is always the start of a
    /// comment or nothing at all.
    fn bracket_error(script: &str) -> Option<char> {
        let chars: Vec<char> = script.chars().collect();
        let mut stack: Vec<char> = Vec::new();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                quote @ ('\'' | '"' | '`') => {
                    i += 1;

                    while i < chars.len() && chars[i] != quote {
                        i += 1 + usize::from(chars[i] == '\\');
                    }
                }
                '/' if i + 1 < chars.len() && chars[i + 1] == '/' => {
                    while i < chars.len() && chars[i] != '\n' {
                        i += 1;
                    }
                }
                '/' if i + 1 < chars.len() && chars[i + 1] == '*' => {
                    i += 2;

                    while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                        i += 1;
                    }

                    i += 1;
                }
                open @ ('{' | '(' | '[') => {
                    stack.push(open);
                }
                close @ ('}' | ')' | ']') => {
                    let open = match close {
                        '}' => '{',
                        ')' => '(',
                        _ => '[',
                    };

                    if stack.pop() != Some(open) {
                        return Some(close);
                    }
                }
                _ => {}
            }

            i += 1;
        }

        stack.pop().map(|open| match open {
            '{' => '}',
            '(' => ')',
            _ => ']',
        })
    }

    /// The page has no build step and no parser in front of it, so a script that stopped parsing
    /// renders its static HTML and does nothing else (§62.2). A JavaScript parser in the test target
    /// would be the strict answer and is not taken: it would be a dependency for one assertion.
    /// This is the cheap answer, and it catches the failure an edit actually produces, a block that
    /// is no longer closed. It does not catch a syntax error inside a balanced block.
    #[test]
    fn the_page_script_is_closed_and_its_brackets_balance() {
        let script = script_body(INDEX_HTML);

        assert!(
            script.len() > 20_000,
            "the scan found {script:.40}, which is too little to be the page's script"
        );

        assert!(
            script.contains("function renderConnections"),
            "the script block found is not the page's script"
        );

        assert_eq!(
            bracket_error(script),
            None,
            "a bracket in the page's script does not match"
        );

        // The two assertions below are what makes the scan worth having: an unclosed block is
        // noticed, and a bracket inside a string is not.
        assert_eq!(
            bracket_error("function f() { if (a) { b(); }"),
            Some('}'),
            "an unclosed block has to be reported"
        );

        assert_eq!(
            bracket_error("const s = \"({\"; // ) \nconst t = `a${b}c`;"),
            None,
            "a bracket in a string, a comment or a template has to be ignored"
        );
    }
}
