//! The dispatcher and the bodies it reads: `Server::route` only distributes, every arm is
//! answered by a function of its own.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::export::{self, Area};
use crate::learn::Detected;
use crate::monitor::NetEvent;
use crate::rules::{Action, Remote, Rule, RuleFile, validate_comment, validate_pattern};

use super::http::{Request, Response, parse_body, parse_or_default};
use super::mcp_tools::mcp_endpoint;
use super::profiles::{create_profile, delete_profile, rename_profile, switch_profile};
use super::settings::{SettingsEdit, apply_settings};
use super::state::{AppState, Startup};
use super::worker::{StoreOutcome, StoreWork, WfpWorker};
use super::{FAVICON_ICO, INDEX_HTML, STATE_DETECTED, STATE_EVENTS, Server};

impl Server {
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
            ("GET", "/api/state") => get_state(state, worker),
            ("POST", "/api/settings") => post_settings(state, worker, request),
            ("POST", "/api/rules") => post_rules(state, worker, request),
            ("POST", "/api/detected") => post_detected(state, worker, request),
            ("POST", "/api/detected/dismiss") => post_detected_dismiss(state, request),
            // `/api/events` is answered by `stream_events`, because a response that never ends
            // cannot be a buffered body.
            // Stopping is a flag rather than a signal: the main thread is parked in `accept`, and
            // only the accept loop itself can leave it.
            ("POST", "/api/shutdown") => post_shutdown(state),
            ("GET", "/api/health") => Ok(Response::text(200, "ok")),
            ("POST", "/api/clear") => post_clear(worker),
            ("POST", "/api/protection") => post_protection(state, worker, request),
            ("POST", "/api/export") => post_export(state, request),
            ("POST", "/api/rules/share") => post_rules_share(state, request),
            ("POST", "/api/rules/import") => post_rules_import(state, worker, request),
            ("POST", "/api/rules/replace") => post_rules_replace(state, worker, request),
            ("POST", "/api/rules/move") => post_rules_move(state, worker, request),
            ("POST", "/api/relaunch") => post_relaunch(state),
            ("GET", "/api/profiles") => get_profiles(state),
            ("POST", "/api/profiles/create") => post_profiles_create(state, worker, request),
            ("POST", "/api/profiles/delete") => post_profiles_delete(state, worker, request),
            ("POST", "/api/profiles/rename") => post_profiles_rename(state, worker, request),
            ("POST", "/api/profiles/switch") => post_profiles_switch(state, worker, request),
            ("POST", "/mcp") => mcp_endpoint(state, worker, request),
            _ => Ok(Response::text(404, "not found")),
        }
    }
}

/// What `/api/state` answers: the state together with a read of the store.
fn get_state(state: &AppState, worker: &WfpWorker) -> Result<Response> {
    let outcome = worker.ask(StoreWork::Inventory)?;

    let state_json = StateJson::new(state, &outcome);

    Response::json(200, &state_json)
}

/// What `POST /api/settings` answers: the state the settings change settled on.
fn post_settings(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let edit: SettingsEdit = parse_or_default(&request.body)?;

    let outcome = apply_settings(state, worker, edit)?;

    Response::json(200, &StateJson::new(state, &outcome))
}

/// What `POST /api/rules` answers: the state a replaced rule list settled on.
fn post_rules(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let incoming: Replacement = parse_body(&request.body, "a rule file object")?;

    for rule in &incoming.rule {
        validate_pattern(&rule.pattern).with_context(|| format!("rule '{}'", rule.name))?;

        if let Some(comment) = &rule.comment {
            validate_comment(comment).with_context(|| format!("rule '{}'", rule.name))?;
        }
    }

    if stale_generation(state, incoming.generation) {
        return generation_conflict(state, worker);
    }

    let rules = RuleFile {
        rule: incoming.rule,
    };

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

/// What `POST /api/detected` answers: the state a decided application settled on.
fn post_detected(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
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
                text.parse::<Remote>()
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

/// What `POST /api/detected/dismiss` answers: how many entries went away.
fn post_detected_dismiss(state: &AppState, request: &Request) -> Result<Response> {
    let body: Dismissal = parse_body(&request.body, "a dismissal object")?;

    let removed = state.detector.dismiss(&body.app, body.remote.as_deref())?;

    Response::json(200, &serde_json::json!({ "removed": removed }))
}

/// What `POST /api/shutdown` answers: whether this request was the one that stopped the loop.
fn post_shutdown(state: &AppState) -> Result<Response> {
    let stopping = state.request_stop();

    info!(first = stopping, "shutdown requested");

    Response::json(200, &serde_json::json!({ "stopping": stopping }))
}

/// What `POST /api/relaunch` answers: the stop of this process after the shell granted an
/// elevated start of it.
///
/// The elevated copy is a second `--serve` of the same executable, and it opens its own browser
/// through its own tray. Whoever answers this page afterwards is the new process, which is why
/// the answer is the same shape `POST /api/shutdown` gives.
fn post_relaunch(state: &AppState) -> Result<Response> {
    if crate::elevated::is_elevated() {
        bail!("the tool is already elevated");
    }

    crate::elevated::relaunch_elevated()?;

    let stopping = state.request_stop();

    info!(first = stopping, "relaunch requested");

    Response::json(200, &serde_json::json!({ "stopping": stopping }))
}

/// What `POST /api/clear` answers: the store's own report, and nothing else.
fn post_clear(worker: &WfpWorker) -> Result<Response> {
    let outcome = worker.ask(StoreWork::Clear)?;

    Response::json(200, &outcome)
}

/// What `POST /api/protection` answers: the state as the firewall settled on it.
///
/// The switch is the run-time pause PLAN.md section 1 promises, and it is the store that feels it:
/// paused means our filters are out of it, which leaves the machine on whatever the operating
/// system and any other firewall decide. Resuming rebuilds from the rules that are loaded, so a
/// rule edited while paused is installed by the resume rather than lost.
fn post_protection(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let body: Protection = parse_or_default(&request.body)?;
    let on = state.set_protection(body.enabled.unwrap_or_else(|| !state.protection()));

    let outcome = if on {
        let rules = state.rules.lock().expect("rules lock poisoned").clone();

        worker.ask(StoreWork::Apply {
            rules,
            known: state.detector.apps(),
            policy: state.policy(),
        })?
    } else {
        worker.ask(StoreWork::Clear)?
    };

    info!(protection = on, store = %outcome.describe(), "protection switched");

    Response::json(200, &StateJson::new(state, &outcome))
}

/// What `POST /api/export` answers: the report of the files that were copied.
fn post_export(state: &AppState, request: &Request) -> Result<Response> {
    // An empty body exports everything, which is what the button in the UI sends.
    let body: Backup = parse_or_default(&request.body)?;
    let report = export::run(
        &state.paths,
        body.area.unwrap_or(Area::All),
        &state.active_name(),
    )?;

    Response::json(200, &report)
}

/// What `POST /api/rules/share` answers: one rule as a Base64 string.
fn post_rules_share(state: &AppState, request: &Request) -> Result<Response> {
    let body: ShareIndex = parse_body(&request.body, "a rule index")?;
    let rules = state.rules.lock().expect("rules lock poisoned").clone();

    let Some(rule) = rules.rule.get(body.index) else {
        bail!("there is no rule at index {}", body.index);
    };

    Ok(Response::text(200, export::encode(rule)?))
}

/// What `POST /api/rules/import` answers: the state an appended rule settled on.
fn post_rules_import(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let body: Share = parse_body(&request.body, "a share string")?;
    let incoming = export::decode(&body.share)?;

    validate_pattern(&incoming.pattern)?;

    if let Some(comment) = &incoming.comment {
        validate_comment(comment)?;
    }

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

/// What `POST /api/rules/replace` answers: the state a whole file settled on.
fn post_rules_replace(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let body: Import = parse_body(&request.body, "the rules file text")?;

    if stale_generation(state, body.generation) {
        return generation_conflict(state, worker);
    }

    let incoming = RuleFile::from_text(&body.text)?;

    // Every pattern goes through the check a single rule goes through, because a file
    // that was edited by hand after an export has not been read by anything since.
    for rule in &incoming.rule {
        validate_pattern(&rule.pattern)?;

        if let Some(comment) = &rule.comment {
            validate_comment(comment)?;
        }
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

/// What `POST /api/rules/move` answers: the state a reordered rule list settled on.
///
/// Order is not cosmetic here: the file's order becomes the filter creation order, and the first
/// matching rule wins, so moving a rule can decide a connection that the old order decided the
/// other way. The store is rebuilt because a rebuild is the only way order reaches WFP.
fn post_rules_move(state: &AppState, worker: &WfpWorker, request: &Request) -> Result<Response> {
    let body: MoveRule = parse_body(&request.body, "a rule move object")?;

    if stale_generation(state, body.generation) {
        return generation_conflict(state, worker);
    }

    let applied = {
        let mut current = state.rules.lock().expect("rules lock poisoned");

        if body.index >= current.rule.len() || body.to >= current.rule.len() {
            bail!(
                "index {} to {} outside the {} rules",
                body.index,
                body.to,
                current.rule.len(),
            );
        }

        let rule = current.rule.remove(body.index);
        current.rule.insert(body.to, rule);

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

/// What `GET /api/profiles` answers: which profile is live and which names exist.
fn get_profiles(state: &AppState) -> Result<Response> {
    let body = serde_json::json!({
        "active": state.active_name(),
        "names": crate::rules::list_names(&state.paths.profiles),
    });

    Response::json(200, &body)
}

/// What `POST /api/profiles/create` answers: the state the new profile settled on.
fn post_profiles_create(
    state: &AppState,
    worker: &WfpWorker,
    request: &Request,
) -> Result<Response> {
    let body: ProfileSwitch = parse_or_default(&request.body)?;
    let outcome = create_profile(state, worker, &body.name)?;

    // A profile operation can move which file is the active one, and the notice on the
    // page has to compare against the file that is active afterwards.
    state.note_rules_written();

    Response::json(200, &StateJson::new(state, &outcome))
}

/// What `POST /api/profiles/delete` answers: the state the fallback settled on.
fn post_profiles_delete(
    state: &AppState,
    worker: &WfpWorker,
    request: &Request,
) -> Result<Response> {
    let body: ProfileSwitch = parse_or_default(&request.body)?;
    let outcome = delete_profile(state, worker, &body.name)?;

    // A profile operation can move which file is the active one, and the notice on the
    // page has to compare against the file that is active afterwards.
    state.note_rules_written();

    Response::json(200, &StateJson::new(state, &outcome))
}

/// What `POST /api/profiles/rename` answers: the state the renamed profile settled on.
fn post_profiles_rename(
    state: &AppState,
    worker: &WfpWorker,
    request: &Request,
) -> Result<Response> {
    let body: ProfileRename = parse_or_default(&request.body)?;
    let outcome = rename_profile(state, worker, &body.name, &body.new_name)?;

    // A profile operation can move which file is the active one, and the notice on the
    // page has to compare against the file that is active afterwards.
    state.note_rules_written();

    Response::json(200, &StateJson::new(state, &outcome))
}

/// What `POST /api/profiles/switch` answers: the state the switched-to profile settled on.
fn post_profiles_switch(
    state: &AppState,
    worker: &WfpWorker,
    request: &Request,
) -> Result<Response> {
    let body: ProfileSwitch = parse_or_default(&request.body)?;
    let outcome = switch_profile(state, worker, &body.name)?;

    // A profile operation can move which file is the active one, and the notice on the
    // page has to compare against the file that is active afterwards.
    state.note_rules_written();

    Response::json(200, &StateJson::new(state, &outcome))
}

/// The JSON body of `/api/state`.
#[derive(Debug, Clone, Serialize)]
struct StateJson {
    port: u16,
    learn_mode: bool,
    /// Whether our filters are in the store. False is a paused firewall rather than a broken one.
    protection: bool,
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
    /// The applications waiting for a decision, newest activity first.
    ///
    /// At most `STATE_DETECTED` of them, which is why the count below is answered separately.
    detected: Vec<Detected>,
    /// How many are waiting in all. Read off the list above it would stop at the cap, so a queue
    /// of forty would be reported as twenty and the page would claim the tab holds everything.
    detected_total: usize,
    /// Whether the feed behind the events is running, with how much it delivered.
    monitor: MonitorJson,
    /// What the rebuild at startup found, so the page can say what changed while it was closed.
    startup: Startup,
    /// Whether `rules.toml` on disk is not the file this process wrote.
    ///
    /// True for a hand edit made while the tool was closed as well as for one made a moment ago,
    /// and it clears when the tool writes the file again.
    rules_changed: bool,
    /// How often this run has written the rules file. A whole-list write that names a different
    /// generation is answered 409 rather than applied, which is what stops two open pages from
    /// overwriting each other silently.
    generation: u64,
    /// Whether the process runs with an elevated token. The page offers the relaunch button from
    /// this value rather than from whether the store opened, because the two fail for different
    /// reasons.
    elevated: bool,
    /// The rules whose wildcard pattern matches more applications than the cap allows, so the page
    /// can name the truncation rather than let the rule look like it matches everything.
    ///
    /// Rules within the cap are left out entirely; an empty list means nothing was cut.
    pattern_truncations: Vec<PatternTruncation>,
}

/// One rule whose wildcard pattern was held down by the cap.
#[derive(Debug, Clone, Serialize)]
struct PatternTruncation {
    /// The name of the rule as the user wrote it.
    name: String,
    /// The pattern in drive form, which is how the rule file and the page show it.
    pattern: String,
    /// How many applications this tool has seen under the pattern.
    matches: usize,
    /// How many of them get filters.
    installed: usize,
}

/// The monitor's state together with the count the log holds, so an empty list can be told apart
/// from a feed that was never open.
#[derive(Debug, Clone, Serialize)]
pub(super) struct MonitorJson {
    /// `starting`, `running`, `refused` or `stopped`.
    pub(super) state: &'static str,
    /// The code that refused the subscription, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) code: Option<String>,
    /// Events the callback handed over since the process started.
    pub(super) events: u64,
    /// Wall-clock milliseconds since the epoch of the last event, zero when none arrived.
    ///
    /// A running feed with a stale stamp is the case the count cannot tell apart from a quiet
    /// machine: the subscription stayed open but stopped delivering.
    pub(super) last_event_ms: u64,
}

impl StateJson {
    fn new(state: &AppState, store: &StoreOutcome) -> Self {
        let rules = state.rules.lock().expect("rules lock poisoned").clone();

        let mut events = state.events.snapshot();
        events.reverse();
        events.truncate(STATE_EVENTS);

        // Newest activity first, and the newest `STATE_DETECTED` of them are answered. The list on
        // disk is ordered by first sight and a refreshed entry keeps its place, so cutting it as it
        // stands answers the twenty oldest questions of a process that has been running for a week
        // and hides the one asking right now (§62.1). Rust's sort is stable, so entries sharing a
        // timestamp keep the order they were collected in.
        let mut detected = state.detector.snapshot();
        detected.sort_by_key(|entry| std::cmp::Reverse(entry.seen_ms));
        let detected_total = detected.len();
        detected.truncate(STATE_DETECTED);

        // Counting against the same seen list the worker expands against, so the number on the
        // page is the number the store was built from.
        let known = state.detector.apps();
        let pattern_truncations = rules
            .rule
            .iter()
            .filter_map(|rule| {
                let (matches, installed) = crate::wfp::pattern_reach(&rule.pattern, &known);
                (matches > installed).then(|| PatternTruncation {
                    name: rule.name.clone(),
                    pattern: rule.pattern.clone(),
                    matches,
                    installed,
                })
            })
            .collect();

        Self {
            port: state.settings.port,
            learn_mode: state.learn_mode(),
            protection: state.protection(),
            default_policy: state.policy().name(),
            volatile_filters: state.settings.volatile_filters,
            log_level: state.log_level(),
            theme: state.live.theme().name(),
            profile: state.active_name(),
            rules,
            store: store.clone(),
            events,
            detected,
            detected_total,
            monitor: state.monitor(),
            startup: state.startup.clone(),
            rules_changed: state.rules_changed_outside(),
            generation: state.rules_generation(),
            elevated: crate::elevated::is_elevated(),
            pattern_truncations,
        }
    }
}

/// Whether a whole-list write disagrees with the server about which version of the list it edits.
///
/// A write that names no generation is unconditional, which is what a client that does not know
/// about the counter sends.
fn stale_generation(state: &AppState, claimed: Option<u64>) -> bool {
    claimed.is_some_and(|generation| generation != state.rules_generation())
}

/// The answer to a whole-list write that named a generation the server has moved past: the state
/// as it is now, so the client can re-read and decide again. The store is asked rather than
/// assumed, because a conflict response should not be cheaper to look at than a normal one.
fn generation_conflict(state: &AppState, worker: &WfpWorker) -> Result<Response> {
    let outcome = worker.ask(StoreWork::Inventory)?;

    Response::json(409, &StateJson::new(state, &outcome))
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

/// The body of `POST /api/protection`: what protection should be. Absent means flip, which is what
/// the tray menu and the header on the page send.
#[derive(Debug, Clone, Default, Deserialize)]
struct Protection {
    #[serde(default)]
    enabled: Option<bool>,
}

/// The body of `POST /api/rules/share`: which rule to encode.
#[derive(Debug, Clone, Deserialize)]
struct ShareIndex {
    index: usize,
}

/// The body of `POST /api/rules/move`: which rule to move, where it lands, and — when the client
/// knows it — the generation the row was read from.
#[derive(Debug, Clone, Deserialize)]
struct MoveRule {
    index: usize,
    to: usize,
    #[serde(default)]
    generation: Option<u64>,
}

/// The body of `POST /api/rules`: the whole list and, when the client knows it, the generation it
/// read that list from.
///
/// This is not `RuleFile` itself: that type rejects unknown fields because `rules.toml` has no
/// generation to carry, so the counter belongs to the request rather than to the file.
#[derive(Debug, Clone, Deserialize)]
struct Replacement {
    #[serde(default)]
    rule: Vec<Rule>,
    #[serde(default)]
    generation: Option<u64>,
}

/// The body of `POST /api/rules/import`.
#[derive(Debug, Clone, Deserialize)]
struct Share {
    share: String,
}

/// The body of `POST /api/rules/replace`: a whole rules file, as text, and the optional generation
/// the restore was read against.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Import {
    text: String,
    #[serde(default)]
    generation: Option<u64>,
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use crate::monitor::EventLog;
    use crate::server::Live;
    use crate::server::testsupport::{TEST_TOKEN, connection, state, state_with};

    use super::*;

    /// Whether the store accepted the work a route just did. Only an accepted write takes an entry
    /// off the Detected list, and an unelevated run is refused by the store, which is a fact about
    /// the machine rather than about the code. The store tests cover the accepted case.
    fn store_accepted(body: &str) -> bool {
        json_str(body)
            .pointer("/store/ok")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// The JSON a route answered with.
    fn json(response: &Response) -> serde_json::Value {
        json_str(std::str::from_utf8(&response.body).expect("a state body is UTF-8"))
    }

    fn json_str(body: &str) -> serde_json::Value {
        serde_json::from_str(body).expect("a state body is JSON")
    }

    /// The pause PLAN.md section 1 promises is a route rather than a tray detail, so the flip has
    /// to be visible in the answer and in the state the process holds.
    #[test]
    fn the_protection_endpoint_flips_and_reports_what_it_became() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let post = |body: &str| {
            Server::route(
                &server_state,
                &worker,
                &Request::new("POST", "/api/protection", body.as_bytes().to_vec()),
            )
            .expect("route")
        };

        let paused = post("");

        assert_eq!(paused.status, 200);

        let body = json(&paused);

        assert_eq!(
            body["protection"], false,
            "an empty body means flip, and it started enforcing"
        );
        assert!(!server_state.protection());

        let resumed = post("");

        assert_eq!(json(&resumed)["protection"], true);
        assert!(server_state.protection());
    }

    /// An explicit value is not a flip: two requests that both ask for paused leave it paused,
    /// which is what lets the page and the menu ask for the same thing without arguing.
    #[test]
    fn the_protection_endpoint_takes_an_explicit_value() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        for _ in 0..2 {
            let response = Server::route(
                &server_state,
                &worker,
                &Request::new("POST", "/api/protection", br#"{"enabled":false}"#.to_vec()),
            )
            .expect("route");

            assert_eq!(json(&response)["protection"], false);
        }

        assert!(!server_state.protection());
    }

    /// The point of the switch living in the worker: saving a rule while paused must not be what
    /// resumes the firewall.
    #[test]
    fn a_rule_saved_while_paused_leaves_protection_paused() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/protection", br#"{"enabled":false}"#.to_vec()),
        )
        .expect("pause");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"browser","action":"allow","pattern":"C:\\Program Files\\*\\browser.exe","enabled":true}]}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);
        assert_eq!(
            json(&response)["protection"],
            false,
            "a save is not a resume"
        );
    }

    /// A decided application becomes an ordinary rule, leaves the detected list, and the rules
    /// file carries the new entry.
    #[test]
    fn a_detected_application_becomes_a_rule() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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

    /// The state is a read, and a read is answered to anyone on loopback. Were the token in its
    /// body, `curl` on the same machine could read the secret and then write whatever it liked,
    /// which is exactly the escape the fragment handoff is meant to close.
    #[test]
    fn the_state_endpoint_carries_no_session_token() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            !body.contains(TEST_TOKEN),
            "the secret is not in a body anyone may read: {body}",
        );
        assert!(
            !body.contains("\"token\""),
            "not even as a field named token: {body}",
        );
    }

    /// A save by the tool is not a change from outside, so the page must not be told otherwise.
    #[test]
    fn a_save_by_the_tool_leaves_no_notice() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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

    /// A rules file handed over whole replaces the list rather than adding to it, which is what
    /// turns an export into something a person can put back.
    #[test]
    fn a_whole_file_replaces_the_rule_list() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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

    /// A moved rule has to land in its new place in the answer and in the file, because the
    /// file's order is the order the filters get created in and the first match wins.
    #[test]
    fn a_moved_rule_is_written_in_its_new_place() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"one","action":"allow","pattern":"C:\\Tools\\one.exe","enabled":true},{"name":"two","action":"deny","pattern":"C:\\Tools\\two.exe","enabled":true}]}"#.to_vec(),
            ),
        )
        .expect("route");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/move", br#"{"index":1,"to":0}"#.to_vec()),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        let body = json(&response);

        assert_eq!(body["rules"]["rule"][0]["name"], "two", "the move reorders");
        assert_eq!(body["rules"]["rule"][1]["name"], "one", "the move reorders");

        let written =
            std::fs::read_to_string(server_state.rules_path()).expect("read the rules file");

        assert!(
            written.find("two").expect("the moved name is written")
                < written.find("one").expect("the other name is written"),
            "the new order has to survive a restart: {written}",
        );
    }

    /// A move that names a place the list does not have is refused, and the refusal leaves the
    /// order alone, so a typo in a request cannot shuffle the set by accident.
    #[test]
    fn a_move_outside_the_rule_list_is_refused() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let error = match Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/move", br#"{"index":0,"to":9}"#.to_vec()),
        ) {
            Ok(_) => panic!("a move past the end has to be refused"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("outside"),
            "the refusal has to name the problem: {error}",
        );
    }

    /// Two pages holding the same list: the one that writes second names the generation it read,
    /// finds the server has moved past it, and is refused rather than silently winning.
    #[test]
    fn a_write_naming_a_stale_generation_is_refused() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        // The first page writes without naming a generation, which is unconditional and moves
        // the server's counter past the zero a page loaded before it would name.
        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"first","action":"allow","pattern":"C:\\Tools\\first.exe","enabled":true}],"generation":0}"#.to_vec(),
            ),
        )
        .expect("route");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"second","action":"deny","pattern":"C:\\Tools\\second.exe","enabled":true}],"generation":0}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 409, "a stale write is a conflict");

        let body = json(&response);

        assert_eq!(
            body["rules"]["rule"][0]["name"], "first",
            "the refused write leaves the server's list on screen",
        );

        let written =
            std::fs::read_to_string(server_state.rules_path()).expect("read the rules file");

        assert!(
            written.contains("first") && !written.contains("second"),
            "a refused write must not reach the file: {written}",
        );
    }

    /// The same write naming the generation the server is on is applied, and the answer carries
    /// the moved counter so the page can write again.
    #[test]
    fn a_write_naming_the_current_generation_is_applied() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let first = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", Vec::new()),
        )
        .expect("route");

        let generation = json(&first)["generation"].as_u64().expect("a generation");

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules/move",
                serde_json::json!({ "index": 0, "to": 0, "generation": generation })
                    .to_string()
                    .into_bytes(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200, "a current write is applied");
        assert_eq!(
            json(&response)["generation"].as_u64(),
            Some(generation + 1),
            "a write moves the counter",
        );
    }

    /// An elevated process has nobody left to ask for elevation, and a route that spawned
    /// anyway would leave a second tray icon arguing with the first about one store.
    ///
    /// The unelevated answer cannot be tested without asking the operating system for a UAC
    /// dialog and leaving an elevated process behind, so it is not tested here.
    #[test]
    fn a_relaunch_when_already_elevated_is_refused() {
        if !crate::elevated::is_elevated() {
            return;
        }

        let server_state = state();

        let error = match Server::route(
            &server_state,
            &WfpWorker::start_enforcing(),
            &Request::new("POST", "/api/relaunch", Vec::new()),
        ) {
            Ok(_) => panic!("an elevated relaunch has nothing to ask for"),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("elevated"),
            "the refusal has to name the reason: {error}",
        );
    }

    /// A file this build cannot read is refused before the one on disk is touched, because the
    /// point of a restore is not to lose the set it was meant to fix.
    #[test]
    fn a_whole_file_that_cannot_be_read_leaves_the_rules_alone() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
    fn an_unknown_path_is_not_found() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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

    /// A rule narrowed by protocol, direction, port and remote address travels through the API,
    /// lands in `rules.toml`, and comes back in the state, which is what the four narrowing
    /// columns of the page rely on.
    #[test]
    fn a_narrowed_rule_travels_through_the_api() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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

    /// A span between two addresses is written over the API exactly like a network is, is stored
    /// in the file, and comes back as the text it was written as. A span across the families is
    /// refused there, because no layer of the store can match it.
    #[test]
    fn a_span_between_two_addresses_travels_through_the_api() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let accepted = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"remote":"10.0.0.1-10.0.0.9"}]}"#.to_vec(),
            ),
        )
        .expect("route the span");

        let body = String::from_utf8_lossy(&accepted.body).into_owned();

        assert!(
            body.contains(r#""remote":"10.0.0.1-10.0.0.9""#),
            "the span has to come back as it was written: {body}",
        );

        let written = std::fs::read_to_string(server_state.rules_path()).expect("read the rules");

        assert!(
            written.contains(r#"remote = "10.0.0.1-10.0.0.9""#),
            "the span has to survive a restart: {written}",
        );

        let refused = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/rules",
                br#"{"rule":[{"name":"ssh","action":"allow","pattern":"C:\\Tools\\ssh.exe","enabled":true,"remote":"10.0.0.1-::2"}]}"#.to_vec(),
            ),
        );

        assert!(refused.is_err(), "one span cannot cross the families");
    }

    /// A port the server cannot read is refused rather than read as no port, so a typo in the page
    /// cannot silently widen a rule to every port.
    #[test]
    fn the_rules_endpoint_refuses_a_port_it_cannot_read() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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

    #[test]
    fn the_state_endpoint_answers_with_the_loaded_rules() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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

    /// The Detected answer is ordered by the newest activity before it is cut, so a program that
    /// has been asking since before the cap was reached is not the one that disappears (§62.1).
    /// The list on disk is ordered by first sight and a refreshed entry keeps its place, which is
    /// what the answer must not follow.
    #[test]
    fn the_state_endpoint_answers_with_the_newest_detected_entries() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let rules = server_state
            .rules
            .lock()
            .expect("rules lock poisoned")
            .clone();

        // One entry more than the answer carries, collected oldest first, each asking at its own
        // second. A new entry goes in at the front, so the list is newest first as it stands and
        // the entry collected first sits at its end.
        for index in 0..=STATE_DETECTED {
            let mut event = connection(&format!("C:\\Tools\\tool{index}.exe"));
            event.time_ms = 1_000 + u64::try_from(index).expect("an index fits a u64") * 1_000;

            assert!(
                server_state.detector.observe(&event, &rules),
                "tool{index} is a new question"
            );
        }

        // The entry at the end of the list asks again much later. Refreshing it does not move it,
        // so cutting the list as it stands answers the 20 questions nobody is asking any more and
        // hides this one.
        let mut latest = connection("C:\\Tools\\tool0.exe");
        latest.time_ms = 100_000;

        assert!(
            !server_state.detector.observe(&latest, &rules),
            "a refreshed entry is not a new one"
        );

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = json(&response);

        assert_eq!(
            body.pointer("/detected_total")
                .and_then(serde_json::Value::as_u64),
            Some(21),
            "the badge counts the whole list: {body}"
        );

        let answered = body
            .pointer("/detected")
            .and_then(serde_json::Value::as_array)
            .expect("a detected array");

        assert_eq!(answered.len(), STATE_DETECTED, "the answer is cut");

        assert_eq!(
            answered[0]
                .pointer("/app")
                .and_then(serde_json::Value::as_str),
            Some("C:\\Tools\\tool0.exe"),
            "the newest question is answered rather than cut: {body}"
        );
    }

    /// An empty connection list has to come with the reason for being empty, which is what the
    /// monitor reports: a refused subscription is a supported state, and a page that hides it
    /// reads as a quiet machine.
    #[test]
    fn the_state_endpoint_reports_the_monitor_and_what_it_delivered() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
            added: vec!["new rule".to_owned()],
            changed: Vec::new(),
            gone: Vec::new(),
            reason: None,
            differs: true,
        };

        let worker = WfpWorker::start_enforcing();

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
        assert!(
            body.contains("\"added\":[\"new rule\"]"),
            "the rule the file gained: {body}"
        );
        assert!(body.contains("\"differs\":true"), "{body}");
    }

    /// A state that never went through a startup rebuild says so, rather than letting the page read
    /// two zeros as a store that was found empty.
    #[test]
    fn a_state_that_never_rebuilt_the_store_says_the_startup_was_not_measured() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        assert!(body.contains(r#""local_network":false"#), "{body}");
    }

    /// A destination on the local segment leaves the machine, so it is reported and marked rather
    /// than dropped; the marker is what the page's filter works on, and a client that hides the
    /// local network needs the same answer over MCP.
    #[test]
    fn the_state_endpoint_marks_a_connection_to_the_local_network() {
        let events = Arc::new(EventLog::new());

        let mut event = connection("printer.exe");
        event.remote_addr = "192.168.1.20".to_owned();
        event.local_network = true;
        events.push(event);

        let server_state = state_with(Arc::clone(&events), Live::default());
        let worker = WfpWorker::start_enforcing();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""remote_addr":"192.168.1.20""#), "{body}");
        assert!(body.contains(r#""local_network":true"#), "{body}");
    }

    /// A wildcard rule that matches more applications than the cap allows is reported in the state
    /// with both numbers, so the page can say what was left out instead of letting the rule look
    /// complete. A rule within the cap is not reported at all.
    #[test]
    fn the_state_reports_a_wildcard_pattern_cut_by_the_cap() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let body = || {
            let response = Server::route(
                &server_state,
                &worker,
                &Request::new("GET", "/api/state", vec![]),
            )
            .expect("route");

            json(&response)
        };

        assert_eq!(
            body()["pattern_truncations"],
            serde_json::json!([]),
            "nothing has been seen yet, so nothing is cut",
        );

        for index in 0..crate::wfp::MAX_WILDCARD_MATCHES + 1 {
            let app = crate::device::to_device_path(&format!(
                "C:\\Program Files\\app{index}\\browser.exe"
            ));

            server_state.detector.note_app(&app);
        }

        let truncations = body()["pattern_truncations"]
            .as_array()
            .expect("an array")
            .clone();

        assert_eq!(truncations.len(), 1, "the one wildcard rule is reported");
        assert_eq!(truncations[0]["name"], "browser", "the rule is named");
        assert_eq!(
            truncations[0]["matches"],
            crate::wfp::MAX_WILDCARD_MATCHES + 1,
            "the matches are counted past the cap",
        );
        assert_eq!(
            truncations[0]["installed"],
            crate::wfp::MAX_WILDCARD_MATCHES,
            "only the cap is installed",
        );
    }
}
