//! The settings body and what a change to it does: write `config.toml`, publish the parts that
//! take effect now, rebuild the store.

use anyhow::{Context, Result};
use serde::Deserialize;
use tracing::info;

use tracing_subscriber::EnvFilter;

use crate::config::{Policy, Theme};

use super::state::AppState;
use super::worker::{StoreOutcome, StoreWork, WfpWorker};

/// The body of `POST /api/settings`. Every field is optional and an absent field keeps its value,
/// so a client can flip one thing without having to know the rest.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SettingsEdit {
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
/// renders it and the page reloads the state after every settings change. `log_level` reaches the
/// running filter through the reload handle the state holds, so it takes effect at once as well.
/// Only `port` still waits for the next run, because the listener is already bound.
pub(super) fn apply_settings(
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

    // Whether this body named the level, which decides whether the filter gets swapped below. An
    // edit that says nothing about it must leave the filter alone, because the filter a process
    // started with may have come from `RUST_LOG` rather than from the file.
    let named_level = edit.log_level.is_some();

    if let Some(log_level) = edit.log_level {
        // Read it here rather than handing the text to `tracing` and hoping: a level the filter
        // cannot parse would be written to the file and then silently do nothing, which is the
        // failure this setting used to be content with.
        EnvFilter::try_new(&log_level).context("read the log level")?;

        next.log_level = log_level;
    }

    next.save(&state.paths.config)
        .context("write the settings file")?;

    state.live.set(next.learn_mode, next.default_policy);
    state.live.set_theme(next.theme);

    if named_level {
        state.set_log_level(&next.log_level);
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::testsupport::state;
    use crate::server::{Request, Server};

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

    /// The log level used to be the one setting a running process ignored, so the answer a client
    /// got back described the file rather than the process. It is reported as a live value now.
    #[test]
    fn a_log_level_change_is_answered_with_the_new_level() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/settings",
                br#"{"log_level": "debug"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(body.contains(r#""log_level":"debug""#), "{body}");

        let written =
            std::fs::read_to_string(server_state.paths.config.clone()).expect("read the config");

        assert!(
            written.contains(r#"log_level = "debug""#),
            "the level has to survive a restart too: {written}",
        );
    }

    /// A level the filter cannot read would be written to the file and then do nothing at all,
    /// which is exactly the silent behaviour this release set out to end, so it is refused on the
    /// way in instead.
    #[test]
    fn the_settings_endpoint_refuses_a_log_level_it_cannot_read() {
        let server_state = state();
        let worker = WfpWorker::start();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/settings",
                br#"{"log_level": "winfw_mcp=chatty"}"#.to_vec(),
            ),
        );

        assert!(
            response.is_err(),
            "a name that is not a level must not be accepted"
        );
        assert_eq!(
            server_state.log_level(),
            "info",
            "a refused level changes nothing"
        );
    }
}
