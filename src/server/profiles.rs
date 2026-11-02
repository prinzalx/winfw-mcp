//! The profile routes' work: moving which rules file is the live one, and what that does to the
//! store.

use anyhow::{Context, Result, bail};

use crate::rules::RuleFile;

use super::state::AppState;
use super::worker::{StoreOutcome, StoreWork, WfpWorker};

/// Persist the current rules, point the tool at another profile, and rebuild the store.
///
/// The rules being left are written back first, so a change made in the browser survives the
/// switch. An empty name selects `rules.toml`; any other name must be a single file stem, and its
/// file is created empty when it does not exist yet.
pub(super) fn switch_profile(
    state: &AppState,
    worker: &WfpWorker,
    name: &str,
) -> Result<StoreOutcome> {
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

    // The Detected list belongs to a profile the same way its rules do, so the live list moves
    // with the live rules. Events seen while another profile was live stay under its name.
    state.detector.set_profile(name)?;

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
pub(super) fn create_profile(
    state: &AppState,
    worker: &WfpWorker,
    name: &str,
) -> Result<StoreOutcome> {
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
pub(super) fn delete_profile(
    state: &AppState,
    worker: &WfpWorker,
    name: &str,
) -> Result<StoreOutcome> {
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

    // Its Detected list goes with it: entries waiting for a decision about rules of a profile
    // nobody can select again would only be collected noise.
    state.detector.drop_profile(name)?;

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
pub(super) fn rename_profile(
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

    state.detector.rename_profile(name, new_name)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::testsupport::state;
    use crate::server::{Request, Server};

    /// Switching to a new profile keeps the rules we had in the file they came from, points the
    /// tool at the new (empty) file, and lists the new profile as the active one.
    #[test]
    fn switching_profile_moves_the_live_rules_to_a_new_file() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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

    /// A Detected entry asks a question about the rules that are live, so switching profiles
    /// switches the list: an entry collected under one profile is not reported while another one
    /// answers, and it is back when the first profile is live again.
    #[test]
    fn the_detected_list_follows_the_profile() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        server_state.detector.observe(
            &crate::monitor::NetEvent {
                remote_addr: String::new(),
                ..crate::server::testsupport::connection("\\device\\harddiskvolume3\\a.exe")
            },
            &RuleFile::default(),
        );

        Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/api/profiles/switch",
                br#"{"name":"work"}"#.to_vec(),
            ),
        )
        .expect("switch");

        let listed = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("list");
        let body = String::from_utf8_lossy(&listed.body).into_owned();

        assert!(
            !body.contains("a.exe"),
            "the other profile's entry is not reported: {body}",
        );

        Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/profiles/switch", br#"{"name":""}"#.to_vec()),
        )
        .expect("switch back");

        let listed = Server::route(
            &server_state,
            &worker,
            &Request::new("GET", "/api/state", vec![]),
        )
        .expect("list again");
        let body = String::from_utf8_lossy(&listed.body).into_owned();

        assert!(
            body.contains("a.exe"),
            "the entry is where it was left: {body}",
        );
    }

    /// Deleting the live profile falls back to `rules.toml` and takes the file with it, so the data
    /// directory does not fill up with profiles nobody can select.
    #[test]
    fn deleting_the_live_profile_falls_back_to_the_default_rules() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
        let worker = WfpWorker::start_enforcing();

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
}
