//! The temporary rules and the poll that retires them.
//!
//! A temporary rule is one the person meant for a single run of one program. Nothing announces a
//! program leaving — the firewall's own event stream speaks about connections, not about
//! processes — so the answer is a look at the running processes on a poll, taken where the server
//! is idle anyway: the accept loop calls [`sweep`] once its interval has passed.
//!
//! The same look covers a program that left while the tool was stopped: the first sweep of a run
//! retires a temporary rule whose program never came back.

use anyhow::{Context, Result};

use super::state::AppState;
use super::worker::{StoreWork, WfpWorker};

/// Retire the temporary rules whose program is no longer running.
///
/// Returns the names it removed, which is also how a test tells "nothing to do" from "one rule
/// gone". A process list the system cannot hand over means no answer rather than an empty one:
/// on a build without the snapshot there is nothing to say about any program, and removing every
/// temporary rule on that account would be a confident way to be wrong.
pub(super) fn sweep(state: &AppState, worker: &WfpWorker) -> Result<Vec<String>> {
    let Some(running) = crate::processes::image_paths() else {
        return Ok(Vec::new());
    };

    // The lock is only taken for the question, and the answer for a list without a temporary rule
    // is known before the file or the store are touched at all.
    let mut current = state.rules.lock().expect("rules lock poisoned");

    if !current.rule.iter().any(|rule| rule.temporary) {
        return Ok(Vec::new());
    }

    let gone = crate::rules::prune_temporary(&mut current, &running);

    if gone.is_empty() {
        return Ok(Vec::new());
    }

    // File first, then store, as every other write does: a store that refuses us must not lose
    // the removal, because the next run would put the rule back.
    current
        .save(&state.rules_path())
        .context("write the rules file")?;
    state.note_rules_written();

    let applied = current.clone();
    drop(current);

    let outcome = worker.ask(StoreWork::Apply {
        rules: applied,
        known: state.detector.apps(),
        policy: state.policy(),
    })?;

    tracing::info!(
        removed = %gone.join(", "),
        store = %outcome.describe(),
        "temporary rules retired",
    );

    Ok(gone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Action, Rule, RuleFile};
    use crate::server::WfpWorker;
    use crate::server::testsupport::state;
    use crate::testutil;

    /// A temporary rule for the test binary itself, which is running while the test runs.
    fn this_program(name: &str) -> Rule {
        let path = std::env::current_exe().expect("the test binary knows itself");
        let text = path.to_string_lossy().replace('/', "\\");

        let mut rule = Rule::plain(name, Action::Allow, text);
        rule.temporary = true;

        rule
    }

    fn with_rules(rules: Vec<Rule>) -> crate::server::AppState {
        let state = state();

        *state.rules.lock().expect("rules lock poisoned") = RuleFile { rule: rules };

        state
    }

    /// The rule of a program that is running is kept, and a temporary rule of one that is not is
    /// gone within one sweep of the real process list.
    #[test]
    fn a_temporary_rule_outlives_its_program_by_one_poll() {
        let worker = WfpWorker::start_enforcing();
        let state = with_rules(vec![this_program("still running"), {
            let mut rule = Rule::plain("gone", Action::Allow, "C:\\test\\long-departed-tool.exe");
            rule.temporary = true;

            rule
        }]);

        let removed = sweep(&state, &worker).expect("sweep");

        assert_eq!(
            removed,
            ["gone".to_owned()],
            "only the rule whose program is not running should go",
        );

        let kept = state.rules.lock().expect("rules lock poisoned").clone();

        assert_eq!(kept.rule.len(), 1);
        assert_eq!(kept.rule[0].name, "still running");
    }

    /// A rule that is not temporary is never retired by this poll, whatever the process list says.
    #[test]
    fn a_permanent_rule_is_not_retired() {
        let worker = WfpWorker::start_enforcing();
        let state = with_rules(vec![Rule::plain(
            "keeper",
            Action::Deny,
            "C:\\test\\long-departed-tool.exe",
        )]);

        assert!(sweep(&state, &worker).expect("sweep").is_empty());

        let kept = state.rules.lock().expect("rules lock poisoned");

        assert_eq!(kept.rule.len(), 1);
    }

    /// The removal reaches the file: a sweep that only changed the memory copy would put the rule
    /// back on the next start.
    #[test]
    fn a_retired_rule_is_gone_from_the_file() {
        let worker = WfpWorker::start_enforcing();
        let scratch = testutil::scratch_dir("temporary-file");
        let file = scratch.join("rules.toml");
        let mut state = state();

        state.active_file = std::sync::Mutex::new(file.clone());

        {
            let mut current = state.rules.lock().expect("rules lock poisoned");
            let mut rule = Rule::plain("gone", Action::Allow, "C:\\test\\long-departed-tool.exe");
            rule.temporary = true;
            current.rule.push(rule);
            current.save(&file).expect("write the file");
        }

        let removed = sweep(&state, &worker).expect("sweep");

        assert_eq!(removed, ["gone".to_owned()]);

        let text = std::fs::read_to_string(&file).expect("the file is there");

        assert!(
            !text.contains("long-departed-tool"),
            "the retired rule is still in the file:\n{text}"
        );
    }
}
