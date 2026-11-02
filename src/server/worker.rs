//! The thread that owns the WFP engine handle, and the work it carries out on behalf of a request
//! thread.

use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tracing::warn;

use crate::rules::RuleFile;

use super::state::Live;

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
    pub(super) ok: bool,
    pub(super) removed: usize,
    pub(super) installed: usize,
    /// The rules a rebuild found changed between the store and the file, named. Empty for every
    /// piece of work other than a rebuild, and for a refused one.
    pub(super) diff: RuleDiff,
    /// Providers, sublayers and filters we could read, or why we could not.
    pub(super) inventory: InventorySummary,
    pub(super) reason: Option<String>,
}

/// The rule names a rebuild found between the store and the rules file, as far as the store can
/// tell: names the file gained, names it lost, and names whose permits and blocks differ.
///
/// An edit that keeps a rule's name, its action and its number of filters — a narrowed port, say
/// — leaves the same trace in the store as no edit at all, and is not claimed here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RuleDiff {
    pub(super) added: Vec<String>,
    pub(super) changed: Vec<String>,
    pub(super) gone: Vec<String>,
}

impl RuleDiff {
    /// Whether the diff has anything to say.
    pub(super) fn is_empty(&self) -> bool {
        self.added.is_empty() && self.changed.is_empty() && self.gone.is_empty()
    }
}

impl StoreOutcome {
    /// Nothing reached the engine, so nothing was installed or removed either.
    pub(super) fn refused(inventory: InventorySummary, reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            removed: 0,
            installed: 0,
            diff: RuleDiff::default(),
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
pub(super) struct InventorySummary {
    pub(super) providers: Option<usize>,
    pub(super) sublayers: Option<usize>,
    pub(super) filters: Option<usize>,
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
    ///
    /// `live` carries the protection switch, which the worker honours on every piece of work: a
    /// rebuild asked for while protection is paused must not put filters back into the store.
    pub fn start(live: Arc<Live>) -> Self {
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
                // Read per item rather than remembered, so a pause made a moment ago is honoured
                // by the work that arrives after it.
                let work = honouring_protection(work, live.protection());

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

    /// The worker a test wants: protection on, because a test that pauses it says so.
    ///
    /// It owns its switch rather than sharing the one in the state, which is exactly what a test
    /// that never pauses protection cannot tell the difference about.
    #[cfg(test)]
    pub fn start_enforcing() -> Self {
        Self::start(Arc::new(Live::default()))
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

/// What a piece of store work becomes when protection is paused.
///
/// A rebuild is the only thing that changes: paused means "take our filters out", which is exactly
/// what the store route already asks for by hand, so doing the swap here means every caller that
/// pushes rules to the store — the page, an import, a profile switch, a settings change — cannot
/// quietly resume protection by writing a rule.
fn honouring_protection(work: StoreWork, protection: bool) -> StoreWork {
    match work {
        StoreWork::Apply { .. } if !protection => StoreWork::Clear,
        other => other,
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

    let result = match work {
        StoreWork::Apply {
            rules,
            known,
            policy,
        } => engine.apply(&rules, &known, policy).map(|applied| {
            let diff = name_diff(&applied.removed_rules, &applied.installed_rules);

            // The rebuild wrote the whole store, so its table replaces ours wholesale rather
            // than being merged; a filter the rebuild dropped is no longer in the store.
            *owners.lock().expect("owners lock poisoned") = applied.owners;

            (applied.removed, applied.installed, diff)
        }),
        StoreWork::Clear => engine.clear().map(|removed| {
            owners.lock().expect("owners lock poisoned").clear();

            (removed, 0, RuleDiff::default())
        }),
        StoreWork::Inventory => Ok((0, 0, RuleDiff::default())),
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
        Ok((removed, installed, diff)) if unreadable => Ok(StoreOutcome {
            ok: false,
            removed,
            installed,
            diff,
            inventory,
            reason: first_read_error(&raw),
        }),
        Ok((removed, installed, diff)) => Ok(StoreOutcome {
            ok: true,
            removed,
            installed,
            diff,
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
                diff: RuleDiff::default(),
                inventory,
                reason: Some(reason),
            })
        }
    }
}

/// Compare the filters a rebuild took out of the store with the rules it installed, by rule name.
///
/// The base filters of a deny policy are the policy's own plumbing rather than anyone's rule, so
/// their names are never in the answer. Rule names do not have to be unique, so a name counts as
/// changed when the number of permits and blocks under it differs between the two sides; the
/// lists keep the order the rules file has.
#[cfg(windows)]
fn name_diff(removed: &[crate::wfp::RemovedFilter], installed: &[(String, bool)]) -> RuleDiff {
    use std::collections::HashMap;

    /// Permits and blocks per name, skipping the base filters on the store side.
    fn tally<'a>(items: impl Iterator<Item = (&'a str, bool)>) -> HashMap<&'a str, (u32, u32)> {
        let mut counts: HashMap<&str, (u32, u32)> = HashMap::new();

        for (name, deny) in items {
            let slot = counts.entry(name).or_default();

            if deny {
                slot.1 += 1;
            } else {
                slot.0 += 1;
            }
        }

        counts
    }

    let old = tally(
        removed
            .iter()
            .map(|filter| (filter.name.as_str(), filter.deny))
            .filter(|(name, _)| !name.starts_with("base#")),
    );
    let new = tally(installed.iter().map(|(name, deny)| (name.as_str(), *deny)));

    let mut diff = RuleDiff::default();

    for (name, _) in installed {
        match (old.get(name.as_str()), new.get(name.as_str())) {
            (None, _) => {
                if !diff.added.iter().any(|seen| seen == name) {
                    diff.added.push(name.clone());
                }
            }
            (Some(previous), Some(counts)) => {
                if previous != counts && !diff.changed.iter().any(|seen| seen == name) {
                    diff.changed.push(name.clone());
                }
            }
            (Some(_), None) => {}
        }
    }

    for filter in removed {
        let name = filter.name.as_str();

        if !name.starts_with("base#")
            && !new.contains_key(name)
            && !diff.gone.iter().any(|seen| seen == name)
        {
            diff.gone.push(name.to_owned());
        }
    }

    diff
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
        diff: RuleDiff::default(),
        inventory: InventorySummary::default(),
        reason: Some(format!("no WFP on this platform, asked for {work:?}")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;

    #[cfg(windows)]
    fn left(name: &str, deny: bool) -> crate::wfp::RemovedFilter {
        crate::wfp::RemovedFilter {
            name: name.to_owned(),
            deny,
        }
    }

    /// The finding this answers: the counts are equal, yet a rule flipped its action while the
    /// tool was closed, and the name says so.
    #[cfg(windows)]
    #[test]
    fn a_flipped_action_is_named_as_changed_though_the_counts_match() {
        let diff = name_diff(
            &[left("web server", true)],
            &[("web server".to_owned(), false)],
        );

        assert_eq!(diff.changed, ["web server".to_owned()]);
        assert!(diff.added.is_empty() && diff.gone.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn names_the_file_gained_are_added_and_names_it_lost_are_gone() {
        let diff = name_diff(&[left("old rule", false)], &[("new rule".to_owned(), true)]);

        assert_eq!(diff.added, ["new rule".to_owned()]);
        assert_eq!(diff.gone, ["old rule".to_owned()]);
        assert!(diff.changed.is_empty());
    }

    /// A wildcard rule installs one filter per application under the same name. The diff compares
    /// rules, so one name is one entry however many filters stood behind it.
    #[cfg(windows)]
    #[test]
    fn one_rule_installing_many_filters_is_named_once() {
        let diff = name_diff(
            &[],
            &[
                ("browser".to_owned(), false),
                ("browser".to_owned(), false),
                ("browser".to_owned(), false),
            ],
        );

        assert_eq!(diff.added, ["browser".to_owned()]);
    }

    #[cfg(windows)]
    #[test]
    fn an_unchanged_rule_is_not_named_at_all() {
        let diff = name_diff(
            &[left("mail", false), left("mail", false)],
            &[("mail".to_owned(), false), ("mail".to_owned(), false)],
        );

        assert!(diff.is_empty());
    }

    /// The base filters of a deny policy come and go with the policy, not with anyone's rules.
    #[cfg(windows)]
    #[test]
    fn the_base_filters_are_never_named() {
        let diff = name_diff(
            &[left("base#loopback", false), left("base#block", true)],
            &[("mail".to_owned(), false)],
        );

        assert_eq!(diff.added, ["mail".to_owned()]);
        assert_eq!(diff.gone, Vec::<String>::new());
    }

    fn apply() -> StoreWork {
        StoreWork::Apply {
            rules: RuleFile::default(),
            known: Vec::new(),
            policy: Policy::Allow,
        }
    }

    /// The whole point of the switch: a rule written while protection is paused must not be what
    /// resumes it, or pausing on the tray would last exactly until the next click on the page.
    #[test]
    fn a_rebuild_while_protection_is_paused_becomes_a_clear() {
        assert!(matches!(
            honouring_protection(apply(), false),
            StoreWork::Clear
        ));
    }

    #[test]
    fn a_rebuild_with_protection_on_is_still_a_rebuild() {
        assert!(matches!(
            honouring_protection(apply(), true),
            StoreWork::Apply { .. }
        ));
    }

    /// Clearing is what the protection route asks for on its own, so it must not be turned into
    /// anything else by the same rule.
    #[test]
    fn a_clear_is_a_clear_whatever_protection_does() {
        assert!(matches!(
            honouring_protection(StoreWork::Clear, false),
            StoreWork::Clear
        ));
        assert!(matches!(
            honouring_protection(StoreWork::Clear, true),
            StoreWork::Clear
        ));
    }

    /// A read of the store is not a change to it, and a paused firewall still has to be readable.
    #[test]
    fn an_inventory_is_never_touched_by_the_switch() {
        assert!(matches!(
            honouring_protection(StoreWork::Inventory, false),
            StoreWork::Inventory
        ));
    }
}
