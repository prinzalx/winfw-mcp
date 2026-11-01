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
    /// Providers, sublayers and filters we could read, or why we could not.
    pub(super) inventory: InventorySummary,
    pub(super) reason: Option<String>,
}

impl StoreOutcome {
    /// Nothing reached the engine, so nothing was installed or removed either.
    pub(super) fn refused(inventory: InventorySummary, reason: impl Into<String>) -> Self {
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
