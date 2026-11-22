//! Only one instance of the tool at a time.
//!
//! A portable tool is started by double-click, and a second double-click is a mistake rather than
//! a wish for two firewalls: two servers on two ports, two tray icons, and two processes rebuilding
//! the same live store. The reference solves this with a named mutant and brings the running window
//! to the front instead of starting twice (`routine/src/rapp.c:403`); this does the same with a
//! named mutex, and the second process opens the browser on the running one rather than arguing.
//!
//! What is guarded is `--serve`, because that is the command that stays running. A one-shot apply
//! or clear does not need the guard: it is over in a moment, and the store serialises two
//! overlapping transactions on its own.
//!
//! A loser does not open the browser any more. It ends quietly with a non-zero status, and the page
//! of the running instance stays the running instance's business. The one process that may have to
//! wait for the name is the elevated newcomer of a relaunch: it starts while the old instance is
//! still holding the name, so it is given a few seconds of patience before it counts as a second
//! start.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, SetLastError, WIN32_ERROR,
};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex};
use windows::core::PCWSTR;

/// The name the mutex is created under.
///
/// `Local\` scopes it to the session the process runs in, which is what a per-user tool wants: its
/// data lives in that user's `%APPDATA%`, so two accounts on one machine may each run the tool, and
/// neither has a claim on the other's store.
const MUTEX_NAME: &str = "Local\\winfw-mcp.serve";

/// The file the running instance writes the port it serves on to.
///
/// A busy port makes the server fall forward to the next free one (`server::Server::bind`), so the
/// configured port is not necessarily the served port. A second process has to ask rather than
/// assume, and a file is the cheapest way to ask across two processes.
pub const PORT_FILE: &str = "server.port";

/// Held for as long as the process serves. Dropping it hands the name to the next start, which the
/// OS does on its own when the process dies without asking.
pub struct Guard {
    handle: HANDLE,
    /// Where the served port is recorded, so the guard that owns the claim can clean it up.
    port_file: PathBuf,
}

impl Guard {
    /// Tell the next process which port this one serves on. Called once the listener exists, because
    /// only then is the port known.
    pub fn set_port(&self, port: u16) {
        if let Err(error) = fs::write(&self.port_file, port.to_string()) {
            tracing::warn!(
                file = %self.port_file.display(),
                reason = %error,
                "could not record the served port",
            );
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Releasing is politeness; closing the handle would be enough. The file is a claim about the
        // running instance, so a process that stops should not leave it standing, and losing that
        // removal is harmless because the next instance overwrites the file anyway.
        if let Err(error) = unsafe { ReleaseMutex(self.handle) } {
            tracing::debug!(reason = %error, "releasing the instance mutex failed");
        }

        if let Err(error) = unsafe { CloseHandle(self.handle) } {
            tracing::debug!(reason = %error, "closing the instance mutex failed");
        }

        let _ = fs::remove_file(&self.port_file);
    }
}

/// How long an elevated newcomer of a relaunch waits for the name the old instance still holds.
///
/// The old process stops as soon as the shell grants the elevated start, so the wait covers the
/// time between "the shell said yes" and "the old accept loop left". It is bounded on purpose: if
/// the name is still held after this, something else is serving and waiting longer changes nothing.
const TAKEOVER_PATIENCE: Duration = Duration::from_secs(5);

/// How often a waiting takeover looks at the name again.
const TAKEOVER_POLL: Duration = Duration::from_millis(200);

/// Try to become the running instance. `None` means another process already holds the name, so the
/// caller should not start a second server.
///
/// Only the winner is handed a guard, which is what ties the claim to the process that holds it.
pub fn claim(paths: &crate::paths::DataPaths) -> Result<Option<Guard>> {
    let port_file = paths.root.join(PORT_FILE);

    Ok(claim_name(MUTEX_NAME)?.map(|handle| Guard { handle, port_file }))
}

/// The same claim for the elevated newcomer of a relaunch: it waits up to [`TAKEOVER_PATIENCE`]
/// for the name to be released before it reports itself as a second start.
///
/// The name is polled rather than waited on with an object wait, because the old process releases
/// it by exiting, and a poll of a mutex that is almost free is cheaper than plumbing a second
/// synchronisation object through the startup.
pub fn claim_takeover(paths: &crate::paths::DataPaths) -> Result<Option<Guard>> {
    let port_file = paths.root.join(PORT_FILE);

    Ok(
        claim_name_waiting(MUTEX_NAME, TAKEOVER_PATIENCE, TAKEOVER_POLL)?
            .map(|handle| Guard { handle, port_file }),
    )
}

/// The URL a second process should open, which is the running instance's rather than the configured
/// one.
///
/// Falls back to the configured port when no instance recorded one, because a missing file deserves
/// a guess rather than refusing to open anything.
pub fn running_url(port_file: &Path, configured: u16) -> String {
    let port = fs::read_to_string(port_file)
        .ok()
        .and_then(|text| text.trim().parse::<u16>().ok())
        .unwrap_or(configured);

    format!("http://127.0.0.1:{port}/")
}

/// The same claim under a name the caller chooses, so a test can hold a name of its own rather than
/// depend on whether a developer happens to have the tool running.
fn claim_name(name: &str) -> Result<Option<HANDLE>> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // Zeroed on purpose, because a successful `CreateMutexW` that created the name does not write
    // the last error at all: it leaves whatever the thread's previous failure left there. Without
    // this, an earlier unrelated failure can read as "another instance is running" and the tool
    // refuses to start.
    // SAFETY: setting the calling thread's last error.
    unsafe { SetLastError(WIN32_ERROR(0)) };

    // SAFETY: the buffer outlives the call and is NUL terminated, and a null security attribute
    // list is what Windows wants for the default descriptor.
    let handle = unsafe { CreateMutexW(None, true, PCWSTR(wide.as_ptr())) }
        .with_context(|| format!("CreateMutexW failed for '{name}'"))?;

    // The winner sees no error here; the loser is told the name already existed. Nothing may be
    // called between the two, because the last error is only meaningful immediately after the call.
    // SAFETY: reading the calling thread's last error, set by the call above.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // SAFETY: the handle came from `CreateMutexW` and is not used again, so closing it keeps
        // the loser from holding an object it does not own.
        let _ = unsafe { CloseHandle(handle) };

        return Ok(None);
    }

    Ok(Some(handle))
}

/// [`claim_name`] repeated until the name is free or the patience has run out.
fn claim_name_waiting(name: &str, patience: Duration, poll: Duration) -> Result<Option<HANDLE>> {
    let deadline = Instant::now() + patience;

    loop {
        if let Some(handle) = claim_name(name)? {
            return Ok(Some(handle));
        }

        if Instant::now() >= deadline {
            return Ok(None);
        }

        std::thread::sleep(poll);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded port wins over the configured one, and the whitespace the file is written with is
    /// forgiven. What is not a port at all is treated as no answer.
    #[test]
    fn the_running_url_prefers_the_recorded_port() {
        let dir = crate::testutil::scratch_dir("instance-url");
        let file = dir.join(PORT_FILE);

        assert_eq!(
            running_url(&file, 8788),
            "http://127.0.0.1:8788/",
            "a missing file is answered by the configured port",
        );

        fs::write(&file, "8791\n").expect("write a port");

        assert_eq!(running_url(&file, 8788), "http://127.0.0.1:8791/");

        fs::write(&file, "http").expect("write nonsense");

        assert_eq!(running_url(&file, 8788), "http://127.0.0.1:8788/");
    }

    /// The first claim wins, a second one on a held name is refused, and releasing hands the name to
    /// whoever asks next. That is the whole guarantee the module promises.
    #[test]
    fn one_claim_at_a_time_holds_a_name() {
        // A name of its own, so the test does not care whether the tool is running on this machine.
        let name = format!("Local\\winfw-mcp-test-{}", std::process::id());

        let first = claim_name(&name)
            .expect("claim")
            .expect("the name was free");
        let second = claim_name(&name).expect("claim");

        assert!(second.is_none(), "a second claim on a held name is refused");

        // Closing rather than dropping: what releases the name in real use is `Guard::drop`, and a
        // raw handle here would otherwise keep the object alive without saying so.
        // SAFETY: the handle came from `claim_name` and is not used again.
        unsafe { CloseHandle(first) }.expect("close the handle");

        let third = claim_name(&name).expect("claim");

        assert!(third.is_some(), "releasing hands the name on");

        // SAFETY: the handle came from `claim_name` and is not used again.
        let _ = unsafe { CloseHandle(third.expect("the handle claimed above")) };
    }

    /// A name that becomes free within the patience is claimed; one that stays held past the
    /// patience is not. Both halves matter for the elevated relaunch: the newcomer must neither
    /// give up on a name that is about to be free nor wait forever on a name that is not.
    #[test]
    fn a_waiting_claim_uses_the_patience_it_is_given() {
        let name = format!("Local\\winfw-mcp-wait-{}", std::process::id());

        let held = claim_name(&name)
            .expect("claim")
            .expect("the name was free");

        let patience = Duration::from_millis(600);
        let poll = Duration::from_millis(50);

        // A name held for the whole patience is a second start, not a wait.
        let given_up = claim_name_waiting(&name, patience, poll).expect("claim");
        assert!(given_up.is_none(), "the patience has an end");

        // A name released shortly after the wait begins is claimed. The handle travels as a plain
        // number, because a raw handle is not `Send` but this thread is its only owner.
        let held_raw = held.0 as usize;
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // SAFETY: the value is the handle `claim_name` returned, and it is closed exactly
            // once, here.
            let _ = unsafe { CloseHandle(HANDLE(held_raw as *mut _)) };
        });

        let claimed = claim_name_waiting(&name, Duration::from_secs(2), poll)
            .expect("claim")
            .expect("the name was released while waiting");

        releaser.join().expect("the releaser thread");

        // SAFETY: the handle came from `claim_name_waiting` and is not used again.
        let _ = unsafe { CloseHandle(claimed) };
    }

    /// Dropping the guard takes the port file with it, so a stopped process does not leave a claim
    /// about a server that is no longer there.
    #[test]
    fn a_released_guard_leaves_no_port_behind() {
        let paths = crate::paths::DataPaths::under(crate::testutil::scratch_dir("instance-guard"));
        paths.ensure().expect("create the data directory");

        let guard = claim(&paths).expect("claim").expect("the name was free");

        guard.set_port(8792);

        assert_eq!(
            running_url(&paths.root.join(PORT_FILE), 8788),
            "http://127.0.0.1:8792/"
        );

        drop(guard);

        assert_eq!(
            running_url(&paths.root.join(PORT_FILE), 8788),
            "http://127.0.0.1:8788/",
            "the file is gone, so only the configured port is left to offer",
        );
    }
}
