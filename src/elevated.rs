//! Whether this process is elevated, and the one action an unelevated process can ask for.
//!
//! Reading and writing the live store need elevation (PLAN.md section 2), and a portable tool is
//! started by double-click, which is unelevated. The two questions that follow from this are
//! answered here rather than guessed from a store refusal: is the process elevated, and can it ask
//! the shell to start an elevated copy of itself?

use anyhow::{Context, Result, bail};

/// Whether the process runs with an elevated token.
///
/// `TokenElevation` is what `ShellExecuteW` with `runas` decides, so this answers the question the
/// relaunch route asks directly rather than inferred from whether the store opened. An unelevated
/// process answers `false`; so does a process whose token cannot be read, which is the safe
/// direction because a relaunch is refused with a message rather than attempted blindly.
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();

        // SAFETY: the handle is written by `OpenProcessToken` and closed on every path below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;

        // SAFETY: `token` is a valid handle owned until it is closed here, and the output pointer
        // and its size belong to `elevation`.
        let elevated = unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
                &mut returned,
            )
        }
        .is_ok();

        // SAFETY: `token` was opened successfully above and has not been closed yet.
        unsafe { windows::Win32::Foundation::CloseHandle(token) }.ok();

        elevated && elevation.TokenIsElevated != 0
    }

    #[cfg(not(windows))]
    {
        false
    }
}

/// Ask the shell to start an elevated copy of this executable serving, and report whether the
/// shell granted it.
///
/// `runas` is the verb that shows the UAC dialog. A refused dialog is an ordinary refusal: the
/// shell reports `ERROR_CANCELLED` and this process stays exactly where it was, which is what lets
/// the caller stop only after the shell said yes.
pub fn relaunch_elevated() -> Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use tracing::info;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        use windows::core::{PCWSTR, w};

        let exe = std::env::current_exe().context("find this executable")?;
        let exe_wide = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let arguments = wide("--serve");

        // SAFETY: every pointer is a nul-terminated wide string we own for the duration of the
        // call, and the shell reads all of them before it returns. A null directory lets the new
        // process inherit this one, which is good enough for a tool that only uses APPDATA.
        let status = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR(exe_wide.as_ptr()),
                PCWSTR(arguments.as_ptr()),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };

        // `ShellExecuteW` reports a value rather than an error, and every value that is not an
        // success is at most 32. The refused dialog is `ERROR_CANCELLED` (5) in that range.
        if status.0 as usize <= 32 {
            bail!(
                "the shell refused the elevated start (status {})",
                status.0 as usize,
            );
        }

        info!(
            status = status.0 as usize,
            "asked the shell for an elevated start"
        );

        Ok(())
    }

    #[cfg(not(windows))]
    {
        bail!("an elevated relaunch is a Windows idea");
    }
}

/// Encode a string as a terminated wide string.
#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded: Vec<u16> = std::ffi::OsStr::new(value).encode_wide().collect();
    encoded.push(0);

    encoded
}
