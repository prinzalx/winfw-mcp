//! Whether this process is elevated, and the one action an unelevated process can ask for.
//!
//! Reading and writing the live store need elevation (plan section 2), and a portable tool is
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

/// The arguments to start an elevated copy of this process with.
///
/// A command that only touches files is handed through unchanged, so an import really imports the
/// file the user named rather than starting a server. A serving command becomes `--takeover`
/// rather than `--serve`, because the newcomer starts while the process that asked for it still
/// holds the instance name, and it should wait for that name instead of ending as a second start.
///
/// No arguments at all also means `--takeover`: whoever started the tool without a flag and asked
/// for elevation means the tool to run, which is `--serve`.
pub fn relaunch_arguments(args: &[String]) -> Vec<String> {
    match args.first().map(String::as_str) {
        Some("--serve") | Some("--takeover") | Some("--apply") | None => {
            vec!["--takeover".to_owned()]
        }
        _ => args.to_vec(),
    }
}

/// Join arguments into one command line for the shell, quoting what contains a space.
///
/// The shell splits this string itself, so a profile whose path holds a space would otherwise
/// arrive as two arguments and be read as a file that does not exist.
fn command_line(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.contains(' ') {
                format!("\"{arg}\"")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ask the shell to start an elevated copy of this executable, and report whether the shell
/// granted it.
///
/// `runas` is the verb that shows the UAC dialog. A refused dialog is an ordinary refusal: the
/// shell reports `ERROR_CANCELLED` and this process stays exactly where it was, which is what lets
/// the caller stop only after the shell said yes.
pub fn relaunch_elevated(args: &[String]) -> Result<()> {
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
        let arguments = wide(&command_line(&relaunch_arguments(args)));

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

        if !granted(status.0 as isize) {
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

/// Whether a `ShellExecuteW` return value says the shell granted the start.
///
/// The function reports a value rather than an error, and every value that is not a success is at
/// most 32, so a refusal has to be read out of the number. `ERROR_CANCELLED` (5) — the refused
/// dialog — is inside that range, which is what lets the caller stop only after the shell said
/// yes.
fn granted(status: isize) -> bool {
    status > 32
}

/// Show the question whether this process should restart elevated, and report whether the user
/// said yes.
///
/// A release build has no console, so the question cannot be asked in the window it was started
/// from: it goes into a dialog of its own. Answering no is a supported answer rather than a
/// failure, and the caller says in its log what staying unelevated means.
#[cfg(windows)]
pub fn ask_elevated(question: &str) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{
        IDYES, MB_ICONWARNING, MB_SETFOREGROUND, MB_YESNO, MessageBoxW,
    };
    use windows::core::PCWSTR;

    let title = wide("winfw-mcp is not running as administrator");
    let body = wide(question);

    // SAFETY: both pointers are nul-terminated wide strings owned until after the call, and a null
    // owner window is allowed.
    let answer = unsafe {
        MessageBoxW(
            None,
            PCWSTR(body.as_ptr()),
            PCWSTR(title.as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_SETFOREGROUND,
        )
    };

    answer == IDYES
}

/// Without a window to ask in there is no question: nothing is restarted and the run continues as
/// it did before the question existed.
#[cfg(not(windows))]
pub fn ask_elevated(_question: &str) -> bool {
    false
}

/// Encode a string as a terminated wide string.
#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut encoded: Vec<u16> = std::ffi::OsStr::new(value).encode_wide().collect();
    encoded.push(0);

    encoded
}

#[cfg(test)]
mod tests {
    use super::granted;

    /// The decision is the whole safety of the route: stopping this process on a refused dialog
    /// would leave the firewall with no tool and no server.
    #[test]
    fn only_a_value_above_the_error_range_grants_the_start() {
        assert!(!granted(0), "a null handle is not a start");
        assert!(!granted(5), "ERROR_CANCELLED is the refused dialog");
        assert!(
            !granted(32),
            "32 is the last value the shell reports as an error"
        );
        assert!(
            granted(33),
            "the first value above the error range is a success"
        );
    }

    #[test]
    fn a_serving_command_becomes_a_takeover_and_a_file_command_is_passed_through() {
        let serving = super::relaunch_arguments(&[]);
        assert_eq!(
            serving,
            ["--takeover"],
            "a start with no arguments means the tool should run, and the process that asks for it is still holding the instance name"
        );

        let serve = super::relaunch_arguments(&["--serve".to_owned()]);
        assert_eq!(serve, ["--takeover"], "the same reasoning behind --serve");

        let clear = super::relaunch_arguments(&["--clear".to_owned()]);
        assert_eq!(
            clear,
            ["--clear"],
            "a one-shot command stays a one-shot command"
        );

        let imported = super::relaunch_arguments(&[
            "--import".to_owned(),
            "C:\\profiles\\my profile.xml".to_owned(),
        ]);
        assert_eq!(
            imported,
            ["--import", "C:\\profiles\\my profile.xml"],
            "an import has to bring the file the user named"
        );
    }

    /// The shell splits the arguments itself, so a path with a space has to arrive as one argument
    /// rather than as a file that does not exist.
    #[test]
    fn an_argument_with_a_space_is_quoted_for_the_shell() {
        assert_eq!(super::command_line(&["--clear".to_owned()]), "--clear");
        assert_eq!(
            super::command_line(&["--import".to_owned(), "my profile.xml".to_owned()]),
            "--import \"my profile.xml\"",
            "the shell would split an unquoted path",
        );
    }

    /// The arguments travel to the shell as terminated wide strings, so the terminator is part of
    /// the contract and not something the callee can supply.
    #[test]
    fn a_wide_string_ends_where_the_shell_reads_it() {
        let encoded = super::wide("--serve");

        assert_eq!(encoded.len(), "--serve".len() + 1);
        assert_eq!(
            encoded.last(),
            Some(&0),
            "the shell reads up to the terminator"
        );
    }
}
