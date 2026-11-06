//! The programs that are running right now.
//!
//! A temporary rule asks whether its program is still there, and nothing announces a process
//! leaving: the firewall's own event stream speaks about connections, not about programs. So the
//! answer is taken from the process list, which is the one place that knows.
//!
//! The paths come back in the drive form a rule is typed in (`C:\...`), which is what
//! [`crate::rules::expired_temporary`] compares against.

/// The image path of every process the system named, in drive form.
///
/// `None` means the list could not be taken at all, which is not the same answer as "no programs
/// are running": a caller that heard `None` has to say nothing about any program rather than
/// retire every temporary rule on the strength of an empty list.
///
/// A process whose path the system would not hand over — one of another user, mostly — is left
/// out of the list rather than guessed at. That can only cost a temporary rule its early
/// retirement, never a permanent rule its place.
#[cfg(windows)]
pub fn image_paths() -> Option<Vec<String>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };

    // One snapshot of every process, so the list is one moment rather than a scan that never ends.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.ok()?;

    let mut found = Vec::new();
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok();

    while more {
        found.push(image_path(entry.th32ProcessID));

        more = unsafe { Process32NextW(snapshot, &mut entry) }.is_ok();
    }

    unsafe {
        let _ = CloseHandle(snapshot);
    }

    Some(found.into_iter().flatten().collect())
}

/// The drive-form path of one process, when the system would name it.
#[cfg(windows)]
fn image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };

    // Limited information is the right the current user has for somebody else's process without
    // elevation, and it is enough for the name.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;

    let mut buffer = [0u16; 1024];
    let mut size = buffer.len() as u32;

    let read = unsafe {
        QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )
    }
    .is_ok();

    unsafe {
        let _ = CloseHandle(handle);
    }

    if read {
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    } else {
        None
    }
}

/// There is no process list to take off Windows, so nothing is known about any program.
#[cfg(not(windows))]
pub fn image_paths() -> Option<Vec<String>> {
    None
}

#[cfg(test)]
mod tests {
    use super::image_paths;

    /// The test binary is a running process, so the list has to name it. On a build without a
    /// process list the same call answers `None`, which is the other honest answer.
    #[test]
    fn the_running_programs_name_this_process() {
        match image_paths() {
            Some(paths) => {
                let ours = std::env::current_exe()
                    .expect("the test binary knows itself")
                    .to_string_lossy()
                    .to_lowercase();

                assert!(
                    paths.iter().any(|path| path.to_lowercase() == ours),
                    "the process list does not hold {ours}: {} entries",
                    paths.len(),
                );
            }
            #[cfg(windows)]
            None => panic!("a Windows build has a process list to read"),
            #[cfg(not(windows))]
            None => {}
        }
    }
}
