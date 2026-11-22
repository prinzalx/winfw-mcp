//! Translation between drive paths (`C:\dir\a.exe`) and the NT device paths WFP and the event
//! stream use (`\device\harddiskvolume3\dir\a.exe`).
//!
//! The two forms mean the same file, and which one a user writes is a matter of habit: a rule
//! typed by hand says `C:\`, while an event reported by the firewall says
//! `\device\harddiskvolumeN\`. Learning mode has to compare the two, so the mapping is resolved
//! once and cached.
//!
//! The cache is not permanent. A volume can be mounted long after the process started, and a
//! portable tool that has to be restarted because a USB stick appeared later would be a poor
//! tool. So a lookup whose drive prefix is unknown re-asks the system, throttled to one re-ask per
//! second, which catches the mount without a device-notification window in the tray.
//!
//! Catching the mount is only half of it, because a filter that is already in the store was built
//! against the smaller answer. When an answer names a drive the answer before it did not have,
//! `store_needs_rebuild` says so once, and the monitor answers by handing the rules to the worker
//! again. That is what makes a rule for a drive mounted after start take effect on its own.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

/// One `(drive prefix, device prefix)` pair, both lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mapping {
    drive: String,
    device: String,
}

/// How long a re-ask has to wait after the previous one, in milliseconds.
///
/// A miss is normal for a path that is not a path at all (`*`, `not a path`), so the pause keeps a
/// rule list full of such patterns from turning every render into a system query.
const REQUERY_PAUSE_MS: u64 = 1000;

/// How long the monitor's probe has to wait after the previous one, in milliseconds.
///
/// The probe is not chasing a known miss, it is watching for a volume to appear, so it can afford
/// to be slower than a lookup that is waiting for an answer.
const PROBE_PAUSE_MS: u64 = 10_000;

/// The mappings of this machine, resolved on first use and replaced when a lookup misses.
///
/// The read lock is dropped before the write lock is taken, which matters because a lock is never
/// held across a system call.
static CACHE: RwLock<Option<Arc<[Mapping]>>> = RwLock::new(None);

/// When the last re-ask happened, in milliseconds since the epoch.
static LAST_QUERY_MS: AtomicU64 = AtomicU64::new(0);

/// When the monitor's last probe happened, in milliseconds since the epoch.
static LAST_PROBE_MS: AtomicU64 = AtomicU64::new(0);

/// Set when an answer named a drive the answer before it did not have.
///
/// The filters already in the store were built against the smaller answer, so the flag says
/// "build them again". It is taken by the monitor rather than read, which is what keeps one mount
/// from queueing a rebuild on every event.
static MOUNT_SEEN: AtomicBool = AtomicBool::new(false);

fn mappings() -> Arc<[Mapping]> {
    {
        let guard = CACHE.read().unwrap_or_else(PoisonError::into_inner);

        if let Some(current) = &*guard {
            return Arc::clone(current);
        }
    }

    requery()
}

/// Ask the system for the mappings and make them the current answer.
///
/// Threads can race through here at the same time; the worst case is that the same question is
/// asked twice and the same answer is written twice, which is cheaper than a lock held over
/// `QueryDosDeviceW`.
fn requery() -> Arc<[Mapping]> {
    let fresh: Arc<[Mapping]> = Arc::from(query());

    LAST_QUERY_MS.store(now_ms(), Ordering::Relaxed);

    {
        let mut guard = CACHE.write().unwrap_or_else(PoisonError::into_inner);

        if grew_against(&fresh, guard.as_deref()) {
            MOUNT_SEEN.store(true, Ordering::Relaxed);
        }

        *guard = Some(Arc::clone(&fresh));
    }

    fresh
}

/// Whether a fresh answer names a drive the previous answer did not.
///
/// Only a drive that appeared counts. One that disappeared is not a reason to build the filters
/// again: the filters that hold its paths match nothing, which is what a missing volume means, and
/// a drive that changed volume is not a new pattern to translate either.
fn grew_against(fresh: &[Mapping], previous: Option<&[Mapping]>) -> bool {
    let Some(previous) = previous else {
        // The first answer is the baseline rather than a change.
        return false;
    };

    fresh
        .iter()
        .any(|found| !previous.iter().any(|known| known.drive == found.drive))
}

/// Ask the system again once the probe pause has passed, and say whether the filters in the store
/// were built against a mapping set that is known to be smaller now.
///
/// A rule for a drive that did not exist when the filters were built went into the store as the text
/// the user wrote, and the event stream never reports that text. The next write to the rule list
/// fixes it, so this is the part that notices on its own: a volume mounted after start takes effect
/// without anyone editing a rule.
pub fn store_needs_rebuild() -> bool {
    let now = now_ms();
    let previous = LAST_PROBE_MS.swap(now, Ordering::Relaxed);

    if previous == 0 || now.saturating_sub(previous) >= PROBE_PAUSE_MS {
        requery();
    }

    MOUNT_SEEN.swap(false, Ordering::Relaxed)
}

/// Milliseconds since the epoch, or zero if the clock cannot be read.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// Rewrite a drive path into device form, leaving anything else alone.
///
/// A pattern that already starts with `\device\` is returned as it stands, which is what lets a
/// rule be written in either form. A path that looks like a drive but does not match any known
/// letter gets one more chance, which is how a drive mounted after start is still recognised.
pub fn to_device_path(path: &str) -> String {
    let lowered = path.to_lowercase();

    if lowered.starts_with("\\device\\") || lowered.starts_with("\\??\\") {
        return lowered;
    }

    // A name written with an environment variable means the directory on this machine, so it is
    // resolved before anything else looks at the text.
    let lowered = expand_env_vars(&lowered).to_lowercase();

    // A short 8.3 name is not the name the ALE layer reports, so a rule that holds one is repaired
    // before it is mapped. Without this the rule is written, installed, and never matches anything.
    let lowered = if wants_long_form(&lowered) {
        expand_short_path(&lowered)
    } else {
        lowered
    };

    let drive_like = looks_like_drive_path(&lowered);

    if let Some(resolved) = search_device(&lowered) {
        return resolved;
    }

    if drive_like
        && requery_after_pause()
        && let Some(resolved) = search_device(&lowered)
    {
        return resolved;
    }

    lowered
}

/// Whether it is worth asking the system for the long form of a path.
///
/// A tilde is the marker of an 8.3 name, so a path without one is already long and the question is
/// not asked at all. A pattern that holds a wildcard is not a path the system could resolve:
/// `GetLongPathNameW` reads `*` as a literal character, finds no such file, and the answer would be
/// the input anyway.
fn wants_long_form(path: &str) -> bool {
    path.contains('~') && !path.contains('*') && !path.contains('?') && looks_like_drive_path(path)
}

/// Replace every `%NAME%` in a path with the value of that environment variable.
///
/// Only a name the process actually has is replaced, so a name a rules file carried over from
/// another machine stays visible instead of becoming an empty string, which would turn
/// `%ProgramFiles%\tool.exe` into `\tool.exe` and match a different directory.
///
/// It is the text a person writes when they write the rule by hand, so it is resolved where the
/// path is mapped and never where the rule is stored: the file keeps the words, and only the filter
/// sees the value.
fn expand_env_vars(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut rest = path;

    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);

        let after = &rest[start + 1..];
        let Some(end) = after.find('%') else {
            // One percent sign with no closing partner is ordinary text.
            out.push('%');
            out.push_str(after);

            return out;
        };

        let name = &after[..end];

        if name.is_empty() {
            // `%%` is one literal percent sign.
            out.push('%');
        } else {
            out.push_str(&std::env::var(name).unwrap_or_else(|_| format!("%{name}%")));
        }

        rest = &after[end + 1..];
    }

    out.push_str(rest);

    out
}

/// Hand a drive path to the system and ask for its long form, falling back to the input.
///
/// A path that does not exist comes back unchanged, which is the only honest answer: the tool does
/// not know what the volume would have called it. A path longer than the buffer also comes back
/// unchanged rather than truncated.
#[cfg(windows)]
fn expand_short_path(path: &str) -> String {
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;

    let mut wide: Vec<u16> = path.encode_utf16().collect();
    wide.push(0);
    let mut buffer = [0u16; 512];

    let length =
        unsafe { GetLongPathNameW(windows::core::PCWSTR(wide.as_ptr()), Some(&mut buffer)) };

    // Zero means the path is unknown to the volume, and a length past the end of the buffer means
    // the answer did not fit. Both are a reason to keep what the user wrote.
    if length == 0 || usize::try_from(length).unwrap_or(usize::MAX) > buffer.len() {
        return path.to_string();
    }

    String::from_utf16_lossy(&buffer[..length as usize]).to_lowercase()
}

/// There is nothing to expand off Windows.
#[cfg(not(windows))]
fn expand_short_path(path: &str) -> String {
    path.to_string()
}

/// Rewrite a device path into drive form for display, falling back to the input unchanged.
pub fn to_dos_path(path: &str) -> String {
    let lowered = path.to_lowercase();

    if let Some(resolved) = search_dos(&lowered) {
        return resolved;
    }

    if lowered.starts_with("\\device\\")
        && requery_after_pause()
        && let Some(resolved) = search_dos(&lowered)
    {
        return resolved;
    }

    lowered
}

/// Does the text start with a `X:` drive prefix at all?
///
/// Only a path that could name a drive is worth a re-ask, which is what keeps `*` from causing a
/// system query every second.
fn looks_like_drive_path(lowered: &str) -> bool {
    let bytes = lowered.as_bytes();

    bytes.len() > 1 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}

/// First mapping whose drive prefix the path starts with, rewritten.
fn search_device(lowered: &str) -> Option<String> {
    mappings()
        .iter()
        .find(|mapping| lowered.starts_with(&mapping.drive))
        // The separator belongs to the drive prefix in the device form, and `strip_prefix`
        // leaves it on `rest`, where it is already in the shape we need.
        .map(|mapping| format!("{}{}", mapping.device, &lowered[mapping.drive.len()..]))
}

/// First mapping whose device prefix the path starts with, rewritten.
fn search_dos(lowered: &str) -> Option<String> {
    mappings()
        .iter()
        .find(|mapping| lowered.starts_with(&mapping.device))
        .map(|mapping| format!("{}{}", mapping.drive, &lowered[mapping.device.len()..]))
}

/// Re-ask the system, unless the last re-ask is less than the pause old. The answer is whether the
/// cache holds an answer newer than the pause, which is what the callers report on.
fn requery_after_pause() -> bool {
    let now = now_ms();
    let previous = LAST_QUERY_MS.swap(now, Ordering::Relaxed);

    if previous != 0 && now.saturating_sub(previous) < REQUERY_PAUSE_MS {
        return false;
    }

    requery();

    true
}

/// Count of the system queries this process made, for the tests.
#[cfg(test)]
static QUERIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Ask the system which device each drive letter points at.
#[cfg(windows)]
fn query() -> Vec<Mapping> {
    use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

    #[cfg(test)]
    QUERIES.fetch_add(1, Ordering::Relaxed);

    let mut found = Vec::new();

    // One bitmap tells us which letters exist, so we never probe a drive that cannot be there.
    let mask = unsafe { GetLogicalDrives() };

    for index in 0..26u32 {
        if mask & (1 << index) == 0 {
            continue;
        }

        // Cast to `char` deliberately: a `u8` would be formatted as its number, and `QueryDosDeviceW`
        // has nothing to do with "67:".
        let drive = format!("{}:", (b'A' + index as u8) as char);

        // `PCWSTR` reads until a NUL, which `encode_utf16` does not provide.
        let mut wide: Vec<u16> = drive.encode_utf16().collect();
        wide.push(0);
        let mut buffer = [0u16; 512];

        let length =
            unsafe { QueryDosDeviceW(windows::core::PCWSTR(wide.as_ptr()), Some(&mut buffer)) };

        if length == 0 {
            continue;
        }

        let device = String::from_utf16_lossy(&buffer[..length as usize]);
        let device = device.trim_end_matches('\0').to_lowercase();

        found.push(Mapping {
            drive: drive.to_lowercase(),
            device,
        });
    }

    found
}

/// There is no drive to ask about off Windows.
#[cfg(not(windows))]
fn query() -> Vec<Mapping> {
    #[cfg(test)]
    QUERIES.fetch_add(1, Ordering::Relaxed);

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty the cache and forget when the last re-ask happened, so a test starts from a known
    /// state rather than from whatever an earlier test left behind.
    fn forget() {
        *CACHE.write().unwrap_or_else(PoisonError::into_inner) = None;
        LAST_QUERY_MS.store(0, Ordering::Relaxed);
        LAST_PROBE_MS.store(0, Ordering::Relaxed);
        MOUNT_SEEN.store(false, Ordering::Relaxed);
    }

    /// Put a list of mappings in the cache without asking the system, and note the moment as
    /// "just queried", which is what the throttle reads.
    fn prime(mappings: Vec<Mapping>) {
        CACHE
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(Arc::from(mappings));
        LAST_QUERY_MS.store(now_ms(), Ordering::Relaxed);
    }

    #[test]
    fn a_device_path_is_left_in_device_form() {
        forget();

        assert_eq!(
            to_device_path("\\Device\\HarddiskVolume3\\windows\\a.exe"),
            "\\device\\harddiskvolume3\\windows\\a.exe"
        );
    }

    #[test]
    fn an_unknown_shape_is_only_lowercased() {
        forget();

        assert_eq!(to_device_path("not a path"), "not a path");
    }

    #[test]
    fn a_real_drive_round_trips_to_device_form_and_back() {
        forget();

        assert!(
            !mappings().is_empty(),
            "Windows always has a system drive to map",
        );

        let mapping = &mappings()[0];
        let dos = format!("{}\\windows\\a.exe", mapping.drive);

        let device = to_device_path(&dos);

        assert_eq!(device, format!("{}\\windows\\a.exe", mapping.device));
        assert_eq!(to_dos_path(&device), dos.to_lowercase());
    }

    #[test]
    fn a_drive_mounted_after_the_cache_was_made_is_still_found() {
        forget();

        let mapping = mappings().first().expect("a system drive").clone();
        let dos = format!("{}\\games\\a.exe", mapping.drive);

        // The cache says the letter is nowhere, and it has only just been asked, which is the state
        // in which the pause refuses to help.
        prime(Vec::new());

        assert_eq!(to_device_path(&dos), dos.to_lowercase());

        // The pause having passed, the same lookup asks again and now finds the drive.
        LAST_QUERY_MS.store(0, Ordering::Relaxed);

        assert_eq!(
            to_device_path(&dos),
            format!("{}\\games\\a.exe", mapping.device)
        );
    }

    #[test]
    fn a_device_path_that_is_not_mounted_yet_is_resolved_after_a_reask() {
        forget();

        let mapping = mappings().first().expect("a system drive").clone();

        prime(vec![Mapping {
            drive: "q:".to_owned(),
            device: "\\device\\harddiskvolume99".to_owned(),
        }]);
        LAST_QUERY_MS.store(0, Ordering::Relaxed);

        assert_eq!(
            to_dos_path(&format!("{}\\windows\\a.exe", mapping.device)),
            format!("{}\\windows\\a.exe", mapping.drive)
        );
    }

    #[test]
    fn a_miss_asks_the_system_once_per_pause() {
        forget();
        prime(Vec::new());
        LAST_QUERY_MS.store(0, Ordering::Relaxed);

        let before = QUERIES.load(Ordering::Relaxed);

        assert!(to_device_path("z:\\windows\\a.exe").ends_with("a.exe"));

        let after_first = QUERIES.load(Ordering::Relaxed);

        assert!(after_first > before, "the miss should have asked");

        assert!(to_device_path("z:\\windows\\b.exe").ends_with("b.exe"));

        assert_eq!(
            QUERIES.load(Ordering::Relaxed),
            after_first,
            "the pause should have held the second miss back",
        );
    }

    #[test]
    fn a_pattern_that_is_not_a_path_does_not_ask_the_system() {
        forget();
        prime(Vec::new());

        let before = QUERIES.load(Ordering::Relaxed);

        assert_eq!(to_device_path("*"), "*");
        assert_eq!(to_dos_path("*"), "*");

        assert_eq!(QUERIES.load(Ordering::Relaxed), before);
    }

    #[test]
    fn wants_long_form_is_only_asked_for_a_short_path() {
        assert!(wants_long_form("c:\\progra~1\\tool.exe"));

        assert!(!wants_long_form("c:\\tools\\tool.exe"));
        assert!(!wants_long_form("c:\\tools\\*.exe"));
        assert!(!wants_long_form("c:\\tools\\tool?.exe"));
        assert!(!wants_long_form(
            "\\device\\harddiskvolume3\\progra~1\\tool.exe"
        ));
    }

    #[test]
    fn only_a_drive_that_appeared_counts_as_a_mount() {
        let mapping = |drive: &str, volume: &str| Mapping {
            drive: drive.to_string(),
            device: format!("\\device\\harddiskvolume{volume}"),
        };

        let before = vec![mapping("c:", "3")];

        assert!(grew_against(
            &[mapping("c:", "3"), mapping("d:", "7")],
            Some(&before),
        ));

        assert!(!grew_against(&before, Some(&before)));

        // The same letter pointing at another volume is not a drive that appeared.
        assert!(!grew_against(&[mapping("c:", "9")], Some(&before)));

        // The first answer of a process is the baseline, not a change.
        assert!(!grew_against(&before, None));
    }

    #[test]
    fn the_probe_asks_the_system_once_per_pause() {
        forget();

        let before = QUERIES.load(Ordering::Relaxed);

        assert!(!store_needs_rebuild());
        assert_eq!(QUERIES.load(Ordering::Relaxed), before + 1);

        assert!(!store_needs_rebuild());
        assert_eq!(QUERIES.load(Ordering::Relaxed), before + 1);
    }

    #[test]
    fn an_environment_name_is_replaced_only_when_the_process_has_it() {
        // One thread at a time is what makes this safe to write here; see the working checklist.
        unsafe { std::env::set_var("WINFW_TEST_DIR", "C:\\test") };

        assert_eq!(expand_env_vars("%WINFW_TEST_DIR%"), "C:\\test");
        assert_eq!(
            expand_env_vars("%WINFW_MISSING_DIR%\\tool.exe"),
            "%WINFW_MISSING_DIR%\\tool.exe"
        );

        // A lone percent sign and a doubled one are ordinary text.
        assert_eq!(
            expand_env_vars("c:\\tools\\100%.exe"),
            "c:\\tools\\100%.exe"
        );
        assert_eq!(expand_env_vars("50%%"), "50%");
        assert_eq!(expand_env_vars("plain"), "plain");
    }

    #[test]
    fn a_rule_written_with_an_environment_name_is_mapped_with_its_value() {
        unsafe { std::env::set_var("WINFW_TEST_DIR", "C:\\test") };

        forget();
        prime(vec![Mapping {
            drive: "c:".to_string(),
            device: "\\device\\harddiskvolume3".to_string(),
        }]);

        assert_eq!(
            to_device_path("%WINFW_TEST_DIR%\\tool.exe"),
            "\\device\\harddiskvolume3\\test\\tool.exe"
        );
    }

    #[test]
    fn expand_short_path_falls_back_to_the_input() {
        let known = expand_short_path("c:\\windows\\system32\\notepad.exe");
        assert!(known.ends_with("notepad.exe"), "{known}");

        let unknown = "c:\\windows\\definitely-not-here-9x.exe";
        assert_eq!(expand_short_path(unknown), unknown);
    }
}
