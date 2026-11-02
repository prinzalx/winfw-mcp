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

use std::sync::atomic::{AtomicU64, Ordering};
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

/// The mappings of this machine, resolved on first use and replaced when a lookup misses.
///
/// The read lock is dropped before the write lock is taken, which matters because a lock is never
/// held across a system call.
static CACHE: RwLock<Option<Arc<[Mapping]>>> = RwLock::new(None);

/// When the last re-ask happened, in milliseconds since the epoch.
static LAST_QUERY_MS: AtomicU64 = AtomicU64::new(0);

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
    *CACHE.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::clone(&fresh));

    fresh
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
}
