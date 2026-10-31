//! Translation between drive paths (`C:\dir\a.exe`) and the NT device paths WFP and the event
//! stream use (`\device\harddiskvolume3\dir\a.exe`).
//!
//! The two forms mean the same file, and which one a user writes is a matter of habit: a rule
//! typed by hand says `C:\`, while an event reported by the firewall says
//! `\device\harddiskvolumeN\`. Learning mode has to compare the two, so the mapping is resolved
//! once per process and cached.
//!
//! Volumes can be remounted while the process runs, which is rare enough to accept: the tool is
//! restarted far more often than a drive letter changes.

/// One `(drive prefix, device prefix)` pair, both lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mapping {
    drive: String,
    device: String,
}

/// The mappings of this machine, resolved on first use.
#[cfg(windows)]
fn mappings() -> &'static [Mapping] {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Vec<Mapping>> = OnceLock::new();

    CACHE.get_or_init(query)
}

/// Ask the system which device each drive letter points at.
#[cfg(windows)]
fn query() -> Vec<Mapping> {
    use windows::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

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

#[cfg(not(windows))]
fn mappings() -> &'static [Mapping] {
    use std::sync::OnceLock;

    static CACHE: OnceLock<Vec<Mapping>> = OnceLock::new();

    CACHE.get_or_init(Vec::new)
}

/// Rewrite a drive path into device form, leaving anything else alone.
///
/// A pattern that already starts with `\device\` is returned as it stands, which is what lets a
/// rule be written in either form.
pub fn to_device_path(path: &str) -> String {
    let lowered = path.to_lowercase();

    if lowered.starts_with("\\device\\") || lowered.starts_with("\\??\\") {
        return lowered;
    }

    for mapping in mappings() {
        if let Some(rest) = lowered.strip_prefix(&mapping.drive) {
            // The separator belongs to the drive prefix in the device form, and `strip_prefix`
            // leaves it on `rest`, where it is already in the shape we need.
            return format!("{}{rest}", mapping.device);
        }
    }

    lowered
}

/// Rewrite a device path into drive form for display, falling back to the input unchanged.
pub fn to_dos_path(path: &str) -> String {
    let lowered = path.to_lowercase();

    for mapping in mappings() {
        if let Some(rest) = lowered.strip_prefix(&mapping.device) {
            return format!("{}{rest}", mapping.drive);
        }
    }

    lowered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_device_path_is_left_in_device_form() {
        assert_eq!(
            to_device_path("\\Device\\HarddiskVolume3\\windows\\a.exe"),
            "\\device\\harddiskvolume3\\windows\\a.exe"
        );
    }

    #[test]
    fn an_unknown_shape_is_only_lowercased() {
        assert_eq!(to_device_path("not a path"), "not a path");
    }

    #[test]
    fn a_real_drive_round_trips_to_device_form_and_back() {
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
}
