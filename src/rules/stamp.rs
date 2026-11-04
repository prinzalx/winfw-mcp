//! The stamp that says whether a stored file changed since it was read.

use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::warn;

/// A cheap fingerprint of the contents of a rules file.
///
/// It answers one question: is this still the file the tool wrote, or did something else change
/// it? A length plus an FNV-1a hash answers that without a hashing dependency. The case it does
/// not cover is an attacker deliberately hunting for a collision, which the security chapter says
/// out loud rather than pretending otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// Bytes in the file.
    pub(crate) len: u64,
    /// FNV-1a over those bytes.
    pub(crate) hash: u64,
}

/// FNV-1a over a byte string, from any seed.
///
/// One hash for the whole tool: it answers both the file fingerprint here and the stable filter
/// keys in [`crate::wfp`], which is the only other place it was written out by hand.
pub(crate) fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;

    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// The start value of FNV-1a.
pub(crate) const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// The multiplier of FNV-1a.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

impl Fingerprint {
    /// The fingerprint of bytes exactly as they are on disk.
    pub(crate) fn of(bytes: &[u8]) -> Self {
        Self {
            len: bytes.len() as u64,
            hash: fnv1a(FNV_OFFSET, bytes),
        }
    }

    /// Read a file and fingerprint it. `None` means the file is not there, which is a state of its
    /// own rather than an empty file.
    pub fn of_file(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(Self::of(&bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(anyhow::Error::new(error).context(format!("read {}", path.display())))
            }
        }
    }
}

/// The stamp file that belongs to a rules file: `rules.toml` gets `rules.toml.stamp`.
///
/// Living next to the file it describes means a profile needs no bookkeeping of its own, and it
/// follows the `.bak` pattern [`RuleFile::save`] already uses.
pub fn stamp_path(rules_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.stamp", rules_file.display()))
}

/// Record what the tool just wrote, so the next start can tell its own work from an outside edit.
///
/// A stamp that cannot be written is reported and tolerated: the worst case is that a later change
/// goes unnoticed, which is what every version before this one did all the time.
pub fn write_stamp(rules_file: &Path, fingerprint: Option<Fingerprint>) {
    let path = stamp_path(rules_file);

    let result = match fingerprint {
        Some(fingerprint) => std::fs::write(
            &path,
            format!("{:x}:{:x}\n", fingerprint.len, fingerprint.hash),
        ),
        None => std::fs::remove_file(&path),
    };

    if let Err(error) = result {
        warn!(
            file = %path.display(),
            reason = %error,
            "could not record the rules file fingerprint",
        );
    }
}

/// Read the stamp the tool left behind. `None` covers both no stamp and an unreadable one,
/// because neither can be compared against.
pub fn read_stamp(rules_file: &Path) -> Option<Fingerprint> {
    let text = std::fs::read_to_string(stamp_path(rules_file)).ok()?;
    let (len, hash) = text.trim().split_once(':')?;

    Some(Fingerprint {
        len: u64::from_str_radix(len, 16).ok()?,
        hash: u64::from_str_radix(hash, 16).ok()?,
    })
}

/// A profile name is the stem of one file in `profiles\`: a single component, no separators.
///
/// The empty name is not a profile at all — it means `rules.toml` itself — so it is rejected here;
/// the caller decides what empty means before asking.
pub fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':'])
}

/// The names of the profiles stored in `dir`, sorted, without the `.toml` suffix.
///
/// A directory that does not exist or cannot be read simply has no profiles, which is what a
/// fresh install looks like.
pub fn list_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            {
                return None;
            }

            Some(path.file_stem()?.to_str()?.to_owned())
        })
        .collect();

    names.sort();
    names
}
