//! What a program file is: a Windows component, a signed third-party program, or unsigned.
//!
//! Every rule names a path, and a path says nothing about who put the file there. The firewall
//! itself only ever sees the path, so a service host and a downloader that happens to sit in the
//! same folder look the same. This module answers the question the path cannot, from the two
//! things the file system does record: whether the file carries a signature Windows trusts —
//! embedded in the file or held in a system security catalog — and who owns the file.
//!
//! The answer is kept for the life of the process. A file that changes its signature under us is
//! a reinstall, and a reinstall means a restart anyway.

/// Who a program file belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Signed to Windows standards and owned by the system installer: a component of the
    /// operating system itself.
    Windows,
    /// Signed, but not owned by the system installer: somebody else installed it.
    ThirdParty,
    /// Nothing vouches for the file: no embedded signature and no catalog entry.
    Unsigned,
}

impl Origin {
    /// The name the state API answers with.
    pub fn label(self) -> &'static str {
        match self {
            Origin::Windows => "windows",
            Origin::ThirdParty => "third_party",
            Origin::Unsigned => "unsigned",
        }
    }
}

/// The programs that run whatever they are handed: owned by Microsoft, reachable by any script,
/// and therefore trusted by nobody by default. A Windows component that interprets is the
/// downloader's trick — `certutil` fetches, `mshta` executes — so the origin answer names the
/// interpreter rather than letting the Windows side of the file vouch for the script inside it.
pub fn interpreter(path: &str) -> bool {
    let leaf = path.rsplit(['/', '\\']).next().unwrap_or(path);

    matches!(
        leaf.to_lowercase().as_str(),
        "powershell.exe"
            | "cmd.exe"
            | "curl.exe"
            | "certutil.exe"
            | "mshta.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "rundll32.exe"
    )
}

/// The origin of one file, or `None` when nothing can be said about it — a missing file mostly,
/// since a file that is merely unsigned is answered, not refused.
#[cfg(windows)]
pub fn of(path: &str) -> Option<Origin> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// How many answers are remembered before the memory is dropped rather than grown
    /// without end.
    const CACHE_LIMIT: usize = 4096;

    static CACHE: OnceLock<Mutex<HashMap<String, Option<Origin>>>> = OnceLock::new();

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("signature cache lock poisoned");

    if let Some(known) = cache.get(path) {
        return *known;
    }

    if cache.len() == CACHE_LIMIT {
        cache.clear();
    }

    let answer = look(path);
    cache.insert(path.to_string(), answer);
    answer
}

/// There is no file signature to read off a non-Windows build, so nothing is known.
#[cfg(not(windows))]
pub fn of(_path: &str) -> Option<Origin> {
    None
}

/// The one place the question is actually answered, on a cache miss.
#[cfg(windows)]
fn look(path: &str) -> Option<Origin> {
    // A missing file is not an unsigned file: saying "unsigned" here would convict a rule whose
    // program was simply never installed on this drive.
    std::fs::metadata(path).ok()?;

    if !signed(path) {
        return Some(Origin::Unsigned);
    }

    // Signed. The owner separates the operating system's own files from everything else; an
    // owner we cannot read counts as somebody else's, which is the cautious side of the guess.
    if owner_is_system(path) {
        Some(Origin::Windows)
    } else {
        Some(Origin::ThirdParty)
    }
}

/// Whether the file carries a signature Windows trusts, embedded or cataloged.
///
/// A failure of the verification machinery counts as "not signed", which is the direction that
/// cannot hand a program more trust than it earned.
#[cfg(windows)]
fn signed(path: &str) -> bool {
    unsafe { embedded(path) || cataloged(path) }
}

/// The embedded Authenticode signature of one file, checked without any network call.
#[cfg(windows)]
unsafe fn embedded(path: &str) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::WinTrust::{
        WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::core::PCWSTR;

    let wide = drive_wide(path);

    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &raw mut file,
        },
        ..Default::default()
    };

    unsafe { verify(&mut data) }
}

/// Whether a system security catalog vouches for the file — the signature form system files
/// themselves carry.
#[cfg(windows)]
unsafe fn cataloged(path: &str) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminReleaseContext,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::core::{PCWSTR, w};

    let wide = drive_wide(path);

    // One administrator context per question, released on every exit below. SHA-256 is the
    // catalog hash of every catalog this machine's system files are indexed under.
    let mut admin = 0isize;
    if unsafe { CryptCATAdminAcquireContext2(&mut admin, None, w!("SHA256"), None, None) }.is_err()
    {
        return false;
    }

    let mut file = match unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            0x8000_0000, // GENERIC_READ
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    } {
        Ok(handle) => handle,
        Err(_) => {
            unsafe {
                let _ = CryptCATAdminReleaseContext(admin, 0);
            };
            return false;
        }
    };

    let verdict = unsafe { cataloged_with_context(admin, &mut file, &wide, path) };

    unsafe {
        let _ = CloseHandle(file);
        let _ = CryptCATAdminReleaseContext(admin, 0);
    }

    verdict
}

/// The catalog question once the administrator context and the open file are in hand.
#[cfg(windows)]
unsafe fn cataloged_with_context(
    admin: isize,
    file: &mut windows::Win32::Foundation::HANDLE,
    wide: &[u16],
    path: &str,
) -> bool {
    use windows::Win32::Security::Cryptography::Catalog::{
        CATALOG_INFO, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
        CryptCATAdminReleaseCatalogContext, CryptCATCatalogInfoFromContext,
    };
    use windows::Win32::Security::WinTrust::{
        WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0, WTD_CHOICE_CATALOG, WTD_REVOKE_NONE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    use windows::core::PCWSTR;

    // The hash of the file is what catalogs index, so it is what a lookup has to present. The
    // length comes back from a call with no buffer; the hash itself from the second one.
    let mut length = 0u32;
    if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin, *file, &mut length, None, None) }
        .is_err()
    {
        return false;
    }

    let mut hash = vec![0u8; length as usize];
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            *file,
            &mut length,
            Some(hash.as_mut_ptr()),
            None,
        )
    }
    .is_err()
    {
        return false;
    }

    // The first catalog that holds the hash is enough to ask; the enumeration exists to walk
    // further, which a plain trust question does not need.
    let catalog = unsafe { CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None) };
    if catalog == 0 {
        return false;
    }

    let mut info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };

    if unsafe { CryptCATCatalogInfoFromContext(catalog, &mut info, 0) }.is_err() {
        unsafe {
            let _ = CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
        };
        return false;
    }

    let catalog_path = utf16_from_buffer(&info.wszCatalogFile);
    let member_tag = leaf_wide(path);

    let mut entry = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 1,
        pcwszCatalogFilePath: PCWSTR(catalog_path.as_ptr()),
        pcwszMemberTag: PCWSTR(member_tag.as_ptr()),
        pcwszMemberFilePath: PCWSTR(wide.as_ptr()),
        hMemberFile: *file,
        pbCalculatedFileHash: hash.as_mut_ptr(),
        cbCalculatedFileHash: length,
        hCatAdmin: admin,
        ..Default::default()
    };

    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        dwStateAction: WTD_STATEACTION_VERIFY,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &raw mut entry,
        },
        ..Default::default()
    };

    unsafe { verify(&mut data) }
}

/// Ask WinVerifyTrust about one prepared block and release whatever state the asking left.
#[cfg(windows)]
unsafe fn verify(data: &mut windows::Win32::Security::WinTrust::WINTRUST_DATA) -> bool {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WTD_STATEACTION_CLOSE, WinVerifyTrustEx,
    };

    // The action identifier is a constant, so it needs a place of its own to point at; the
    // API declares it by mutable pointer even though it only ever reads it.
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    let verdict = unsafe { WinVerifyTrustEx(HWND::default(), &raw mut action, data) };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrustEx(HWND::default(), &raw mut action, data) };

    verdict == 0
}

/// Whether the file belongs to the operating system: its owner is the local system account or a
/// service identity, which is what TrustedInstaller leaves on the files it installs.
#[cfg(windows)]
fn owner_is_system(path: &str) -> bool {
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSID};
    use windows::core::{PCWSTR, PWSTR};

    let wide = drive_wide(path);

    let mut owner = PSID::default();
    let error = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            std::ptr::null_mut(),
        )
    };

    if error != ERROR_SUCCESS || owner.0.is_null() {
        return false;
    }

    let mut text = PWSTR::null();
    let converted = unsafe { ConvertSidToStringSidW(owner, &mut text) }.is_ok();

    let answer = if converted {
        // The local system account exactly, or any identity under the service prefix that
        // TrustedInstaller and the service SIDs share. The exact match on the system account is
        // not fussiness: S-1-5-1, the Users group, is a prefix of its text.
        let text = unsafe { text.to_string() }.unwrap_or_default();
        text == "S-1-5-18" || text.starts_with("S-1-5-80-")
    } else {
        false
    };

    unsafe {
        if !text.is_null() {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }
    }

    answer
}

/// The null-terminated UTF-16 form of a path, ready for a PCWSTR.
#[cfg(windows)]
fn drive_wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = std::ffi::OsStr::new(value).encode_wide().collect();
    wide.push(0);
    wide
}

/// The file name a path ends with, as written, for a catalog member tag.
#[cfg(windows)]
fn leaf_wide(path: &str) -> Vec<u16> {
    let leaf = path.rsplit(['/', '\\']).next().unwrap_or(path);
    drive_wide(leaf)
}

/// The text inside a fixed UTF-16 buffer that ends at its first zero, kept null-terminated.
#[cfg(windows)]
fn utf16_from_buffer(buffer: &[u16]) -> Vec<u16> {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());

    let mut text = buffer[..end].to_vec();
    text.push(0);
    text
}

#[cfg(test)]
mod tests {
    use super::{Origin, interpreter, of};

    /// The service host is installed by the operating system, so it has to answer Windows. This
    /// is the file the backlog's blanket permit is all about, so its answer matters twice.
    #[cfg(windows)]
    #[test]
    fn the_service_host_is_a_windows_file() {
        let path = format!(
            "{}\\System32\\svchost.exe",
            std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string())
        );
        assert_eq!(of(&path), Some(Origin::Windows), "{path}");
    }

    /// Our own test binary is built here, signed by nobody, so it has to answer Unsigned.
    #[cfg(windows)]
    #[test]
    fn the_test_binary_is_unsigned() {
        let ours = std::env::current_exe().expect("the test binary knows itself");
        let path = ours.to_string_lossy().to_string();
        assert_eq!(of(&path), Some(Origin::Unsigned), "{path}");
    }

    /// A file that is not there is not a file without a signature; nothing is known about it.
    #[test]
    fn a_missing_file_has_no_origin() {
        assert_eq!(of("Q:\\never\\installed\\nowhere.exe"), None);
    }

    /// The downloader's crowd is named despite its Windows ownership, and only that crowd:
    /// a service host runs services, not scripts.
    #[test]
    fn the_interpreters_are_the_blocklisted_names() {
        assert!(interpreter(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        ));
        assert!(interpreter("C:\\Windows\\System32\\cmd.exe"));
        assert!(interpreter("C:\\Windows\\System32\\certutil.exe"));
        assert!(interpreter("C:\\tools\\Curl\\CURL.EXE"));
        assert!(!interpreter("C:\\Windows\\System32\\svchost.exe"));
    }
}
