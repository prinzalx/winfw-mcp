//! Turn the security identifier of an event into the account name a human recognizes.
//!
//! WFP hands the user of a connection to the event callback as a `PSID` in the event header. The
//! pointer is only valid while the callback runs, and resolving it is a lookup that — for a domain
//! account — may go out over the network. Neither is a problem for a single event, but a busy
//! machine produces hundreds of events per second for the same handful of accounts, so the answer
//! is cached behind a lock and the pointer is never kept.
//!
//! A name that cannot be resolved is reported as the SID text instead of nothing at all: "who ran
//! this" is more useful as `S-1-5-21-…` than as a blank column, and it tells "lookup failed" apart
//! from "the event named no user".

/// How many accounts the cache holds before it is thrown away.
///
/// The set of accounts on one machine is small, and an event callback must not block for long, so
/// the cheapest policy is a hard bound with a reset rather than an eviction scheme.
const CACHE_LIMIT: usize = 64;

/// The account name behind a security identifier, cached for the lifetime of the process.
///
/// Returns `None` for a null identifier, which is what an event that names no user carries. A
/// lookup that fails reports the SID text, so nothing is lost and the caller never has to handle
/// an error in a callback that has nowhere to report one.
///
/// On a non-Windows build there is no WFP event to answer, so this is a stub.
#[cfg(windows)]
pub(crate) fn account_name(sid: windows::Win32::Security::PSID) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    /// The cached answers, keyed by the text form of the identifier. `None` as a value means "we
    /// tried and could not resolve it", which keeps a failing lookup from being retried per event.
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();

    if sid.0.is_null() {
        return None;
    }

    // The text form is only the cache key. The lookup itself uses the pointer the event gave us,
    // so there is no copy of the identifier to allocate and release for every event.
    let sid_text = unsafe { sid_text(sid) }?;

    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("user cache lock poisoned");

    if let Some(known) = cache.get(&sid_text) {
        return Some(known.clone().unwrap_or_else(|| sid_text.clone()));
    }

    if cache.len() == CACHE_LIMIT {
        cache.clear();
    }

    let name = unsafe { lookup_account(sid) };
    cache.insert(sid_text.clone(), name.clone());
    Some(name.unwrap_or(sid_text))
}

/// The text form of an identifier (`S-1-5-21-…`), or `None` when the conversion fails.
#[cfg(windows)]
unsafe fn sid_text(sid: windows::Win32::Security::PSID) -> Option<String> {
    use windows::Win32::Foundation::HLOCAL;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::core::PWSTR;

    let mut text = PWSTR::null();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
        return None;
    }

    let copied = unsafe { text.to_string() }.ok();
    // The conversion allocates, and the API hands that memory to us to release.
    let _ = unsafe { windows::Win32::Foundation::LocalFree(Some(HLOCAL(text.0.cast()))) };
    copied
}

/// The account behind an identifier, as `DOMAIN\name`, or `None` when the lookup fails.
///
/// The identifier is read, not kept, which is what makes this safe to call from a callback whose
/// memory is released as soon as it returns.
#[cfg(windows)]
unsafe fn lookup_account(sid: windows::Win32::Security::PSID) -> Option<String> {
    use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
    use windows::core::{PCWSTR, PWSTR};

    // Two passes, as the API requires: the first reports the buffer sizes and fails, the second
    // fills buffers of exactly that size.
    let mut name_len: u32 = 0;
    let mut domain_len: u32 = 0;
    let mut use_type = SID_NAME_USE::default();

    unsafe {
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut domain_len,
            &mut use_type,
        );
    }

    if name_len == 0 {
        return None;
    }

    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];

    if unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut use_type,
        )
    }
    .is_err()
    {
        return None;
    }

    // The lengths the API writes back exclude the terminator; the buffers include room for it.
    let account = cut(&name, name_len);
    let domain = cut(&domain, domain_len);

    if account.is_empty() {
        None
    } else if domain.is_empty() {
        Some(account)
    } else {
        Some(format!("{domain}\\{account}"))
    }
}

/// The text a `LookupAccountSidW` buffer holds, up to the length the API reported.
#[cfg(windows)]
fn cut(buffer: &[u16], len: u32) -> String {
    let end = (len as usize).min(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// Stub for the platforms that have no WFP events.
#[cfg(not(windows))]
pub(crate) fn account_name(_sid: *mut core::ffi::c_void) -> Option<String> {
    None
}
