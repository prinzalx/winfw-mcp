//! The service identities a rule can name.
//!
//! A Windows service owns a per-service SID derived from its name, and WFP reports the
//! connection of a hosted service with that SID in its token. Naming the service therefore
//! narrows a rule for `svchost.exe` to the one service the person meant — the difference between
//! permitting a program and permitting every program that lives inside it.

use anyhow::{Result, bail};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE};
use windows::core::{PCWSTR, PWSTR};

/// Resolve a service name to its per-service SID, or `None` when the machine has no service of
/// that name.
///
/// `NT SERVICE\<name>` is the account the local security database answers for an installed
/// service, and a name nothing has installed maps to nothing — which is what turns the lookup
/// into the existence check at the same time.
pub(crate) fn resolve(name: &str) -> Option<Vec<u8>> {
    let account: Vec<u16> = format!("NT SERVICE\\{name}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // Two calls: the first measures the SID and its account name, the second fills buffers sized
    // from those numbers. Only the measured length of the SID decides the answer. The account
    // type rides on a real variable: the API writes the domain and the SID only once it can
    // also write the type, which is the pattern the monitor's lookups already use.
    let mut sid_len = 0u32;
    let mut domain_len = 0u32;
    let mut use_type = SID_NAME_USE::default();

    let _ = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut domain_len,
            &mut use_type,
        )
    };

    if sid_len == 0 {
        return None;
    }

    let mut buffer = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len.max(1) as usize];
    let sid = PSID(buffer.as_mut_ptr() as *mut core::ffi::c_void);

    let status = unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(account.as_ptr()),
            Some(sid),
            &mut sid_len,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_len,
            &mut use_type,
        )
    };

    if !status.is_ok() {
        return None;
    }

    buffer.truncate(sid_len as usize);
    Some(buffer)
}

/// The security descriptor a service condition is matched against: it grants access to every
/// named service, so one filter matches any of them.
///
/// `Err` names a service the machine does not have, which is what turns a typo in a hand-edited
/// rules file into a refused store rebuild rather than a rule that silently grew back to the
/// whole program.
pub(crate) fn security_descriptor(names: &[String]) -> Result<Option<ServiceSd>> {
    if names.is_empty() {
        return Ok(None);
    }

    let mut sddl = String::from("D:");

    for name in names {
        let sid = match resolve(name) {
            Some(sid) => sid,
            None => bail!("service '{name}' is not installed"),
        };

        sddl.push_str(&format!("(A;;GA;;;{})", sid_text(&sid)?));
    }

    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut psd = PSECURITY_DESCRIPTOR::default();

    // SAFETY: the buffer is NUL-terminated wide text the descriptor is read from, and the
    // pointer receives the freshly allocated descriptor.
    let status = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    };

    status
        .map_err(|error| anyhow::anyhow!("the service descriptor '{sddl}' was refused: {error}"))?;

    Ok(Some(ServiceSd { psd }))
}

/// The descriptor WFP points at for as long as the conditions of a filter live. The system
/// allocated it, so it goes back through `LocalFree`.
pub(crate) struct ServiceSd {
    pub(crate) psd: PSECURITY_DESCRIPTOR,
}

impl Drop for ServiceSd {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.psd.0)));
        }
    }
}

/// The text form of a SID, as SDDL names it.
fn sid_text(sid: &[u8]) -> Result<String> {
    let mut text = PWSTR::null();

    unsafe { ConvertSidToStringSidW(PSID(sid.as_ptr() as *mut core::ffi::c_void), &mut text) }?;

    // SAFETY: the call above filled the pointer with a NUL-terminated system string.
    let read = unsafe { text.to_string()? };

    unsafe {
        // The system allocated the text; the SID bytes belong to the caller's buffer.
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
    }

    Ok(read)
}

/// The SDDL revision the descriptor is read at, which is the only one the API takes.
const SDDL_REVISION_1: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_service_resolves_to_nothing() {
        assert_eq!(resolve("NoServiceHere99"), None);
    }

    #[test]
    fn a_known_service_resolves_to_a_sid() {
        let sid = resolve("Dnscache").expect("Dnscache is installed on every Windows machine");

        assert!(sid.len() >= 8, "a SID has a revision, a count and a prefix");
    }

    #[test]
    fn a_descriptor_grants_the_named_service() {
        let names = vec!["Dnscache".to_owned()];
        let owned = security_descriptor(&names)
            .expect("the descriptor is built")
            .expect("one name is not none");

        assert!(!owned.psd.0.is_null());
    }

    #[test]
    fn a_descriptor_names_every_service_in_the_list() {
        let names = vec!["Dnscache".to_owned(), "Dhcp".to_owned()];

        let _ = security_descriptor(&names).expect("both names build one descriptor");
    }
}
