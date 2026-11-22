//! The service identities a rule can name.
//!
//! A Windows service owns a per-service SID derived from its name, and WFP reports the
//! connection of a hosted service with that SID in its token. Naming the service therefore
//! narrows a rule for `svchost.exe` to the one service the person meant — the difference between
//! permitting a program and permitting every program that lives inside it.

use anyhow::{Result, bail};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetSecurityDescriptorLength, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, SID_NAME_USE,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfigW,
    SC_MANAGER_CONNECT, SERVICE_QUERY_CONFIG,
};
use windows::core::{PCWSTR, PWSTR};

/// Resolve a service name to its per-service SID, or `None` when the machine has no service of
/// that name.
///
/// `NT SERVICE\<name>` is the account the local security database answers for an installed
/// service, and a name nothing has installed maps to nothing — which is what turns the lookup
/// into the existence check at the same time.
pub(crate) fn resolve(name: &str) -> Option<Vec<u8>> {
    lookup_sid(&format!("NT SERVICE\\{name}"))
}

/// The SID of an account name as the local security database answers it, or `None` when the
/// name maps to nothing.
fn lookup_sid(account: &str) -> Option<Vec<u8>> {
    let wide: Vec<u16> = account.encode_utf16().chain(std::iter::once(0)).collect();

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
            PCWSTR(wide.as_ptr()),
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
            PCWSTR(wide.as_ptr()),
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

/// The account a service runs as, as its name is written in the service configuration
/// (`NT AUTHORITY\NetworkService`, `LocalSystem`, `NT SERVICE\<name>`, or a user account).
///
/// The SCM answers through an open-and-close pair of handles; reading the configuration only
/// asks for what every logged-on account may read.
fn logon_account(name: &str) -> Result<String> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    let manager = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
        .map_err(|error| anyhow::anyhow!("the service map refused the read: {error}"))?;

    let service = unsafe { OpenServiceW(manager, PCWSTR(wide.as_ptr()), SERVICE_QUERY_CONFIG) };

    // The manager handle is closed on every way out; only a service that opened is queried.
    let service = match service {
        Ok(service) => service,
        Err(error) => {
            let _ = unsafe { CloseServiceHandle(manager) };
            bail!("service '{name}' could not be opened for the account read: {error}");
        }
    };

    // Two calls again: the first measures the configuration, the second fills a buffer sized
    // from that number.
    let mut needed = 0u32;
    let _ = unsafe { QueryServiceConfigW(service, None, 0, &mut needed) };

    let mut buffer = vec![0u8; needed.max(1) as usize];
    let status = unsafe {
        QueryServiceConfigW(
            service,
            Some(buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW),
            needed,
            &mut needed,
        )
    };

    let account = if status.is_ok() {
        // SAFETY: the call answered `ok` over a buffer it filled with a configuration whose
        // strings live inside it, and the slice is at least one struct wide.
        let config = unsafe { &*(buffer.as_ptr() as *const QUERY_SERVICE_CONFIGW) };

        // SAFETY: the start name is a NUL-terminated wide string inside the buffer above.
        unsafe { config.lpServiceStartName.to_string() }.unwrap_or_default()
    } else {
        String::new()
    };

    let _ = unsafe { CloseServiceHandle(service) };
    let _ = unsafe { CloseServiceHandle(manager) };

    Ok(account)
}

/// The security descriptor a service condition is matched against: it grants access to every
/// named service and to the account each named service runs as, so one filter matches any of
/// them.
///
/// The account SID is not decoration. The kernel classifies a shared-`svchost` service's
/// connection with the logon account as its user (`S-1-5-20` for NetworkService), not with the
/// per-service SID, so a descriptor naming only the per-service SID matches no traffic at all.
///
/// `Err` names a service the machine does not have, which is what turns a typo in a hand-edited
/// rules file into a refused store rebuild rather than a rule that silently grew back to the
/// whole program.
pub(crate) fn security_descriptor(names: &[String]) -> Result<Option<ServiceSd>> {
    if names.is_empty() {
        return Ok(None);
    }

    let mut sddl = String::from("O:SYG:SYD:");
    let mut granted: Vec<String> = Vec::new();

    for name in names {
        let sid = match resolve(name) {
            Some(sid) => sid,
            None => bail!("service '{name}' is not installed"),
        };

        grant(&mut sddl, &mut granted, &sid_text(&sid)?)?;

        // The account a `NT SERVICE\<name>` virtual account runs as is the service itself, and
        // the second grant would repeat the first; the seen list keeps such pairs out.
        let account = logon_account(name)?;

        if !account.is_empty() {
            match lookup_sid(&account) {
                Some(sid) => grant(&mut sddl, &mut granted, &sid_text(&sid)?)?,
                None => bail!("service '{name}' runs as '{account}', which is no account here"),
            }
        }
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

    // SAFETY: the descriptor is the freshly allocated one the call above just returned.
    let length = unsafe { GetSecurityDescriptorLength(psd) };

    Ok(Some(ServiceSd {
        // The value shape `FwpmFilterAdd0` marshals for a security-descriptor condition is a
        // pointer to this blob, not the descriptor itself (fwptypes.idl:
        // `[case(FWP_SECURITY_DESCRIPTOR_TYPE)] [unique] FWP_BYTE_BLOB* sd`). Handing the stub
        // the raw descriptor instead makes it read the descriptor's own first four bytes as a
        // size and follow a garbage data pointer, and the install fails as
        // RPC_X_BAD_STUB_DATA.
        blob: FWP_BYTE_BLOB {
            size: length,
            data: psd.0 as *mut u8,
        },
        psd,
    }))
}

/// Append one grant to the descriptor unless the same SID was granted for an earlier name.
///
/// The mask is the specific-rights spelling Windows' own filter manager writes (`CCRC`), not
/// `GA`: a generic mask was measured here not to match any connection, while the
/// specific-rights spelling on the same field and match type does.
fn grant(sddl: &mut String, granted: &mut Vec<String>, sid: &str) -> Result<()> {
    if !granted.iter().any(|seen| seen == sid) {
        granted.push(sid.to_owned());
        sddl.push_str(&format!("(A;;CCRC;;;{sid})"));
    }

    Ok(())
}

/// The descriptor a service condition carries, alive for as long as the conditions of a filter
/// point into it. The system allocated the descriptor, so it goes back through `LocalFree`;
/// the blob is a view of it, not a second allocation.
pub(crate) struct ServiceSd {
    pub(crate) psd: PSECURITY_DESCRIPTOR,
    /// The descriptor sized and framed the way the RPC stub of `FwpmFilterAdd0` reads it.
    /// Its `data` points into `psd`.
    pub(crate) blob: FWP_BYTE_BLOB,
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
        // The blob is the framing the RPC stub reads, so it must describe the descriptor.
        assert!(owned.blob.size > 0, "a security descriptor has a length");
        assert_eq!(
            owned.blob.data, owned.psd.0 as *mut u8,
            "the blob points into the descriptor it frames"
        );
    }

    /// The kernel classifies a shared-`svchost` service's connection with the logon account as
    /// its user, so a descriptor that names only the per-service SID matches no traffic. This
    /// reads the built descriptor back and asks whether the account it grants is in there.
    #[test]
    fn a_descriptor_grants_the_service_account_too() {
        use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
        use windows::Win32::Security::DACL_SECURITY_INFORMATION;

        let names = vec!["Dnscache".to_owned()];
        let owned = security_descriptor(&names)
            .expect("the descriptor is built")
            .expect("one name is not none");

        let mut text = PWSTR::null();

        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                owned.psd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
        }
        .map_err(|error| anyhow::anyhow!("the descriptor would not read back: {error}"))
        .expect("read the descriptor as text");

        let read = unsafe { text.to_string().expect("the text is a string") };

        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        }

        assert!(
            read.contains("S-1-5-80-") && (read.contains("S-1-5-20") || read.contains("CCRC;;;NS")),
            "the descriptor grants the service and its account: {read}"
        );
    }

    #[test]
    fn a_descriptor_names_every_service_in_the_list() {
        let names = vec!["Dnscache".to_owned(), "Dhcp".to_owned()];

        let _ = security_descriptor(&names).expect("both names build one descriptor");
    }
}
