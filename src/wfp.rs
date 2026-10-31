//! Read-only access to the Windows Filtering Platform store.
//!
//! This is the only module that talks to WFP, and for now it only looks: open the engine, then
//! enumerate providers, sublayers and filters. Writes come with milestone 3, inside a
//! transaction, from a single worker task.

use std::ffi::c_void;

use anyhow::{Result, bail};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_PROVIDER0, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterCreateEnumHandle0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0,
    FwpmFreeMemory0, FwpmProviderCreateEnumHandle0, FwpmProviderDestroyEnumHandle0,
    FwpmProviderEnum0, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0,
    FwpmSubLayerEnum0,
};
use windows::core::PCWSTR;

/// `RPC_C_AUTHN_DEFAULT`, spelled out instead of pulling in the RPC module for one constant.
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;

/// The display names of one class of store entries.
pub type Entries = Result<Vec<String>>;

/// Run one of the three enumeration sequences end to end and collect the display names.
///
/// The three `Fwpm*` families differ only in name and entry type, which is what makes them worth
/// a macro rather than three copies of the same loop.
///
/// Everything is requested in a single call, the way the C reference does it. Not only is that
/// one round trip instead of several, it also keeps the ownership rule simple: the whole result
/// is one WFP allocation, released by handing the *array pointer* to `FwpmFreeMemory0`. Freeing
/// the individual elements as well corrupts the heap, because they were never allocated apart
/// from the array.
macro_rules! enumerate {
    ($engine:expr, $create:ident, $fetch:ident, $destroy:ident, $entry:ty) => {{
        let engine = $engine;
        let mut enum_handle = HANDLE::default();

        // SAFETY: a null template asks for every entry, and `enum_handle` is an out parameter.
        let status = unsafe { $create(engine, None, &mut enum_handle) };
        if status != 0 {
            anyhow::bail!("{} failed with 0x{status:08X}", stringify!($create));
        }

        let mut entries: *mut *mut $entry = std::ptr::null_mut();
        let mut returned = 0u32;

        // SAFETY: both out parameters are valid, and the array they receive belongs to WFP.
        let status = unsafe { $fetch(engine, enum_handle, u32::MAX, &mut entries, &mut returned) };
        if status != 0 {
            // SAFETY: the enum handle is still open and belongs to this engine.
            unsafe { $destroy(engine, enum_handle) };
            anyhow::bail!("{} failed with 0x{status:08X}", stringify!($fetch));
        }

        let mut names = Vec::new();

        if !entries.is_null() {
            for index in 0..returned {
                // SAFETY: WFP reported `returned` entries, so this slot is inside the array.
                let entry = unsafe { *entries.add(index as usize) };

                if !entry.is_null() {
                    // SAFETY: the entry stays readable until the array is handed back below.
                    names.push(display_name(unsafe { &(*entry).displayData }));
                }
            }

            // SAFETY: the array is WFP-owned, and this is the documented way to release it.
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
        }

        // SAFETY: the enum handle is still open and belongs to this engine.
        unsafe { $destroy(engine, enum_handle) };
        Ok(names)
    }};
}

/// A handle to the WFP engine.
///
/// The handle is process-wide and has to outlive every query, so it belongs to the long-running
/// core rather than to one request (PLAN.md section 5).
#[derive(Debug)]
pub struct Engine {
    handle: HANDLE,
}

/// What each class of store entry reported. The outcomes stay separate on purpose: WFP grants
/// read access per class, so a process can be allowed to read the filters and still be refused
/// the provider store. Collapsing that into one error would hide which part we are missing.
#[derive(Debug)]
pub struct Inventory {
    pub providers: Entries,
    pub sublayers: Entries,
    pub filters: Entries,
}

impl Engine {
    /// Open a connection to the engine.
    ///
    /// The C reference retries here, because the Base Filtering Engine can be briefly unavailable
    /// during boot. Until there are writes to protect there is no reason to retry: a caller that
    /// fails this early is not under time pressure.
    pub fn open() -> Result<Self> {
        let mut handle = HANDLE::default();

        // SAFETY: `handle` is a valid out parameter, a null server name means the local machine,
        // and a null session selects the default non-dynamic session.
        let status = unsafe {
            FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_DEFAULT, None, None, &mut handle)
        };

        if status != 0 {
            bail!(
                "FwpmEngineOpen0 failed with 0x{status:08X}; is the Base Filtering Engine running?"
            );
        }

        Ok(Self { handle })
    }

    /// Read every class we care about in one call.
    pub fn inventory(&self) -> Inventory {
        Inventory {
            providers: self.providers(),
            sublayers: self.sublayers(),
            filters: self.filters(),
        }
    }

    pub fn providers(&self) -> Entries {
        enumerate!(
            self.handle,
            FwpmProviderCreateEnumHandle0,
            FwpmProviderEnum0,
            FwpmProviderDestroyEnumHandle0,
            FWPM_PROVIDER0
        )
    }

    pub fn sublayers(&self) -> Entries {
        enumerate!(
            self.handle,
            FwpmSubLayerCreateEnumHandle0,
            FwpmSubLayerEnum0,
            FwpmSubLayerDestroyEnumHandle0,
            FWPM_SUBLAYER0
        )
    }

    pub fn filters(&self) -> Entries {
        enumerate!(
            self.handle,
            FwpmFilterCreateEnumHandle0,
            FwpmFilterEnum0,
            FwpmFilterDestroyEnumHandle0,
            FWPM_FILTER0
        )
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: the handle came from FwpmEngineOpen0 and is closed exactly once.
            unsafe { FwpmEngineClose0(self.handle) };
        }
    }
}

/// Copy a display name out of WFP-owned memory. A null name is not an error; an empty string
/// keeps the listing usable.
fn display_name(data: &FWPM_DISPLAY_DATA0) -> String {
    if data.name.is_null() {
        return String::new();
    }

    // SAFETY: the pointer is not null, and WFP guarantees a terminated wide string there.
    unsafe { data.name.to_string() }.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read the live store, and assert on whatever we are allowed to read.
    ///
    /// Measured on this machine: an unelevated process opens the engine without problem but every
    /// enumeration answers `0x00000005`, so reading the store needs elevation just like writing it
    /// does. A run that is allowed to read must see entries, which is the case the assertions
    /// cover; a run that is refused reports it and is visible with `--nocapture`.
    #[test]
    fn the_live_store_reads_or_reports_access_denied() {
        let engine = Engine::open().expect("open engine");

        for (category, entries) in [
            ("providers", engine.providers()),
            ("sublayers", engine.sublayers()),
            ("filters", engine.filters()),
        ] {
            match entries {
                Ok(names) => {
                    assert!(!names.is_empty(), "{category}: Windows always has entries");
                    println!("{category}: read {} entries", names.len());
                }
                Err(error) => {
                    let reason = format!("{error:#}");
                    assert!(
                        reason.contains("0x00000005"),
                        "{category}: unexpected failure {reason}",
                    );
                    println!("{category}: skipped, access denied");
                }
            }
        }
    }

    /// A handle that was never opened must not be handed to `FwpmEngineClose0`.
    #[test]
    fn a_default_handle_counts_as_invalid() {
        assert!(HANDLE::default().is_invalid());
    }
}
