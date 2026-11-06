//! The only module that talks to the Windows Filtering Platform.
//!
//! The read path opens the engine and enumerates the store. The write path turns the rule file
//! into live filters, always inside a transaction, always through the one engine handle.

use std::ffi::c_void;
use std::thread;
use std::time::Duration;

use anyhow::{Result, bail};
use tracing::warn;
use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK,
    FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL,
    FWP_MATCH_FLAGS_ANY_SET, FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0,
    FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_INDEXED,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER_FLAGS, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
    FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteByKey0,
    FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0,
    FwpmProviderAdd0, FwpmProviderCreateEnumHandle0, FwpmProviderDestroyEnumHandle0,
    FwpmProviderEnum0, FwpmSubLayerAdd0, FwpmSubLayerCreateEnumHandle0,
    FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::Win32::Security::PSECURITY_DESCRIPTOR;
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::monitor::Attribution as Owners;

use crate::config::Policy;
use crate::rules::{
    Action, Direction, Family, PortRange, Ports, Remote, Remotes, Rule, RuleFile, is_wildcard,
    wildcard_match,
};

#[macro_use]
mod enumerate;

mod addr;
mod app_id;
mod filters;
mod keys;
mod layers;

#[cfg(test)]
mod tests;

use crate::wfp::enumerate::{EnumHandle, WfpArray};
#[allow(unused_imports)] // Reached through this module by the tests.
use crate::wfp::keys::{filter_key, wide};
#[allow(unused_imports)] // Reached through this module by the tests.
use crate::wfp::layers::LAYERS;
pub(crate) use app_id::pattern_reach;

/// The name the store shows for us, in provider, sublayer and filter display data alike.
const APP_NAME: &str = env!("CARGO_PKG_NAME");

/// The provider everything we install belongs to.
///
/// Tagging is what makes "remove our filters" a targeted operation instead of a sweep through the
/// several hundred filters other software owns. The GUID is fixed rather than generated, because
/// a persistent filter has to be findable by a program that was restarted, rebooted, or upgraded
/// underneath the store.
pub const PROVIDER_KEY: GUID = GUID::from_u128(0x6f1a3ce2_8d94_4f6a_b0c7_2e5d9a1f4b83);

/// The sublayer all our filters are installed into.
///
/// A sublayer of our own gives us a weight of our own, so our rules are consulted before the
/// filters of software that did not bother to create one.
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x38c5b71e_4a26_4d09_9f81_7c6b2e0a5d14);

/// `RPC_C_AUTHN_DEFAULT`, spelled out instead of pulling in the RPC module for one constant.
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;

/// `ERROR_ALREADY_EXISTS`, the Win32 answer for "it was already there".
const ERROR_ALREADY_EXISTS: u32 = 183;

/// Both answers that mean the object is already in the store. Measured on a real store, the two
/// `Fwpm*Add0` calls answer `FWP_E_ALREADY_EXISTS` rather than the Win32 code, so accepting only
/// `ERROR_ALREADY_EXISTS` turns a normal restart into a failed apply.
fn already_exists(status: u32) -> bool {
    status == ERROR_ALREADY_EXISTS || status == FWP_E_ALREADY_EXISTS.0 as u32
}

/// Filter weight for a deny rule.
///
/// A deny is installed one step above an allow so that it wins even when the allow rule appears
/// earlier in `rules.toml`. Equal weights would be resolved by creation order, which would make
/// the outcome depend on where a rule happens to sit in the file rather than on its action.
const WEIGHT_DENY: u8 = 0x0E;

/// Filter weight for an allow rule, one step below a deny.
const WEIGHT_ALLOW: u8 = 0x0D;

/// Filter weight for the permits of the default-deny base: loopback, 6to4 and the ICMPv6 types.
///
/// Above every rule, because these are the traffic the firewall must never block whatever the
/// rules say. Mirrors the reference, which uses `FWW_IMPORTANT` for exactly these
/// (`reference wfp.c:1605-1688`).
///
/// The reference tops out at `0x0F`, and that ceiling is real: WFP answers
/// `FWP_E_INVALID_WEIGHT` for a `FWP_UINT8` weight of `0x10`, just as it does for `0`.
const WEIGHT_BASE_PERMIT: u8 = 0x0F;

/// Filter weight for the unconditional block of the default-deny base: the bottom, so every
/// permit and every rule is consulted before it (`reference wfp.c:1827-1838`). Not
/// literally zero: WFP answers `FWP_E_INVALID_WEIGHT` for a weight of `0`, which is why the
/// reference's `FWW_LOWEST` is `0x08` rather than `0x00`.
const WEIGHT_BASE_BLOCK: u8 = 0x01;

/// `FWW_SUBLAYER`, the top of a `u16` sublayer weight.
const WEIGHT_SUBLAYER: u16 = 0xFFFF;

/// The display names of one class of store entries.
///
/// Each class carries its own result, because WFP grants read access per class. A process can be
/// allowed to read the filters and still be refused the provider store, so a refusal on one class
/// is recorded rather than propagated.
pub type Entries = Result<Vec<String>>;

/// What each class of store entry reported. The outcomes stay separate on purpose: collapsing
/// them into one error would hide which part of the store we are missing.
#[derive(Debug)]
pub struct Inventory {
    pub providers: Entries,
    pub sublayers: Entries,
    pub filters: Entries,
}

/// The difference one `apply` made to the live store.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Filters that carried our provider key and are gone now.
    pub removed: usize,
    /// Filters installed from the enabled rules, counted per layer.
    pub installed: usize,
    /// What the rebuild took out of the store, named, so a startup diff can tell the user which
    /// rules the previous run had left behind.
    pub removed_rules: Vec<RemovedFilter>,
    /// The rules the rebuild installed, as name and action pairs. The base filters of a deny
    /// policy are not rules and are not in here.
    pub installed_rules: Vec<(String, bool)>,
    /// Who is who in the store that is in there now, so an event naming one of these ids can be
    /// read back as the rule that decided it.
    pub owners: Owners,
}

/// One of our filters a rebuild took out of the store, reduced to what the rules file can be
/// compared against: the rule's label, which the filters carry in their description rather than
/// their display name, and whether the filter blocked rather than permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedFilter {
    pub name: String,
    pub deny: bool,
}

/// A handle to the WFP engine.
///
/// The handle is process-wide and has to outlive every query and every write, so it belongs to
/// the long-running core rather than to one request (plan section 5).
#[derive(Debug)]
pub struct Engine {
    handle: HANDLE,
}

/// The waits between attempts to open the engine, for as long as the Base Filtering Engine is
/// allowed to still be coming up. During boot the service can answer "not available" for a few
/// seconds, and a run that gave up on the first answer would serve its whole session without a
/// store (plan section 5). One attempt runs before the first wait and one after each of them,
/// so the policy is five attempts over 3.7 seconds.
const OPEN_WAITS: [Duration; 4] = [
    Duration::from_millis(200),
    Duration::from_millis(500),
    Duration::from_millis(1_000),
    Duration::from_millis(2_000),
];

/// Run an attempt until it succeeds or the waits run out, and hand back whatever the last one
/// said. Generic and handed its sleep so the retry policy is testable without an engine and
/// without spending the waits.
fn retry_open<T>(
    waits: &[Duration],
    mut attempt: impl FnMut() -> Result<T>,
    mut sleep: impl FnMut(Duration),
) -> Result<T> {
    let mut last = attempt();

    for wait in waits {
        if last.is_ok() {
            return last;
        }

        sleep(*wait);
        last = attempt();
    }

    last
}

impl Engine {
    /// Open a connection to the engine, once.
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

    /// Open the engine, waiting for the Base Filtering Engine if it is still coming up.
    ///
    /// Every long-running caller uses this rather than [`Engine::open`] directly: a worker
    /// thread that opened the engine once at startup and missed kept the miss for the rest of
    /// the session, with every request answered "store unavailable" after it.
    pub fn open_retrying() -> Result<Self> {
        retry_open(&OPEN_WAITS, Self::open, thread::sleep)
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

    /// Make the live store match `rules`.
    ///
    /// Our filters are rebuilt from scratch rather than diffed. That is cruder, but it removes a
    /// whole class of stale-filter bugs on rule edits, and it makes rule order become filter
    /// creation order, which is what "the first matching rule wins" is translated from.
    ///
    /// Everything happens in one transaction, so no observer can see a store holding only part of
    /// the rule set.
    ///
    /// `known` is the set of application paths this tool has seen connecting, in device form.
    /// WFP compares an application path exactly, so a rule whose pattern contains wildcards is
    /// expanded against those paths and installed once per match. An unexpanded wildcard pattern
    /// stays in the store as it stands, which keeps the rule visible even while it matches nothing.
    pub fn apply(
        &self,
        rules: &RuleFile,
        known: &[String],
        answers: &crate::dns::Answers,
        policy: Policy,
    ) -> Result<Applied> {
        let mut report = Applied::default();

        self.transaction(|| {
            self.ensure_provider()?;
            self.ensure_sublayer()?;

            let taken = self.remove_our_filters()?;
            report.removed = taken.len();
            report.removed_rules = taken;

            let mut installed = 0;
            let mut owners = Owners::new();

            for rule in rules.rule.iter().filter(|rule| rule.enabled) {
                installed += self.add_rule(rule, known, answers, &mut owners)?;

                // One entry per rule, not per filter: a wildcard rule installs many filters and
                // the diff compares rules. The action rides along so a flipped rule is noticed.
                report
                    .installed_rules
                    .push((rule.name.clone(), rule.action == Action::Deny));
            }

            if policy == Policy::Deny {
                installed += self.add_base_filters(&mut owners)?;
            }

            report.installed = installed;
            report.owners = owners;

            Ok(())
        })?;

        Ok(report)
    }

    /// Take our filters out of the store, leaving the provider and the sublayer in place.
    pub fn clear(&self) -> Result<usize> {
        let mut removed = 0;

        self.transaction(|| {
            removed = self.remove_our_filters()?.len();
            Ok(())
        })?;

        Ok(removed)
    }

    /// Run `body` inside a WFP transaction, and abort the transaction if the body fails.
    ///
    /// A WFP transaction belongs to a thread rather than to a handle, so an abort on one thread
    /// can cancel work another thread started. Every write goes through this method, which is
    /// what makes the single dedicated WFP worker of milestone 4 a requirement rather than a
    /// preference.
    fn transaction(&self, body: impl FnOnce() -> Result<()>) -> Result<()> {
        // SAFETY: a zero flag selects a plain transaction, and the handle is ours.
        let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };

        if status != 0 {
            bail!("FwpmTransactionBegin0 failed with 0x{status:08X}");
        }

        match body() {
            Ok(()) => {
                // SAFETY: the transaction opened above is still open here.
                let status = unsafe { FwpmTransactionCommit0(self.handle) };

                if status != 0 {
                    // SAFETY: the transaction is still open and belongs to this thread.
                    unsafe { FwpmTransactionAbort0(self.handle) };
                    bail!("FwpmTransactionCommit0 failed with 0x{status:08X}");
                }

                Ok(())
            }
            Err(error) => {
                // SAFETY: the transaction is still open and belongs to this thread.
                unsafe { FwpmTransactionAbort0(self.handle) };
                Err(error)
            }
        }
    }

    fn ensure_provider(&self) -> Result<()> {
        let name = wide(APP_NAME);
        let description = wide(APP_NAME);

        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_ptr() as *mut _),
                description: PWSTR(description.as_ptr() as *mut _),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: FWP_BYTE_BLOB::default(),
            serviceName: PWSTR::null(),
        };

        // SAFETY: the struct only borrows the two wide buffers above, which outlive the call.
        let status = unsafe { FwpmProviderAdd0(self.handle, &provider, None) };

        if status != 0 && !already_exists(status) {
            bail!("FwpmProviderAdd0 failed with 0x{status:08X}");
        }

        Ok(())
    }

    fn ensure_sublayer(&self) -> Result<()> {
        let name = wide(APP_NAME);
        let description = wide(APP_NAME);
        let mut provider_key = PROVIDER_KEY;

        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(name.as_ptr() as *mut _),
                description: PWSTR(description.as_ptr() as *mut _),
            },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB::default(),
            weight: WEIGHT_SUBLAYER,
        };

        // SAFETY: the struct only borrows buffers owned by this function, which outlive the call.
        let status = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, None) };

        if status != 0 && !already_exists(status) {
            bail!("FwpmSubLayerAdd0 failed with 0x{status:08X}");
        }

        Ok(())
    }

    /// Delete every filter our provider owns, and report which they were.
    ///
    /// The enumeration is unfiltered and the provider is selected here rather than with a
    /// `FWPM_FILTER_ENUM_TEMPLATE0`: on a real store the template was rejected with
    /// `FWPM_E_INVALID_ENUM_TYPE`, and we already enumerate all filters for the inventory, so the
    /// extra entries cost nothing we were not already paying.
    fn remove_our_filters(&self) -> Result<Vec<RemovedFilter>> {
        let mut raw = HANDLE::default();

        // SAFETY: a null template asks for every filter, and the out parameter is a valid handle
        // slot.
        let status = unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &mut raw) };

        if status != 0 {
            bail!("FwpmFilterCreateEnumHandle0 failed with 0x{status:08X}");
        }

        let enum_handle = EnumHandle {
            engine: self.handle,
            handle: raw,
            destroy: FwpmFilterDestroyEnumHandle0,
        };

        let mut pointer: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;

        // SAFETY: both out parameters are valid, and the array they receive belongs to WFP.
        let status = unsafe {
            FwpmFilterEnum0(
                self.handle,
                enum_handle.handle,
                u32::MAX,
                &mut pointer,
                &mut returned,
            )
        };

        if status != 0 {
            bail!("FwpmFilterEnum0 failed with 0x{status:08X}");
        }

        let entries = WfpArray {
            pointer,
            len: returned,
        };

        let mut ours = Vec::new();
        let mut keys = Vec::new();

        for filter in entries.iter() {
            // A filter without a provider key was not added by us. Comparing the key here
            // instead of in the template keeps the working enumeration path.
            // SAFETY: the pointer is WFP-owned and either null or a readable GUID, which is
            // what `as_ref` checks for.
            let belongs = match unsafe { filter.providerKey.as_ref() } {
                Some(key) => *key == PROVIDER_KEY,
                None => false,
            };

            if belongs {
                // The rule's label lives in the description, not the display name, which is
                // the tool's own name on every filter we add. A filter whose description is
                // gone was edited by someone else after us; naming it is then impossible, and
                // an empty name is the honest answer rather than a guess.
                let label = if filter.displayData.description.is_null() {
                    String::new()
                } else {
                    // SAFETY: the pointer is not null, and WFP guarantees a terminated wide
                    // string there.
                    unsafe { filter.displayData.description.to_string() }.unwrap_or_default()
                };

                ours.push(RemovedFilter {
                    name: label,
                    deny: filter.action.r#type == FWP_ACTION_BLOCK,
                });

                // The key is needed again below, so keep it next to the label.
                keys.push(filter.filterKey);
            }
        }

        for key in &keys {
            // SAFETY: the key came out of the store a few instructions ago, and deleting one
            // filter by key does not invalidate the other keys we collected.
            let status = unsafe { FwpmFilterDeleteByKey0(self.handle, key) };

            if status != 0 {
                bail!("FwpmFilterDeleteByKey0 failed with 0x{status:08X}");
            }
        }

        Ok(ours)
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
