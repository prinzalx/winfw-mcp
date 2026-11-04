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
    FWP_MATCH_FLAGS_ANY_SET, FWP_MATCH_RANGE, FWP_RANGE_TYPE, FWP_RANGE0, FWP_UINT8, FWP_UINT16,
    FWP_UINT32, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
    FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_INDEXED,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
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
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::monitor::Attribution as Owners;

use crate::config::Policy;
use crate::rules::{
    Action, Direction, Family, Remote, Rule, RuleFile, is_wildcard, wildcard_match,
};

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
/// (`simplewall/src/wfp.c:1605-1688`).
///
/// The reference tops out at `0x0F`, and that ceiling is real: WFP answers
/// `FWP_E_INVALID_WEIGHT` for a `FWP_UINT8` weight of `0x10`, just as it does for `0`.
const WEIGHT_BASE_PERMIT: u8 = 0x0F;

/// Filter weight for the unconditional block of the default-deny base: the bottom, so every
/// permit and every rule is consulted before it (`simplewall/src/wfp.c:1827-1838`). Not
/// literally zero: WFP answers `FWP_E_INVALID_WEIGHT` for a weight of `0`, which is why the
/// reference's `FWW_LOWEST` is `0x08` rather than `0x00`.
const WEIGHT_BASE_BLOCK: u8 = 0x01;

/// `FWW_SUBLAYER`, the top of a `u16` sublayer weight.
const WEIGHT_SUBLAYER: u16 = 0xFFFF;

/// The four ALE authorization layers a rule is installed on: outbound connect and inbound accept,
/// for both address families.
const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

/// FNV-1a parameters, used to derive a filter key from a rule name.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

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

/// Run one of the three enumeration sequences end to end and collect the display names.
///
/// The three `Fwpm*` families differ only in name and entry type, which is what makes them worth
/// a macro rather than three copies of the same loop.
///
/// Everything is requested in a single call, the way the C reference does it. Not only is that
/// one round trip instead of several, it also keeps the ownership rule simple: the whole result
/// is one WFP allocation, released by handing the *array pointer* to `FwpmFreeMemory0`. Freeing
/// the individual elements as well corrupts the heap, because they were never allocated apart from
/// the array.
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
/// The handle is process-wide and has to outlive every query and every write, so it belongs to
/// the long-running core rather than to one request (PLAN.md section 5).
#[derive(Debug)]
pub struct Engine {
    handle: HANDLE,
}

/// The waits between attempts to open the engine, for as long as the Base Filtering Engine is
/// allowed to still be coming up. During boot the service can answer "not available" for a few
/// seconds, and a run that gave up on the first answer would serve its whole session without a
/// store (PLAN.md section 5). One attempt runs before the first wait and one after each of them,
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
    pub fn apply(&self, rules: &RuleFile, known: &[String], policy: Policy) -> Result<Applied> {
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
                installed += self.add_rule(rule, known, &mut owners)?;

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
        let mut enum_handle = HANDLE::default();

        // SAFETY: a null template asks for every filter, and the out parameter is a valid handle
        // slot.
        let status = unsafe { FwpmFilterCreateEnumHandle0(self.handle, None, &mut enum_handle) };

        if status != 0 {
            bail!("FwpmFilterCreateEnumHandle0 failed with 0x{status:08X}");
        }

        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut returned = 0u32;

        // SAFETY: both out parameters are valid, and the array they receive belongs to WFP.
        let status = unsafe {
            FwpmFilterEnum0(
                self.handle,
                enum_handle,
                u32::MAX,
                &mut entries,
                &mut returned,
            )
        };

        if status != 0 {
            // SAFETY: the enum handle is still open and belongs to this engine.
            unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
            bail!("FwpmFilterEnum0 failed with 0x{status:08X}");
        }

        let mut ours = Vec::new();
        let mut keys = Vec::new();

        if !entries.is_null() {
            for index in 0..returned {
                // SAFETY: WFP reported `returned` entries, so this slot is inside the array.
                let entry = unsafe { *entries.add(index as usize) };

                if entry.is_null() {
                    continue;
                }

                // SAFETY: the entry stays readable until the array is handed back below.
                let filter = unsafe { &*entry };

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

            // SAFETY: the array is WFP-owned, and this is the documented way to release it.
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
        }

        // SAFETY: the enum handle is still open and belongs to this engine.
        unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };

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

    /// Install one rule as one filter per application per layer. Which layers that is depends on
    /// the direction of the rule; with no direction both an outbound and an inbound connection are
    /// covered, for both address families. Returns the number of filters installed.
    fn add_rule(&self, rule: &Rule, known: &[String], owners: &mut Owners) -> Result<usize> {
        let expansion = app_ids(&rule.pattern, known);
        let truncated = expansion.truncated();
        let matches = expansion.matches;
        let installed = expansion.installed();
        let apps = expansion.apps;

        if truncated {
            // A firewall that quietly stops matching is a firewall nobody can reason about, so the
            // cap is named out loud with the numbers behind it.
            warn!(
                rule = %rule.name,
                pattern = %rule.pattern,
                matches,
                installed,
                "the wildcard pattern matched more applications than the cap allows",
            );
        }

        let mut provider_key = PROVIDER_KEY;

        let action = match rule.action {
            Action::Allow => FWP_ACTION_PERMIT,
            Action::Deny => FWP_ACTION_BLOCK,
        };

        // Deny outranks allow by weight, so a matching deny wins whatever the order in the file
        // is. Among rules of the same action the earlier rule still wins, because equal weights
        // are resolved in creation order and we install in file order.
        let weight = match rule.action {
            Action::Allow => WEIGHT_ALLOW,
            Action::Deny => WEIGHT_DENY,
        };

        // A deny also has to win over the permit filters of other software, which is what
        // clearing the action right of lower-weight filters does. Mirrors the reference
        // implementation.
        let mut flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_INDEXED;

        if rule.action == Action::Deny {
            flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        }

        let owner = wide(APP_NAME);
        let label = wide(&rule.name);

        let mut installed = 0;

        // One set of conditions per application, because the application condition points into
        // that application's blob.
        for (index, app) in apps.iter().enumerate() {
            let app_condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &raw const app.blob as *mut _,
                    },
                },
            };

            let protocol = rule.protocol.map(|protocol| FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint8: protocol.number(),
                    },
                },
            });

            // WFP keeps a pointer to the range rather than a copy of it, so the value lives here,
            // for as long as the filters of this application are being added. It is not an `Option`:
            // the pointer has to be a pointer to the range itself.
            let port_range = rule.port.map_or(FWP_RANGE0::default(), |port| FWP_RANGE0 {
                valueLow: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.lo },
                },
                valueHigh: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.hi },
                },
            });

            // Both address conditions are a pointer into a struct WFP reads while the filter is
            // added, so the value lives here for as long as this application's filters are being
            // added. It is not an `Option` of the struct: the pointer has to reach the struct.
            let addr = rule.remote.map(addr_value);
            let addr_range = span_range(addr.as_ref());
            let local = rule.local.map(addr_value);
            let local_range = span_range(local.as_ref());

            for layer in rule_layers(rule) {
                let mut conditions = vec![app_condition];

                if let Some(condition) = protocol {
                    conditions.push(condition);
                }

                if let Some(port) = rule.port {
                    // One port is matched exactly; a range needs the range type and the range the
                    // store keeps a pointer to.
                    conditions.push(if port.is_single() {
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: port_condition(layer),
                            matchType: FWP_MATCH_EQUAL,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_UINT16,
                                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port.lo },
                            },
                        }
                    } else {
                        FWPM_FILTER_CONDITION0 {
                            fieldKey: port_condition(layer),
                            matchType: FWP_MATCH_RANGE,
                            conditionValue: FWP_CONDITION_VALUE0 {
                                r#type: FWP_RANGE_TYPE,
                                Anonymous: FWP_CONDITION_VALUE0_0 {
                                    rangeValue: &raw const port_range as *mut _,
                                },
                            },
                        }
                    });
                }

                if let Some(addr) = &addr {
                    conditions.push(addr_condition(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        addr,
                        addr_range.as_ref(),
                    ));
                }

                if let Some(local) = &local {
                    conditions.push(addr_condition(
                        FWPM_CONDITION_IP_LOCAL_ADDRESS,
                        local,
                        local_range.as_ref(),
                    ));
                }

                let mut filter = FWPM_FILTER0::default();
                filter.filterKey = filter_key(&format!("{}#{index}", rule.name), &layer);
                filter.displayData = FWPM_DISPLAY_DATA0 {
                    name: PWSTR(owner.as_ptr() as *mut _),
                    description: PWSTR(label.as_ptr() as *mut _),
                };
                filter.flags = flags;
                filter.providerKey = &mut provider_key;
                filter.layerKey = layer;
                filter.subLayerKey = SUBLAYER_KEY;
                filter.weight = FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: weight },
                };
                filter.numFilterConditions = conditions.len() as u32;
                filter.filterCondition = conditions.as_ptr() as *mut _;
                filter.action = FWPM_ACTION0 {
                    r#type: action,
                    ..Default::default()
                };

                let mut filter_id = 0u64;

                // SAFETY: every pointer in the filter points into memory owned by this function, and
                // all of it outlives the call. WFP copies what it needs.
                let status =
                    unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id)) };

                if status != 0 {
                    bail!(
                        "FwpmFilterAdd0 failed with 0x{status:08X} for rule '{}' on layer {}",
                        rule.name,
                        layer_index(layer),
                    );
                }

                owners.insert(filter_id, rule.name.clone());

                installed += 1;
            }
        }

        Ok(installed)
    }

    /// Install the base filters of the default-deny policy, mirroring the reference
    /// (`simplewall/src/wfp.c:1605-1688` and `1827-1838`).
    ///
    /// An unconditional block sits at the very bottom of the four authorization layers, so
    /// traffic no rule mentions is denied rather than falling through to whatever the rest of
    /// the machine decides. Above it sit the permits without which the policy would break the
    /// machine itself: loopback (the browser has to reach this tool's own web server), 6to4,
    /// and the ICMPv6 neighbor and router messages the IPv6 stack needs.
    fn add_base_filters(&self, owners: &mut Owners) -> Result<usize> {
        // Not from the windows crate under the name we would wish for it: `IPPROTO_IPV6` there
        // is the IPv6 *socket option* level, the same number 41 the reference uses as the
        // protocol value of the 6to4 permit.
        const IPPROTO_IPV6: u8 = 41;

        // Router solicitation/advertisement and neighbor solicitation/advertisement.
        const ICMPV6_TYPES: [u16; 4] = [133, 134, 135, 136];

        let mut installed = 0;

        let loopback = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ANY_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK
                        | FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK,
                },
            },
        }];

        for layer in LAYERS {
            self.add_filter(
                "base#loopback",
                layer,
                FWP_ACTION_PERMIT,
                WEIGHT_BASE_PERMIT,
                &loopback,
                owners,
            )?;

            installed += 1;
        }

        let sixtofour = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: IPPROTO_IPV6,
                },
            },
        }];

        self.add_filter(
            "base#6to4",
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_BASE_PERMIT,
            &sixtofour,
            owners,
        )?;

        installed += 1;

        for icmp_type in ICMPV6_TYPES {
            let permit = [FWPM_FILTER_CONDITION0 {
                // `FWPM_CONDITION_ICMP_TYPE` is not a GUID of its own: the SDK spells it as an
                // alias for the local port (`fwpmu.h:1720`), which the windows crate exports.
                fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: icmp_type },
                },
            }];

            self.add_filter(
                &format!("base#icmpv6-{icmp_type}"),
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                FWP_ACTION_PERMIT,
                WEIGHT_BASE_PERMIT,
                &permit,
                owners,
            )?;

            installed += 1;
        }

        for layer in LAYERS {
            self.add_filter(
                "base#block",
                layer,
                FWP_ACTION_BLOCK,
                WEIGHT_BASE_BLOCK,
                &[],
                owners,
            )?;

            installed += 1;
        }

        Ok(installed)
    }

    /// Install one filter of the base, as opposed to one installed from a rule.
    fn add_filter(
        &self,
        name: &str,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        conditions: &[FWPM_FILTER_CONDITION0],
        owners: &mut Owners,
    ) -> Result<()> {
        let mut provider_key = PROVIDER_KEY;

        let owner = wide(APP_NAME);
        let label = wide(name);

        let mut filter = FWPM_FILTER0::default();
        filter.filterKey = filter_key(name, &layer);
        filter.displayData = FWPM_DISPLAY_DATA0 {
            name: PWSTR(owner.as_ptr() as *mut _),
            description: PWSTR(label.as_ptr() as *mut _),
        };
        filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
        filter.providerKey = &mut provider_key;
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight = FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        };
        filter.numFilterConditions = conditions.len() as u32;

        if !conditions.is_empty() {
            filter.filterCondition = conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0;
        }

        filter.action = FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        };

        let mut filter_id = 0u64;

        // SAFETY: every pointer in the filter points into memory owned by the caller of this
        // function — the condition slice and the two wide buffers — and all of it outlives the
        // call. WFP copies what it needs.
        let status = unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id)) };

        if status != 0 {
            bail!(
                "FwpmFilterAdd0 failed with 0x{status:08X} for base filter '{name}' on layer {}",
                layer_index(layer),
            );
        }

        owners.insert(filter_id, name.to_owned());

        Ok(())
    }
}

/// How many applications one wildcard rule may be expanded into.
///
/// A pattern is allowed to be broad, but the store is shared and every match costs four filters.
/// The cap keeps a careless `*` from turning one rule into thousands.
pub(crate) const MAX_WILDCARD_MATCHES: usize = 32;

/// What a pattern resolves to: the applications to install filters for, and how many applications
/// matched in total.
///
/// The two numbers differ only when a wildcard pattern was held down by [`MAX_WILDCARD_MATCHES`],
/// which is the truncation the user has to be told about.
struct Expansion {
    /// The applications to install filters for, at most [`MAX_WILDCARD_MATCHES`] of them.
    apps: Vec<AppId>,
    /// How many applications the pattern matched before the cap was applied.
    matches: usize,
}

impl Expansion {
    /// How many applications are installed. For an exact pattern this is the pattern itself.
    pub(crate) fn installed(&self) -> usize {
        self.apps.len()
    }

    /// Whether the cap left matches out.
    pub(crate) fn truncated(&self) -> bool {
        self.matches > self.installed()
    }
}

/// How far one rule's pattern reaches: the number of applications it matched and the number of
/// them the cap allows to be installed. Only a wildcard pattern can be truncated, and the two
/// numbers differ exactly then, which is what [`pattern_reach`] is asked for by `/api/state`.
///
/// Unlike [`app_ids`] nothing is resolved with WFP, so this only counts and never touches the
/// filter store.
pub(crate) fn pattern_reach(pattern: &str, known: &[String]) -> (usize, usize) {
    if !is_wildcard(pattern) {
        return (1, 1);
    }

    let device_pattern = crate::device::to_device_path(pattern);
    let matches = known
        .iter()
        .filter(|path| wildcard_match(&device_pattern, path))
        .count();

    // A wildcard that matches nothing installs the pattern itself, so one filter is always the
    // minimum; anything above the cap is left out.
    (matches, matches.clamp(1, MAX_WILDCARD_MATCHES))
}

/// Build the application identities one rule needs.
///
/// An exact pattern is resolved on its own, which is the normal case a Detected entry produces.
/// A wildcard pattern is matched against the paths this tool has seen; when nothing has been seen
/// yet the pattern itself goes into the store, so the rule is at least visible to the user.
fn app_ids(pattern: &str, known: &[String]) -> Expansion {
    if !is_wildcard(pattern) {
        return Expansion {
            apps: vec![AppId::resolve(pattern)],
            matches: 1,
        };
    }

    let device_pattern = crate::device::to_device_path(pattern);

    let matched: Vec<&String> = known
        .iter()
        .filter(|path| wildcard_match(&device_pattern, path))
        .collect();
    let matches = matched.len();

    let mut ids: Vec<AppId> = matched
        .into_iter()
        .take(MAX_WILDCARD_MATCHES)
        .map(|path| AppId::resolve(path))
        .collect();

    if ids.is_empty() {
        ids.push(AppId::resolve(pattern));
    }

    Expansion { apps: ids, matches }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: the handle came from FwpmEngineOpen0 and is closed exactly once.
            unsafe { FwpmEngineClose0(self.handle) };
        }
    }
}

/// The application identity used as a filter condition.
///
/// WFP does not match a file name but a device path blob. `FwpmGetAppIdFromFileName0` resolves one
/// for a file that exists, which is the case for the concrete paths learning mode produces. A
/// wildcard pattern usually names a file that does not exist; then the pattern is handed over as
/// it stands and the match becomes exact. Wildcard patterns are expanded into the concrete
/// applications the detector has seen, so a pattern matches every observed program under it.
struct AppId {
    blob: FWP_BYTE_BLOB,
    /// Keeps the fallback's wide characters alive while `blob` points into them.
    _pattern: Vec<u16>,
    /// Non-null only when WFP allocated the blob and has to be given the memory back.
    allocated: Option<*mut FWP_BYTE_BLOB>,
}

impl AppId {
    fn resolve(pattern: &str) -> Self {
        let file = wide(pattern);
        let mut allocated: *mut FWP_BYTE_BLOB = std::ptr::null_mut();

        // SAFETY: `file` is a terminated wide string and `allocated` is an out parameter.
        let status = unsafe { FwpmGetAppIdFromFileName0(PCWSTR(file.as_ptr()), &mut allocated) };

        if status == 0 && !allocated.is_null() {
            // SAFETY: WFP reported success, so the pointer it wrote points at a readable blob.
            let blob = unsafe { *allocated };

            return Self {
                blob,
                _pattern: Vec::new(),
                allocated: Some(allocated),
            };
        }

        // The fallback: the pattern itself, in the same wide form WFP would have produced.
        let mut pattern_units = wide(pattern);

        if pattern_units.last() == Some(&0) {
            pattern_units.pop();
        }

        let blob = FWP_BYTE_BLOB {
            size: (pattern_units.len() * 2) as u32,
            data: pattern_units.as_ptr() as *mut u8,
        };

        Self {
            blob,
            _pattern: pattern_units,
            allocated: None,
        }
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        if let Some(pointer) = self.allocated.as_mut() {
            // SAFETY: the blob came from FwpmGetAppIdFromFileName0 and is released exactly once,
            // after the last filter that could read it has been added.
            unsafe { FwpmFreeMemory0(pointer as *mut _ as *mut *mut c_void) };
        }
    }
}

/// Encode a string as the NUL terminated UTF-16 buffer the WFP structs point at.
fn wide(value: &str) -> Vec<u16> {
    let mut units: Vec<u16> = value.encode_utf16().collect();
    units.push(0);
    units
}

fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;

    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// The bytes of a GUID in the order a UUID is written down.
fn guid_bytes(guid: &GUID) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);

    bytes.extend_from_slice(&guid.data1.to_be_bytes());
    bytes.extend_from_slice(&guid.data2.to_be_bytes());
    bytes.extend_from_slice(&guid.data3.to_be_bytes());
    bytes.extend_from_slice(&guid.data4);

    bytes
}

/// A stable filter key for one rule on one layer.
///
/// A key derived from the rule name, rather than a randomly generated one, is what lets a rule be
/// recognised again after a restart. Two FNV-1a chains with different seeds fill the 128 bits; the
/// second chain also takes the layer, because a filter key has to be unique across the store and
/// one rule installs a filter per layer. The version and variant nibbles are fixed up so the
/// result is a well formed UUID if any other tool looks at it.
pub fn filter_key(name: &str, layer: &GUID) -> GUID {
    let high = fnv1a(FNV_OFFSET, name.as_bytes());
    let low = fnv1a(!FNV_OFFSET, &guid_bytes(layer));
    let low = fnv1a(low, name.as_bytes());

    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&high.to_be_bytes());
    raw[8..].copy_from_slice(&low.to_be_bytes());

    raw[6] = (raw[6] & 0x0F) | 0x50; // version 5
    raw[8] = (raw[8] & 0x3F) | 0x80; // RFC 4122 variant

    GUID::from_u128(u128::from_be_bytes(raw))
}

/// The layers a rule is installed on.
///
/// A rule with no direction is installed on all four, which is what every rule did before the
/// dimension existed. Outbound is the connect layer of each address family, inbound the
/// recv-accept layer of each, mirroring where a connection is authorized in each direction.
///
/// A rule with a remote address is installed only on the layers of that address's family, because
/// a v4 address condition is refused on a v6 layer and could not match a v6 connection anyway.
fn layers_for(direction: Option<Direction>, family: Option<Family>) -> Vec<GUID> {
    let layers = match direction {
        None => LAYERS.to_vec(),
        Some(Direction::Out) => vec![LAYERS[0], LAYERS[1]],
        Some(Direction::In) => vec![LAYERS[2], LAYERS[3]],
    };

    match family {
        None => layers,
        Some(family) => layers
            .into_iter()
            .filter(|layer| layer_family(*layer) == family)
            .collect(),
    }
}

/// Which family a layer belongs to.
fn layer_family(layer: GUID) -> Family {
    if layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 {
        Family::V4
    } else {
        Family::V6
    }
}

/// The layers a rule is installed on, narrowed by its direction and by both of its addresses.
///
/// The remote address decides the family as it always has, and a local address narrows what is
/// left over the same way. A rule that names addresses of two different families ends up on no
/// layer at all, because no connection has ends of both.
fn rule_layers(rule: &Rule) -> Vec<GUID> {
    layers_for(rule.direction, rule.remote.map(Remote::family))
        .into_iter()
        .filter(|layer| {
            rule.local
                .is_none_or(|local| layer_family(*layer) == local.family())
        })
        .collect()
}

/// The value an address condition carries, in whichever family the address is in. A span keeps
/// only its bounds here; the `FWP_RANGE0` that points at them is built next to it.
enum AddrValue {
    V4(FWP_V4_ADDR_AND_MASK),
    V6(FWP_V6_ADDR_AND_MASK),
    V4Range([u32; 2]),
    V6Range([FWP_BYTE_ARRAY16; 2]),
}

/// The value a rule names one end of a connection with.
fn addr_value(address: Remote) -> AddrValue {
    match address {
        Remote::Network(cidr) => match cidr.family {
            Family::V4 => AddrValue::V4(FWP_V4_ADDR_AND_MASK {
                addr: u32::from_be_bytes(cidr.v4_bytes()),
                mask: cidr.v4_mask(),
            }),
            Family::V6 => AddrValue::V6(FWP_V6_ADDR_AND_MASK {
                addr: cidr.addr,
                prefixLength: cidr.prefix,
            }),
        },
        Remote::Span(range) => match range.family {
            Family::V4 => AddrValue::V4Range([bound32(range.from), bound32(range.to)]),
            Family::V6 => AddrValue::V6Range([
                FWP_BYTE_ARRAY16 {
                    byteArray16: range.from,
                },
                FWP_BYTE_ARRAY16 {
                    byteArray16: range.to,
                },
            ]),
        },
    }
}

/// The range a span condition points at, or nothing for an address, which WFP matches by prefix.
///
/// The reference fills the same shape: a v4 bound is the address byteswapped, which is the number
/// `bound32` of the octets gives, and a v6 bound is a pointer to the octets.
fn span_range(value: Option<&AddrValue>) -> Option<FWP_RANGE0> {
    match value {
        Some(AddrValue::V4Range([lo, hi])) => Some(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: *lo },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: *hi },
            },
        }),
        Some(AddrValue::V6Range([lo, hi])) => Some(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_VALUE0_0 {
                    byteArray16: lo as *const FWP_BYTE_ARRAY16 as *mut _,
                },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_VALUE0_0 {
                    byteArray16: hi as *const FWP_BYTE_ARRAY16 as *mut _,
                },
            },
        }),
        _ => None,
    }
}

/// The condition that names one end of a connection: the remote address, or the local one.
///
/// A span is matched as a range and so points at the bounds [`span_range`] built; an address is
/// matched by prefix straight out of its own value.
fn addr_condition(
    field: GUID,
    addr: &AddrValue,
    range: Option<&FWP_RANGE0>,
) -> FWPM_FILTER_CONDITION0 {
    match addr {
        AddrValue::V4(addr) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: addr as *const FWP_V4_ADDR_AND_MASK as *mut _,
                },
            },
        },
        AddrValue::V6(addr) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: addr as *const FWP_V6_ADDR_AND_MASK as *mut _,
                },
            },
        },
        AddrValue::V4Range(_) | AddrValue::V6Range(_) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: range
                        .map(|range| range as *const FWP_RANGE0 as *mut _)
                        .unwrap_or(std::ptr::null_mut()),
                },
            },
        },
    }
}

/// The four octets of a v4 address as WFP numbers them: most significant octet first.
fn bound32(addr: [u8; 16]) -> u32 {
    u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]])
}

/// The condition that names the port a connection is about on a layer.
///
/// On an outbound layer the port the user means is the remote one, because that is where the
/// connection goes; on an inbound layer it is the local one. Picking one of the two for every layer
/// would make a port rule apply in only one direction, whatever its direction says.
fn port_condition(layer: GUID) -> GUID {
    if layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        FWPM_CONDITION_IP_REMOTE_PORT
    } else {
        FWPM_CONDITION_IP_LOCAL_PORT
    }
}

/// Which of the four layers a GUID is, so an error message can name the position in `LAYERS`.
fn layer_index(layer: GUID) -> usize {
    LAYERS
        .iter()
        .position(|candidate| *candidate == layer)
        .unwrap_or(LAYERS.len())
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
    use crate::rules::{Cidr, Protocol};

    /// A path that exists on every Windows install, so the application-id resolution succeeds.
    const TEST_APP: &str = "C:\\Windows\\System32\\cmd.exe";

    /// A rule with no direction is installed everywhere, and each direction picks the two layers
    /// where its connections are authorized.
    #[test]
    fn a_direction_narrows_the_layers_a_rule_is_installed_on() {
        assert_eq!(layers_for(None, None).len(), LAYERS.len());
        assert_eq!(
            layers_for(Some(Direction::Out), None),
            vec![LAYERS[0], LAYERS[1]]
        );
        assert_eq!(
            layers_for(Some(Direction::In), None),
            vec![LAYERS[2], LAYERS[3]]
        );
    }

    /// An address of one family cannot match on a layer of the other, so a rule with a remote
    /// address is only installed on the layers it could ever fire on. The two families together
    /// are exactly the layers the rule would be installed on without an address.
    #[test]
    fn a_remote_address_narrows_the_layers_to_its_family() {
        let v4: Cidr = "192.168.1.0/24".parse().expect("parse a v4 network");
        let v6: Cidr = "fe80::/10".parse().expect("parse a v6 network");

        assert_eq!(
            layers_for(None, Some(v4.family)),
            vec![LAYERS[0], LAYERS[2]]
        );
        assert_eq!(
            layers_for(None, Some(v6.family)),
            vec![LAYERS[1], LAYERS[3]]
        );
        assert_eq!(
            layers_for(Some(Direction::In), Some(v4.family)),
            vec![LAYERS[2]]
        );
        assert_eq!(
            layers_for(Some(Direction::Out), Some(v6.family)),
            vec![LAYERS[1]]
        );

        // Both families together are the unaddressed case again, so nothing is lost.
        let mut both = layers_for(None, Some(v4.family));
        both.extend(layers_for(None, Some(v6.family)));
        assert_eq!(both.len(), LAYERS.len());
    }

    /// A local address narrows the layers exactly like a remote one does, and the two of them have
    /// to agree on a family: a rule about a v4 destination behind a v6 interface can match no
    /// connection, so it is installed on no layer at all.
    #[test]
    fn a_local_address_narrows_the_layers_to_its_family() {
        let v4: Cidr = "192.168.1.0/24".parse().expect("parse a v4 network");
        let v6: Cidr = "fe80::/10".parse().expect("parse a v6 network");

        let layers_of = |remote: Option<Cidr>, local: Option<Cidr>| {
            rule_layers(&Rule {
                remote: remote.map(Remote::Network),
                local: local.map(Remote::Network),
                ..Rule::plain("local layer test", Action::Deny, TEST_APP)
            })
        };

        assert_eq!(layers_of(None, Some(v4)), vec![LAYERS[0], LAYERS[2]]);
        assert_eq!(layers_of(None, Some(v6)), vec![LAYERS[1], LAYERS[3]]);
        assert_eq!(layers_of(Some(v4), Some(v4)), vec![LAYERS[0], LAYERS[2]]);
        assert_eq!(
            layers_of(Some(v4), Some(v6)),
            Vec::<GUID>::new(),
            "an address of each family matches nothing",
        );
    }

    /// A broad pattern is capped: the store gets the applications up to the limit. Without the cap
    /// one careless `*` turns into thousands of filters in a store that is shared with everything
    /// else on the machine.
    #[test]
    fn a_wildcard_pattern_is_expanded_up_to_the_cap() {
        let known: Vec<String> = (0..MAX_WILDCARD_MATCHES + 8)
            .map(|index| crate::device::to_device_path(&format!("C:\\test\\app{index}.exe")))
            .collect();

        assert_eq!(
            app_ids("C:\\test\\*.exe", &known).apps.len(),
            MAX_WILDCARD_MATCHES,
            "the cap holds the expansion down",
        );
    }

    /// The cap is not silent any more. The expansion carries the number of matches next to the
    /// number of applications it hands out, so a pattern over the limit reports itself as
    /// truncated and a pattern within the limit does not.
    #[test]
    fn a_pattern_over_the_cap_reports_its_truncation() {
        let known: Vec<String> = (0..MAX_WILDCARD_MATCHES + 8)
            .map(|index| crate::device::to_device_path(&format!("C:\\test\\app{index}.exe")))
            .collect();

        let over = app_ids("C:\\test\\*.exe", &known);
        assert_eq!(
            over.matches,
            MAX_WILDCARD_MATCHES + 8,
            "all matches are counted"
        );
        assert!(over.truncated(), "a pattern over the cap is truncated");

        let within = app_ids("C:\\test\\app*.exe", &known[..MAX_WILDCARD_MATCHES]);
        assert_eq!(
            within.matches, MAX_WILDCARD_MATCHES,
            "the matches within the cap"
        );
        assert!(!within.truncated(), "a pattern at the cap is not truncated");

        let exact = app_ids("C:\\test\\app0.exe", &known[..4]);
        assert!(!exact.truncated(), "an exact pattern is never truncated");

        assert_eq!(
            pattern_reach("C:\\test\\*.exe", &known),
            (MAX_WILDCARD_MATCHES + 8, MAX_WILDCARD_MATCHES),
            "the state view reports the same numbers",
        );
        assert_eq!(
            pattern_reach("C:\\test\\app*.exe", &known[..MAX_WILDCARD_MATCHES]),
            (MAX_WILDCARD_MATCHES, MAX_WILDCARD_MATCHES),
            "a pattern at the cap is not truncated in the state view either",
        );
        assert_eq!(
            pattern_reach("C:\\test\\app0.exe", &known),
            (1, 1),
            "an exact pattern reaches exactly itself",
        );
    }

    /// An exact path has nothing to expand, so the applications this tool has seen are not looked
    /// at — which is what lets a rule for one file install one filter set rather than a search.
    #[test]
    fn an_exact_pattern_ignores_the_applications_that_have_been_seen() {
        let known: Vec<String> = (0..4)
            .map(|index| crate::device::to_device_path(&format!("C:\\other\\app{index}.exe")))
            .collect();

        assert_eq!(app_ids(TEST_APP, &known).apps.len(), 1);
    }

    /// A wildcard that has matched nothing so far still goes into the store as its own text. The
    /// alternative is a rule that is installed as nothing at all, which the user cannot see in the
    /// store and cannot explain.
    #[test]
    fn a_wildcard_that_matches_nothing_seen_yet_still_installs_its_pattern() {
        assert_eq!(app_ids("C:\\test\\*.exe", &[]).apps.len(), 1);
    }

    /// The port a user means is the remote one on the way out and the local one on the way in.
    #[test]
    fn a_port_is_matched_on_the_side_the_connection_is_about() {
        assert_eq!(
            port_condition(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
            FWPM_CONDITION_IP_REMOTE_PORT
        );
        assert_eq!(
            port_condition(FWPM_LAYER_ALE_AUTH_CONNECT_V6),
            FWPM_CONDITION_IP_REMOTE_PORT
        );
        assert_eq!(
            port_condition(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
            FWPM_CONDITION_IP_LOCAL_PORT
        );
        assert_eq!(
            port_condition(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
            FWPM_CONDITION_IP_LOCAL_PORT
        );
    }

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

    /// The write path is exercised against the live store, because that is the only place it has
    /// to work. Whatever it installs, it removes again before returning.
    #[test]
    fn a_rule_is_installed_and_removed_from_the_live_store() {
        let engine = Engine::open().expect("open engine");

        let rules = RuleFile {
            rule: vec![
                Rule::plain("winfw-mcp write test", Action::Deny, TEST_APP),
                Rule::plain("winfw-mcp write test allow", Action::Allow, TEST_APP),
            ],
        };

        // Both actions have to be installed, because they differ in more than their name.
        let expected = rules.rule.len() * LAYERS.len();

        // Start from a clean store, so a count of zero means what it says.
        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        let applied = engine
            .apply(&rules, &[], Policy::Allow)
            .expect("apply the rule");

        assert_eq!(applied.installed, expected, "one filter per rule and layer");
        assert_eq!(applied.removed, 0, "the store was cleared first");

        let rebuilt = engine
            .apply(&rules, &[], Policy::Allow)
            .expect("apply the same rule again");

        assert_eq!(
            rebuilt.removed, expected,
            "a rebuild must remove exactly what the run before installed"
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(
            cleared, expected,
            "clearing removes every filter we installed"
        );
    }

    /// A rule narrowed by protocol, direction and a port is installed on the two layers of its
    /// direction alone, and the store accepts the conditions it carries. Both port encodings are
    /// exercised: a single port is matched exactly, a range needs the range type. The conditions
    /// are the point here — one WFP could not read would fail this test rather than quietly widen
    /// the rule to every port.
    #[test]
    fn a_narrowed_rule_is_installed_on_its_direction_alone() {
        let engine = Engine::open().expect("open engine");

        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        for port in ["443", "1024-2048"] {
            let rules = RuleFile {
                rule: vec![Rule {
                    protocol: Some(Protocol::Tcp),
                    direction: Some(Direction::Out),
                    port: Some(port.parse().expect("parse a port")),
                    ..Rule::plain("winfw-mcp narrow test", Action::Allow, TEST_APP)
                }],
            };

            let applied = engine
                .apply(&rules, &[], Policy::Allow)
                .expect("apply the narrowed rule");

            assert_eq!(
                applied.installed, 2,
                "port '{port}': outbound is the connect layer of both address families, not four",
            );

            let cleared = engine.clear().expect("clear the store");

            assert_eq!(
                cleared, 2,
                "port '{port}': a narrowed rule leaves nothing on the other layers",
            );
        }
    }

    /// A remote address is installed as a real condition on the layers of its family only. This
    /// is what exercises the pointer WFP keeps to the address-and-mask struct, which is the same
    /// trap the port range is: an `Option` there is a pointer to the wrong thing.
    #[test]
    fn a_remote_address_is_installed_on_the_layers_of_its_family() {
        let engine = Engine::open().expect("open engine");

        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        for address in [
            "192.168.1.0/24",
            "10.0.0.5",
            "fe80::/10",
            "2001:db8::1/64",
            "192.168.1.10-192.168.1.20",
            "2001:db8::1-2001:db8::ff",
        ] {
            let rules = RuleFile {
                rule: vec![Rule {
                    remote: Some(address.parse().expect("parse an address")),
                    ..Rule::plain("winfw-mcp address test", Action::Deny, TEST_APP)
                }],
            };

            let applied = engine
                .apply(&rules, &[], Policy::Allow)
                .expect("apply the addressed rule");

            assert_eq!(
                applied.installed, 2,
                "'{address}': an address narrows four layers to the two of its family",
            );

            let cleared = engine.clear().expect("clear the store");

            assert_eq!(cleared, 2, "'{address}': nothing is left behind");
        }
    }

    /// A local address is installed as a real condition on the layers of its family only, exactly
    /// like the remote one, and it keeps a pointer of its own to an address-and-mask struct. A rule
    /// that names both ends carries both conditions on one filter, so a filter the store accepts
    /// there is the assertion that both of them were well formed.
    #[test]
    fn a_local_address_is_installed_on_the_layers_of_its_family() {
        let engine = Engine::open().expect("open engine");

        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        for address in [
            "192.168.1.0/24",
            "10.0.0.5",
            "fe80::/10",
            "2001:db8::1/64",
            "192.168.1.10-192.168.1.20",
            "2001:db8::1-2001:db8::ff",
        ] {
            let rules = RuleFile {
                rule: vec![Rule {
                    local: Some(address.parse().expect("parse an address")),
                    ..Rule::plain("winfw-mcp local test", Action::Deny, TEST_APP)
                }],
            };

            let applied = engine
                .apply(&rules, &[], Policy::Allow)
                .expect("apply the locally addressed rule");

            assert_eq!(
                applied.installed, 2,
                "'{address}': an address narrows four layers to the two of its family",
            );

            let cleared = engine.clear().expect("clear the store");

            assert_eq!(cleared, 2, "'{address}': nothing is left behind");
        }

        let rules = RuleFile {
            rule: vec![Rule {
                remote: Some("192.168.1.0/24".parse().expect("parse a network")),
                local: Some("10.0.0.1-10.0.0.9".parse().expect("parse a span")),
                ..Rule::plain("winfw-mcp both ends test", Action::Deny, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], Policy::Allow)
            .expect("apply a rule naming both ends");

        assert_eq!(
            applied.installed, 2,
            "two addresses of one family narrow four layers to the same two",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(cleared, 2, "nothing is left behind");
    }

    /// The default-deny policy adds the base filters on top of the rules: a loopback permit on
    /// each of the four authorization layers, one 6to4 permit, one permit per ICMPv6 type the
    /// IPv6 stack needs, and one unconditional block per layer. All of them carry our provider
    /// key, so `clear` takes them out again exactly like a rule filter.
    #[test]
    fn the_default_deny_policy_installs_the_base_filters() {
        const BASE_FILTERS: usize = 4 + 1 + 4 + 4;

        let engine = Engine::open().expect("open engine");

        // Start from a clean store, so a count of zero means what it says.
        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        let applied = engine
            .apply(&RuleFile::default(), &[], Policy::Deny)
            .expect("apply the base filters");

        assert_eq!(
            applied.installed, BASE_FILTERS,
            "four loopback permits, one 6to4, four ICMPv6, four blocks"
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(cleared, BASE_FILTERS, "clearing removes the base filters");
    }

    /// Every filter `apply` installs is accounted for in the table it hands back, so an event
    /// naming one of those ids can be read back as the rule it came from. Ids are never zero, the
    /// value the monitor reads as "no filter was named".
    #[test]
    fn apply_accounts_for_every_filter_it_installs() {
        let engine = Engine::open().expect("open engine");

        match engine.clear() {
            Ok(leftovers) => println!("cleared {leftovers} leftover filters"),
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
                println!("write path skipped, access denied");
                return;
            }
        }

        let rules = RuleFile {
            rule: vec![Rule::plain(
                "winfw-mcp attribution test",
                Action::Deny,
                TEST_APP,
            )],
        };

        let applied = engine
            .apply(&rules, &[], Policy::Allow)
            .expect("apply the rule");

        // One table entry per installed filter: nothing we put in the store is unaccounted for.
        assert_eq!(
            applied.owners.len(),
            applied.installed,
            "every installed filter is in the table",
        );
        assert!(
            applied.owners.keys().all(|id| *id != 0),
            "WFP never hands out id 0, which the monitor uses as the sentinel",
        );
        assert!(
            applied
                .owners
                .values()
                .all(|name| name == "winfw-mcp attribution test"),
            "a table entry names the rule its filter came from",
        );

        engine.clear().expect("clear the store");
    }

    /// A filter key has to survive a restart, and a rule installed on several layers needs a
    /// distinct key per layer.
    #[test]
    fn a_filter_key_is_stable_and_distinct_per_rule_and_layer() {
        assert_eq!(
            filter_key("browser", &LAYERS[0]),
            filter_key("browser", &LAYERS[0])
        );
        assert_ne!(
            filter_key("browser", &LAYERS[0]),
            filter_key("browser", &LAYERS[1])
        );
        assert_ne!(filter_key("one", &LAYERS[0]), filter_key("two", &LAYERS[0]));
    }

    /// A handle that was never opened must not be handed to `FwpmEngineClose0`.
    #[test]
    fn a_default_handle_counts_as_invalid() {
        assert!(HANDLE::default().is_invalid());
    }

    /// A deny has to win over an allow no matter where the two rules sit in the file, and inside
    /// the engine that is decided by filter weight rather than by rule order.
    #[test]
    fn a_deny_rule_outranks_an_allow_rule() {
        assert!(WEIGHT_DENY > WEIGHT_ALLOW);
    }

    /// The retry loop is the whole of the boot-time policy, so it is tested without an engine:
    /// an attempt that fails twice and succeeds must be reached over exactly the two waits that
    /// precede it, with no sleep before the first try and none after the successful one.
    #[test]
    fn opening_waits_between_attempts_but_not_around_them() {
        let waits = [
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
        ];
        let mut slept = Vec::new();
        let mut calls = 0;

        let outcome = retry_open(
            &waits,
            || {
                calls += 1;

                if calls < 3 {
                    bail!("not yet {calls}");
                }

                Ok(calls)
            },
            |wait| slept.push(wait),
        );

        assert_eq!(outcome.expect("the third attempt is reached"), 3);
        assert_eq!(
            slept,
            vec![waits[0], waits[1]],
            "waits only between attempts"
        );
    }

    /// The other half: an attempt that never succeeds must stop after the last wait and hand
    /// back its last error rather than spin forever — a machine whose firewall service is
    /// disabled should be slow to start, not started slowly.
    #[test]
    fn opening_gives_up_after_the_last_wait() {
        let waits = [Duration::from_millis(1), Duration::from_millis(2)];
        let mut slept = Vec::new();
        let mut calls = 0;

        let outcome: Result<u32> = retry_open(
            &waits,
            || {
                calls += 1;
                bail!("never")
            },
            |wait| slept.push(wait),
        );

        assert_eq!(outcome.expect_err("all attempts fail").to_string(), "never");
        assert_eq!(calls, 3, "one attempt before the waits and one per wait");
        assert_eq!(slept, vec![waits[0], waits[1]]);
    }

    /// The waits are boot policy, not a mood: ascending, and short enough that a machine whose
    /// engine never comes up still shows its page within seconds.
    #[test]
    fn the_open_waits_add_up_to_seconds_not_minutes() {
        assert!(
            OPEN_WAITS.windows(2).all(|pair| pair[0] <= pair[1]),
            "later attempts get more room, not less",
        );

        let total: Duration = OPEN_WAITS.iter().copied().sum();

        assert!(total < Duration::from_secs(10), "got {total:?}");
    }
}
