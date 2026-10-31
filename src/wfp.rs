//! The only module that talks to the Windows Filtering Platform.
//!
//! The read path opens the engine and enumerates the store. The write path turns the rule file
//! into live filters, always inside a transaction, always through the one engine handle.

use std::ffi::c_void;

use anyhow::{Result, bail};
use windows::Win32::Foundation::{FWP_E_ALREADY_EXISTS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0,
    FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER_FLAG_INDEXED, FWPM_FILTER_FLAG_PERSISTENT,
    FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteByKey0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderCreateEnumHandle0,
    FwpmProviderDestroyEnumHandle0, FwpmProviderEnum0, FwpmSubLayerAdd0,
    FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0, FwpmSubLayerEnum0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows::core::{GUID, PCWSTR, PWSTR};

use crate::rules::{Action, Rule, RuleFile, is_wildcard, wildcard_match};

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
const WEIGHT_DENY: u8 = 0x0F;

/// Filter weight for an allow rule, one step below a deny.
const WEIGHT_ALLOW: u8 = 0x0E;

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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// Filters that carried our provider key and are gone now.
    pub removed: usize,
    /// Filters installed from the enabled rules, counted per layer.
    pub installed: usize,
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
    pub fn apply(&self, rules: &RuleFile, known: &[String]) -> Result<Applied> {
        let mut report = Applied::default();

        self.transaction(|| {
            self.ensure_provider()?;
            self.ensure_sublayer()?;

            report.removed = self.remove_our_filters()?;

            let mut installed = 0;

            for rule in rules.rule.iter().filter(|rule| rule.enabled) {
                installed += self.add_rule(rule, known)?;
            }

            report.installed = installed;

            Ok(())
        })?;

        Ok(report)
    }

    /// Take our filters out of the store, leaving the provider and the sublayer in place.
    pub fn clear(&self) -> Result<usize> {
        let mut removed = 0;

        self.transaction(|| {
            removed = self.remove_our_filters()?;
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

    /// Delete every filter our provider owns, and report how many there were.
    ///
    /// The enumeration is unfiltered and the provider is selected here rather than with a
    /// `FWPM_FILTER_ENUM_TEMPLATE0`: on a real store the template was rejected with
    /// `FWPM_E_INVALID_ENUM_TYPE`, and we already enumerate all filters for the inventory, so the
    /// extra entries cost nothing we were not already paying.
    fn remove_our_filters(&self) -> Result<usize> {
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
                let ours = match unsafe { filter.providerKey.as_ref() } {
                    Some(key) => *key == PROVIDER_KEY,
                    None => false,
                };

                if ours {
                    keys.push(filter.filterKey);
                }
            }

            // SAFETY: the array is WFP-owned, and this is the documented way to release it.
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
        }

        // SAFETY: the enum handle is still open and belongs to this engine.
        unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };

        let mut removed = 0;

        for key in keys {
            // SAFETY: the key came out of the store a few instructions ago, and deleting one
            // filter by key does not invalidate the other keys we collected.
            let status = unsafe { FwpmFilterDeleteByKey0(self.handle, &key) };

            if status != 0 {
                bail!("FwpmFilterDeleteByKey0 failed with 0x{status:08X}");
            }

            removed += 1;
        }

        Ok(removed)
    }

    /// Install one rule as one filter per application per layer, so both directions and both
    /// address families are covered. Returns the number of filters installed.
    fn add_rule(&self, rule: &Rule, known: &[String]) -> Result<usize> {
        let apps = app_ids(&rule.pattern, known);

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

        // One condition per application, because it points into that application's blob.
        for (index, app) in apps.iter().enumerate() {
            let mut condition = FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: &raw const app.blob as *mut _,
                    },
                },
            };

            for layer in LAYERS {
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
                filter.numFilterConditions = 1;
                filter.filterCondition = &mut condition;
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

                installed += 1;
            }
        }

        Ok(installed)
    }
}

/// How many applications one wildcard rule may be expanded into.
///
/// A pattern is allowed to be broad, but the store is shared and every match costs four filters.
/// The cap keeps a careless `*` from turning one rule into thousands.
const MAX_WILDCARD_MATCHES: usize = 32;

/// Build the application identities one rule needs.
///
/// An exact pattern is resolved on its own, which is the normal case a Detected entry produces.
/// A wildcard pattern is matched against the paths this tool has seen; when nothing has been seen
/// yet the pattern itself goes into the store, so the rule is at least visible to the user.
fn app_ids(pattern: &str, known: &[String]) -> Vec<AppId> {
    if !is_wildcard(pattern) {
        return vec![AppId::resolve(pattern)];
    }

    let device_pattern = crate::device::to_device_path(pattern);

    let mut ids: Vec<AppId> = known
        .iter()
        .filter(|path| wildcard_match(&device_pattern, path))
        .take(MAX_WILDCARD_MATCHES)
        .map(|path| AppId::resolve(path))
        .collect();

    if ids.is_empty() {
        ids.push(AppId::resolve(pattern));
    }

    ids
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

    /// A path that exists on every Windows install, so the application-id resolution succeeds.
    const TEST_APP: &str = "C:\\Windows\\System32\\cmd.exe";

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
                Rule {
                    name: "winfw-mcp write test".to_owned(),
                    action: Action::Deny,
                    pattern: TEST_APP.to_owned(),
                    enabled: true,
                },
                Rule {
                    name: "winfw-mcp write test allow".to_owned(),
                    action: Action::Allow,
                    pattern: TEST_APP.to_owned(),
                    enabled: true,
                },
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

        let applied = engine.apply(&rules, &[]).expect("apply the rule");

        assert_eq!(applied.installed, expected, "one filter per rule and layer");
        assert_eq!(applied.removed, 0, "the store was cleared first");

        let rebuilt = engine
            .apply(&rules, &[])
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
}
