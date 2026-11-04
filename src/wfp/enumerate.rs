//! Handles and result arrays handed out by the enumeration calls, closed and freed on scope
//! exit, plus the macro that runs one enumeration end to end.

use crate::wfp::*;

/// An enumeration handle of one engine family, closed when it goes out of scope.
///
/// The three families differ only in the destroy function, so the wrapper holds a pointer to
/// that function rather than repeating the closing for each family.
pub(super) struct EnumHandle {
    pub(super) engine: HANDLE,
    pub(super) handle: HANDLE,
    pub(super) destroy: unsafe fn(HANDLE, HANDLE) -> u32,
}

impl Drop for EnumHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from a Create call of the same engine and is closed exactly
        // once, because this type owns it.
        unsafe { (self.destroy)(self.engine, self.handle) };
    }
}

/// An array of entries WFP allocated and owns until the pointer is handed back to
/// `FwpmFreeMemory0`, which happens on drop.
///
/// The elements were never allocated apart from the array, so only the array pointer may be
/// released; releasing an element as well corrupts the heap.
pub(super) struct WfpArray<T> {
    pub(super) pointer: *mut *mut T,
    pub(super) len: u32,
}

impl<T> WfpArray<T> {
    /// The entries WFP returned. A null array holds none, which is how an empty store reads
    /// rather than a failure; a null slot inside a non-null array is skipped as well.
    pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
        let slots: &[*mut T] = if self.pointer.is_null() {
            &[]
        } else {
            // SAFETY: WFP reported `len` slots for a non-null array, so they are all inside it.
            unsafe { std::slice::from_raw_parts(self.pointer, self.len as usize) }
        };

        slots.iter().filter_map(|slot| {
            // SAFETY: a non-null slot points at an entry that stays readable until the array
            // is handed back on drop.
            unsafe { slot.as_ref() }
        })
    }
}

impl<T> Drop for WfpArray<T> {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            // SAFETY: the array is WFP-owned, and this is the documented way to release it.
            unsafe { FwpmFreeMemory0(&mut self.pointer as *mut _ as *mut *mut c_void) };
        }
    }
}

/// Run one of the three enumeration sequences end to end and collect the display names.
///
/// The three `Fwpm*` families differ only in name and entry type, which is what makes them worth
/// a macro rather than three copies of the same loop.
///
/// Everything is requested in a single call, the way the C reference does it. Not only is that
/// one round trip instead of several, it also keeps the ownership rule simple: the whole result
/// is one WFP allocation, released by [`WfpArray`], and the enumeration handle is closed by
/// [`EnumHandle`]. Both on scope exit, so no failure path can leak either.
macro_rules! enumerate {
    ($engine:expr, $create:ident, $fetch:ident, $destroy:ident, $entry:ty) => {{
        let engine = $engine;
        let mut raw = HANDLE::default();

        // SAFETY: a null template asks for every entry, and `raw` is an out parameter.
        let status = unsafe { $create(engine, None, &mut raw) };
        if status != 0 {
            anyhow::bail!("{} failed with 0x{status:08X}", stringify!($create));
        }

        let enum_handle = crate::wfp::enumerate::EnumHandle {
            engine,
            handle: raw,
            destroy: $destroy,
        };

        let mut pointer: *mut *mut $entry = std::ptr::null_mut();
        let mut returned = 0u32;

        // SAFETY: both out parameters are valid, and the array they receive belongs to WFP.
        let status = unsafe {
            $fetch(
                engine,
                enum_handle.handle,
                u32::MAX,
                &mut pointer,
                &mut returned,
            )
        };
        if status != 0 {
            anyhow::bail!("{} failed with 0x{status:08X}", stringify!($fetch));
        }

        let entries = crate::wfp::enumerate::WfpArray {
            pointer,
            len: returned,
        };

        let mut names = Vec::new();

        for entry in entries.iter() {
            names.push(crate::wfp::enumerate::display_name(&entry.displayData));
        }

        Ok(names)
    }};
}

/// Copy a display name out of WFP-owned memory. A null name is not an error; an empty string
/// keeps the listing usable.
pub(super) fn display_name(data: &FWPM_DISPLAY_DATA0) -> String {
    if data.name.is_null() {
        return String::new();
    }

    // SAFETY: the pointer is not null, and WFP guarantees a terminated wide string there.
    unsafe { data.name.to_string() }.unwrap_or_default()
}
