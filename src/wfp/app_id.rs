//! Application identities: wildcard expansion of a pattern into the applications the detector
//! has seen, and the blob a filter condition points at.

use crate::wfp::*;

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
pub(super) struct Expansion {
    /// The applications to install filters for, at most [`MAX_WILDCARD_MATCHES`] of them.
    pub(super) apps: Vec<AppId>,
    /// How many applications the pattern matched before the cap was applied.
    pub(super) matches: usize,
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

/// How far one rule's pattern field reaches: the number of applications it matched and the number
/// of them the cap allows to be installed. Only a wildcard element can be truncated, and the two
/// numbers differ exactly then, which is what `pattern_reach` is asked for by `/api/state`.
///
/// The cap is over the whole field rather than per element. A list of applications multiplies with
/// the ports and the addresses of the rule, and every application costs a filter per layer in a
/// store that is shared with everything else on the machine, so holding each element down on its
/// own could still install a multiple of the limit.
///
/// Unlike [`app_ids`] nothing is resolved with WFP, so this only counts and never touches the
/// filter store.
pub(crate) fn pattern_reach(patterns: &crate::rules::Patterns, known: &[String]) -> (usize, usize) {
    let mut matches = 0;
    let mut installed = 0;

    for pattern in patterns.elements() {
        let (hits, stands) = element_reach(pattern, known);
        matches += hits;
        installed += stands.len();
    }

    (matches, installed.min(MAX_WILDCARD_MATCHES))
}

/// Build the application identities one rule needs.
///
/// An exact pattern is resolved on its own, which is the normal case a Detected entry produces.
/// A wildcard pattern is matched against the paths this tool has seen; when nothing has been seen
/// yet the pattern itself goes into the store, so the rule is at least visible to the user. Both
/// happen per element of the field, and [`MAX_WILDCARD_MATCHES`] is spent over the whole field
/// rather than per element.
pub(super) fn app_ids(patterns: &crate::rules::Patterns, known: &[String]) -> Expansion {
    let mut apps: Vec<AppId> = Vec::new();
    let mut matches = 0;

    for pattern in patterns.elements() {
        let (hits, stands) = element_reach(pattern, known);
        matches += hits;

        // The cap is spent over the whole field rather than per element, so an element
        // gets whatever room the field has left.
        let room = MAX_WILDCARD_MATCHES - apps.len().min(MAX_WILDCARD_MATCHES);
        apps.extend(stands.into_iter().take(room).map(AppId::resolve));
    }

    Expansion { apps, matches }
}

/// What one element of a pattern field reaches among the applications seen so far: the
/// number it matched and the paths that stand for it.
///
/// An exact element is the pattern itself and needs no lookup. A wildcard is every path
/// under it, and a wildcard that matches nothing keeps the pattern itself, so one filter
/// per element is always the minimum. Both `pattern_reach` and `app_ids` ask this one
/// question and differ only in what they do with the answers; keeping the question in one
/// place is what stops the state view and the installation from drifting apart.
pub(super) fn element_reach<'a>(pattern: &'a str, known: &'a [String]) -> (usize, Vec<&'a str>) {
    if !is_wildcard(pattern) {
        return (1, vec![pattern]);
    }

    let device_pattern = crate::device::to_device_path(pattern);
    let matched: Vec<&str> = known
        .iter()
        .filter(|path| wildcard_match(&device_pattern, path))
        .map(String::as_str)
        .collect();

    if matched.is_empty() {
        (0, vec![pattern])
    } else {
        (matched.len(), matched)
    }
}

/// The application identity used as a filter condition.
///
/// WFP does not match a file name but a device path blob. `FwpmGetAppIdFromFileName0` resolves one
/// for a file that exists, which is the case for the concrete paths learning mode produces. A
/// wildcard pattern usually names a file that does not exist; then the pattern is handed over as
/// it stands and the match becomes exact. Wildcard patterns are expanded into the concrete
/// applications the detector has seen, so a pattern matches every observed program under it.
pub(super) struct AppId {
    pub(super) blob: FWP_BYTE_BLOB,
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
