use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh directory under the system temp directory. It is deliberately left behind so a
/// failing test can be inspected in the file system.
pub fn scratch_dir(tag: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("winfw-mcp-test-{}-{tag}-{id}", std::process::id()));
    // Windows recycles process ids, and the counter restarts at zero every run, so a run can land on
    // a directory an earlier run left behind. A test that treats a missing file as "write the
    // defaults" would then read whatever that earlier build wrote instead.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}
