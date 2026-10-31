use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A fresh directory under the system temp directory. It is deliberately left behind so a
/// failing test can be inspected in the file system.
pub fn scratch_dir(tag: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("winfw-mcp-test-{}-{tag}-{id}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}
