//! The log file: bounded, and the only place a portable run's lines survive.
//!
//! A release build of a portable tool has no console, so everything `tracing` reports would go
//! nowhere without it. The subscriber writes here and to stderr: the file is what a run leaves
//! behind, and the console is what somebody who started the process by hand watches, so neither is
//! worth choosing over the other.
//!
//! The bound is the point of the module. A firewall logs every interesting thing it ever did, and
//! nothing is watching a portable executable's data directory for a log that grew to a gigabyte, so
//! the newest lines are kept and the oldest go: past [`LOG_LIMIT_BYTES`] the live file moves to
//! `<name>.1`, replacing whatever generation was there before it, and writing starts over.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

/// How many bytes the live log may reach before it is rolled over.
pub const LOG_LIMIT_BYTES: u64 = 1024 * 1024;

/// The suffix the rolled generation gets, on the name it already had.
const ROLLED_SUFFIX: &str = ".1";

/// The log file, shared by every thread that logs.
///
/// One open file behind a lock, because a subscriber hands a writer to as many threads as it likes
/// and no line may be interleaved with half of another. Cloning is cheap, and a clone is the same
/// file rather than a second handle that does not know where the first left off.
#[derive(Clone)]
pub struct LogFile {
    inner: Arc<Inner>,
}

struct Inner {
    path: std::path::PathBuf,
    /// Bytes the live file holds, counted on the way past rather than asked for: the file is open
    /// for append, and asking its length before every line would be the more expensive way to
    /// answer a question the writer is already in a position to answer.
    written: AtomicU64,
    /// `None` while the file could not be opened. The next roll retries.
    file: Mutex<Option<File>>,
}

impl LogFile {
    /// Open `path` for appending, ready to be handed to a subscriber.
    ///
    /// The log directory exists by then, because `DataPaths::ensure` created it. A log has never
    /// been a reason to refuse a startup though, so a caller that gets an error back keeps running
    /// with the lines it does write going only to the console.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;

        let written = file
            .metadata()
            .map(|metadata| metadata.len())
            .unwrap_or_default();

        Ok(Self {
            inner: Arc::new(Inner {
                path: path.to_path_buf(),
                written: AtomicU64::new(written),
                file: Mutex::new(Some(file)),
            }),
        })
    }

    /// Write one buffer, rolling the file over first if it reached the bound.
    ///
    /// A file that could not be opened reports the bytes as written anyway: the line went to the
    /// console, and a log file that is missing is not a reason for a subscriber to give up.
    fn write_out(&self, buf: &[u8]) -> io::Result<usize> {
        if self.inner.written.load(Ordering::Relaxed) >= LOG_LIMIT_BYTES {
            self.rotate();
        }

        let Ok(mut slot) = self.inner.file.lock() else {
            return Ok(buf.len());
        };

        let Some(file) = slot.as_mut() else {
            return Ok(buf.len());
        };

        let written = file.write(buf)?;

        self.inner
            .written
            .fetch_add(written as u64, Ordering::Relaxed);

        Ok(written)
    }

    /// Move the current file to `<name>.1` and start over.
    ///
    /// The handle is closed before the rename, because Windows refuses to move a file a handle has
    /// open. Renaming over the previous generation is what keeps the whole thing to two files.
    ///
    /// A rename that failed leaves the count where it was, so the next writer asks again rather
    /// than appending to a half-rotated file.
    fn rotate(&self) {
        let Ok(mut slot) = self.inner.file.lock() else {
            return;
        };

        *slot = None;

        let rolled = format!("{}{}", self.inner.path.display(), ROLLED_SUFFIX);

        let reopened = std::fs::rename(&self.inner.path, &rolled).and_then(|()| {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.inner.path)
        });

        match reopened {
            Ok(file) => {
                *slot = Some(file);
                self.inner.written.store(0, Ordering::Relaxed);
            }
            Err(_) => *slot = None,
        }
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = Tee;

    fn make_writer(&'a self) -> Self::Writer {
        Tee { file: self.clone() }
    }
}

/// One line, written to the log file and to the console.
///
/// The tee lives here rather than in `main` because it is a property of how this tool logs rather
/// than of how one command line happened to start.
pub struct Tee {
    file: LogFile,
}

impl Write for Tee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // The file decides the result. A console that refuses — a detached process, a closed pipe
        // — must not make a line disappear from the log, and the log is the half nobody notices
        // missing until it is needed.
        let written = self.file.write_out(buf)?;
        let _ = io::stderr().write_all(buf);

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Ok(mut slot) = self.file.inner.file.lock()
            && let Some(file) = slot.as_mut()
        {
            file.flush()?;
        }

        let _ = io::stderr().flush();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line of the shape the subscriber writes: one timestamped row, ending in a newline.
    fn line(text: &str) -> String {
        format!("2026-11-01T00:00:00.000000Z  INFO winfw_mcp: {text}\n")
    }

    /// The whole point of the module: a log that is never looked at must not grow without bound,
    /// and the lines that go are the oldest ones.
    #[test]
    fn a_log_past_the_bound_rolls_over_and_starts_empty_again() {
        let dir = crate::testutil::scratch_dir("log");
        let path = dir.join("winfw-mcp.log");

        let log = LogFile::open(&path).expect("open the log");

        // One line is a hundred-odd bytes, so this is comfortably past a megabyte.
        let chunk = line(&"x".repeat(100));

        for _ in 0..12_000 {
            log.write_out(chunk.as_bytes()).expect("write");
        }

        let live = std::fs::metadata(&path).expect("the live log");
        let rolled = dir.join(format!("winfw-mcp.log{ROLLED_SUFFIX}"));

        assert!(
            live.len() < LOG_LIMIT_BYTES,
            "the live file was rolled rather than left to grow: {} bytes",
            live.len(),
        );
        assert!(
            rolled.is_file(),
            "the generation before it is kept beside it"
        );
        // The bound is checked before the write that crosses it, so a full
        // generation is the limit plus at most one line of overshoot.
        let rolled_len = std::fs::metadata(&rolled).expect("the rolled log").len();
        assert!(
            (LOG_LIMIT_BYTES..LOG_LIMIT_BYTES + chunk.len() as u64).contains(&rolled_len),
            "the rolled file is a full generation, not {rolled_len} bytes",
        );
    }

    /// Two rolls keep two files and no more, which is what makes the bound a real one.
    #[test]
    fn rolling_twice_still_leaves_one_previous_generation() {
        let dir = crate::testutil::scratch_dir("log-twice");
        let path = dir.join("winfw-mcp.log");

        let log = LogFile::open(&path).expect("open the log");

        let chunk = line(&"y".repeat(100));

        for _ in 0..36_000 {
            log.write_out(chunk.as_bytes()).expect("write");
        }

        let mut entries: Vec<String> = std::fs::read_dir(&dir)
            .expect("read the scratch dir")
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        entries.sort();

        assert_eq!(
            entries,
            vec![
                "winfw-mcp.log".to_owned(),
                format!("winfw-mcp.log{ROLLED_SUFFIX}")
            ],
            "a third generation is not created",
        );
    }

    /// A log file is never worth failing a startup over, so the failure is something the caller is
    /// told about rather than something that stops the process.
    #[test]
    fn a_log_that_cannot_be_opened_is_an_error_the_caller_decides_about() {
        let missing = crate::testutil::scratch_dir("log-missing")
            .join("nope")
            .join("x.log");

        assert!(
            LogFile::open(&missing).is_err(),
            "the directory does not exist"
        );
    }

    /// A file that is already partly written is appended to rather than truncated: the process
    /// after a restart should not lose the lines before it.
    #[test]
    fn opening_an_existing_log_keeps_what_is_already_there() {
        let dir = crate::testutil::scratch_dir("log-append");
        let path = dir.join("winfw-mcp.log");

        std::fs::write(&path, "first\n").expect("write the first line");

        let log = LogFile::open(&path).expect("open the log");

        log.write_out(b"second\n").expect("write");

        let text = std::fs::read_to_string(&path).expect("read the log");

        assert_eq!(text, "first\nsecond\n");
    }
}
