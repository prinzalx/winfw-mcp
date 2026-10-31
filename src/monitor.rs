//! Live connection events: one subscription, one bounded log.
//!
//! The source is WFP's own event stream (`FwpmNetEventSubscribe4`). Callbacks arrive on threads of
//! the RPC runtime rather than on a thread we control, so the hand-off to the server is a
//! lock-protected log with a sequence number: the log is the only shared state, and a reader asks
//! for "everything after sequence N", which is exactly what an SSE client needs.
//!
//! The log is bounded on purpose. A firewall sees far more connections than a human can read, and
//! the only consumers are the UI panel and learning mode, neither of which needs history older
//! than the last few screens.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// How many events the log keeps. Oldest events fall out at the front.
const LOG_CAPACITY: usize = 200;

/// One connection as the firewall reported it.
///
/// `app` is empty when the event carried no application path, which happens for traffic that
/// belongs to a kernel driver rather than to a process.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NetEvent {
    /// Monotonic within this process; what an SSE client uses to ask for new events only.
    pub seq: u64,
    /// Milliseconds since the Unix epoch, converted from the event's `FILETIME`.
    pub time_ms: u64,
    /// The application path, exactly as the store reported it.
    pub app: String,
    /// Remote port in host byte order, `0` when the event carried none.
    pub remote_port: u16,
    /// IP protocol number: 6 is TCP, 17 is UDP.
    pub protocol: u8,
    /// `false` when the firewall blocked the connection.
    pub allowed: bool,
    /// How the event was classified, for the UI label.
    pub kind: String,
}

/// The shared log between the monitor's callbacks and the request threads.
#[derive(Debug, Default)]
pub struct EventLog {
    inner: Mutex<Log>,
}

#[derive(Debug, Default)]
struct Log {
    /// Sequence number handed to the most recent event.
    next: u64,
    events: VecDeque<NetEvent>,
}

impl EventLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one event and hand back the sequence number it got.
    ///
    /// The caller's own `seq` is overwritten: numbering belongs to the log, so two callbacks
    /// cannot both claim to be event one.
    pub fn push(&self, event: NetEvent) -> u64 {
        let mut log = self.inner.lock().expect("event log lock poisoned");

        log.next += 1;
        let seq = log.next;

        if log.events.len() == LOG_CAPACITY {
            log.events.pop_front();
        }
        log.events.push_back(NetEvent { seq, ..event });

        seq
    }

    /// Everything newer than `last`, oldest first.
    pub fn since(&self, last: u64) -> Vec<NetEvent> {
        let log = self.inner.lock().expect("event log lock poisoned");

        log.events
            .iter()
            .filter(|event| event.seq > last)
            .cloned()
            .collect()
    }

    /// The whole log, oldest first.
    pub fn snapshot(&self) -> Vec<NetEvent> {
        self.since(0)
    }
}

/// Where a callback hands what it saw.
///
/// The log is the connection feed, and the detector is learning mode's list. Both are shared with
/// the request threads, so a callback holds a lock only for as long as appending takes. The rules
/// are read to decide whether an application is already covered by a decision the user made.
#[cfg(windows)]
#[derive(Clone)]
struct Sink {
    log: Arc<EventLog>,
    detector: Arc<crate::learn::Detector>,
    rules: Arc<Mutex<crate::rules::RuleFile>>,
    /// `learn_mode` from the settings. Read once at startup, like every other setting, so the
    /// callback does not have to reach for the config on every connection.
    learning: bool,
}

/// The thread that keeps a subscription open.
///
/// It opens an engine handle of its own, so subscribing and unsubscribing cannot interleave with
/// the transactions the WFP worker runs on its handle.
pub struct Monitor {
    /// Dropping this tells the monitor thread that the process is done.
    shutdown: Option<Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl Monitor {
    /// Start listening. Dropping the returned handle stops the subscription.
    ///
    /// A machine where the event session is unavailable is not a failure: the rest of the tool
    /// still works, it just has no live feed, which the monitor reports in its log.
    pub fn start(
        log: Arc<EventLog>,
        detector: Arc<crate::learn::Detector>,
        rules: Arc<Mutex<crate::rules::RuleFile>>,
        learning: bool,
    ) -> Self {
        let (shutdown, receiver) = channel();

        let join = thread::spawn(move || listen(log, detector, rules, learning, receiver));

        Self {
            shutdown: Some(shutdown),
            join: Some(join),
        }
    }
}

impl Drop for Monitor {
    fn drop(&mut self) {
        drop(self.shutdown.take());

        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Subscribe, then wait to be told to stop.
#[cfg(windows)]
fn listen(
    log: Arc<EventLog>,
    detector: Arc<crate::learn::Detector>,
    rules: Arc<Mutex<crate::rules::RuleFile>>,
    learning: bool,
    shutdown: Receiver<()>,
) {
    use std::ffi::c_void;

    use tracing::{debug, warn};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_UINT32, FWP_VALUE0, FWP_VALUE0_0, FWPM_ENGINE_COLLECT_NET_EVENTS,
        FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, FWPM_NET_EVENT_ENUM_TEMPLATE0,
        FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW, FWPM_NET_EVENT_SUBSCRIPTION0, FWPM_SESSION0,
        FwpmEngineClose0, FwpmEngineOpen0, FwpmEngineSetOption0, FwpmNetEventSubscribe4,
        FwpmNetEventUnsubscribe0,
    };
    use windows::core::PCWSTR;

    // `RPC_C_AUTHN_DEFAULT`, spelled out rather than pulling in the RPC module for one constant.
    const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;

    // Events belong to a session, so the monitor has one of its own and subscribes to that key.
    // The session is deliberately not dynamic: the engine refuses to set options on a dynamic
    // session, and because the monitor installs no filters there is nothing for it to clean up
    // when the process ends.
    //
    // This key must match the one the WFP worker uses: network events are collected per session,
    // and the ALE classifications worth reporting happen in the worker's session.
    const SESSION_KEY: windows::core::GUID =
        windows::core::GUID::from_u128(0x6c9e8b14_3f7a_4d52_a8c1_5e0b7d92f4a6);

    let session = FWPM_SESSION0 {
        sessionKey: SESSION_KEY,
        ..Default::default()
    };

    let mut engine = HANDLE::default();

    let status = unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_DEFAULT,
            None,
            Some(&session),
            &mut engine,
        )
    };

    if status != 0 {
        warn!(
            code = format!("{status:#010x}"),
            "event monitor could not open WFP"
        );

        return;
    }

    // Without these options the engine hands out nothing: collection has to be turned on at all,
    // and the keyword mask decides which classes are collected. Only blocked connections are
    // reported by default, and learning mode needs the allowed ones, which is what the classifier
    // keyword is for. Both settings belong to the session they are made on, so they go away with
    // the monitor instead of changing the machine for everyone else.
    let enable = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 { uint32: 1 },
    };

    let keywords = FWP_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_VALUE0_0 {
            uint32: FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW,
        },
    };

    for (option, value, what) in [
        (FWPM_ENGINE_COLLECT_NET_EVENTS, &enable, "collection"),
        (
            FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS,
            &keywords,
            "allowed-connection keywords",
        ),
    ] {
        let status = unsafe { FwpmEngineSetOption0(engine, option, value) };

        if status != 0 {
            warn!(
                code = format!("{status:#010x}"),
                option = what,
                "event monitor could not configure WFP",
            );
        }
    }

    // A zeroed template means every event class and no time window; the session key is what
    // selects the traffic.
    let enum_template = FWPM_NET_EVENT_ENUM_TEMPLATE0::default();
    let subscription = FWPM_NET_EVENT_SUBSCRIPTION0 {
        // The API takes a mutable pointer although it only ever reads the template.
        enumTemplate: &raw const enum_template as *mut _,
        sessionKey: SESSION_KEY,
        ..Default::default()
    };
    let context = Box::into_raw(Box::new(Sink {
        log,
        detector,
        rules,
        learning,
    })) as *mut c_void;

    let mut events = HANDLE::default();

    let status = unsafe {
        FwpmNetEventSubscribe4(
            engine,
            &subscription,
            Some(on_event),
            Some(context),
            &mut events,
        )
    };

    if status != 0 {
        warn!(
            code = format!("{status:#010x}"),
            "event subscription refused"
        );

        unsafe {
            let _ = FwpmEngineClose0(engine);

            drop(Box::from_raw(context as *mut Sink));
        }

        return;
    }

    debug!("event monitor subscribed");

    // Callbacks run on RPC threads; this thread only holds the subscription open. The sender lives
    // in `Monitor`, so `Err` here means that handle was dropped and the process is shutting down.
    let _ = shutdown.recv();

    unsafe {
        let _ = FwpmNetEventUnsubscribe0(engine, events);
        let _ = FwpmEngineClose0(engine);

        // Unsubscribing is what guarantees no callback runs after this point, so the context can
        // be reclaimed here.
        drop(Box::from_raw(context as *mut Sink));
    }

    debug!("event monitor unsubscribed");

    /// Copy one store event into the log and into learning mode.
    ///
    /// Everything read here is memory the caller owns and that is released when the callback
    /// returns, which is why the entry is copied rather than referenced.
    unsafe extern "system" fn on_event(
        context: *mut c_void,
        event: *const windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT5,
    ) {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
        };

        if context.is_null() || event.is_null() {
            return;
        }

        let sink = unsafe { &*(context as *const Sink) };
        let event = unsafe { &*event };

        let allowed = event.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW;
        let kind = if allowed {
            "allowed"
        } else if event.r#type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
            "blocked"
        } else {
            "other"
        };

        let entry = NetEvent {
            seq: 0,
            time_ms: filetime_to_millis(&event.header.timeStamp),
            app: blob_to_string(&event.header.appId),
            remote_port: event.header.remotePort,
            protocol: event.header.ipProtocol,
            allowed,
            kind: kind.to_owned(),
        };

        // Learning mode looks at the application behind the connection, not at the connection
        // itself, so the log gets a copy and the detector gets the original. With `learn_mode`
        // off the log still fills, because it is what the connection panel shows.
        sink.log.push(entry.clone());

        if !sink.learning {
            return;
        }

        let covered = sink.rules.lock().expect("rules lock poisoned").clone();

        if sink.detector.observe(&entry, &covered)
            && let Err(error) = sink.detector.save()
        {
            warn!(reason = %format!("{error:#}"), "could not write learn.json");
        }
    }
}

/// The non-Windows monitor exists so the crate still builds for a doc tool.
#[cfg(not(windows))]
fn listen(
    _log: Arc<EventLog>,
    _detector: Arc<crate::learn::Detector>,
    _rules: Arc<Mutex<crate::rules::RuleFile>>,
    _learning: bool,
    shutdown: Receiver<()>,
) {
    let _ = shutdown.recv();
}

/// Milliseconds since the Unix epoch from a `FILETIME`, which counts 100 ns steps since 1601.
#[cfg(windows)]
fn filetime_to_millis(value: &windows::Win32::Foundation::FILETIME) -> u64 {
    let raw = (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime);

    // 116444736000000000 is the number of 100 ns steps between 1601-01-01 and 1970-01-01.
    raw.checked_sub(116_444_736_000_000_000)
        .map_or(0, |delta| delta / 10_000)
}

/// Copy a WFP byte blob out as a string.
///
/// Paths arrive as UTF-16 with a trailing NUL, and `size` counts bytes, so the length has to be
/// halved before anything is decoded. A blob with an odd length loses its last byte rather than
/// reading past the end.
#[cfg(windows)]
fn blob_to_string(
    blob: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
) -> String {
    if blob.data.is_null() || blob.size == 0 {
        return String::new();
    }

    let bytes = unsafe { std::slice::from_raw_parts(blob.data as *const u8, blob.size as usize) };

    let mut units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();

    if units.last() == Some(&0) {
        units.pop();
    }

    String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(app: &str) -> NetEvent {
        NetEvent {
            seq: 0,
            time_ms: 0,
            app: app.to_owned(),
            remote_port: 443,
            protocol: 6,
            allowed: true,
            kind: "allowed".to_owned(),
        }
    }

    #[test]
    fn a_push_numbers_the_event_and_a_snapshot_returns_it() {
        let log = EventLog::new();

        log.push(event("a.exe"));

        let snapshot = log.snapshot();

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].seq, 1);
        assert_eq!(snapshot[0].app, "a.exe");
    }

    #[test]
    fn since_returns_only_newer_events() {
        let log = EventLog::new();

        log.push(event("a.exe"));
        log.push(event("b.exe"));

        let newer = log.since(1);

        assert_eq!(newer.len(), 1);
        assert_eq!(newer[0].app, "b.exe");
    }

    #[test]
    fn the_log_drops_the_oldest_event_when_it_is_full() {
        let log = EventLog::new();

        for index in 0..LOG_CAPACITY + 5 {
            log.push(event(&format!("app{index}.exe")));
        }

        let snapshot = log.snapshot();

        assert_eq!(snapshot.len(), LOG_CAPACITY);
        assert_eq!(snapshot.first().unwrap().app, "app5.exe");
    }

    #[cfg(windows)]
    #[test]
    fn a_blob_is_read_as_utf16_without_its_trailing_nul() {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;

        let path = "C:\\windows\\a.exe";
        let mut raw: Vec<u16> = path.encode_utf16().chain([0]).collect();

        let blob = FWP_BYTE_BLOB {
            size: (raw.len() * 2) as u32,
            data: raw.as_mut_ptr().cast(),
        };

        assert_eq!(blob_to_string(&blob), path);
    }

    #[cfg(windows)]
    #[test]
    fn a_filetime_before_the_epoch_counts_as_zero() {
        let value = windows::Win32::Foundation::FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };

        assert_eq!(filetime_to_millis(&value), 0);
    }
}
