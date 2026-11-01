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
//!
//! A connection that never left the machine is dropped before it reaches the log, so the feed, its
//! counters and learning mode all agree about what is worth showing. The rules themselves do not
//! care: the loopback permits of the default-deny policy are still installed.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{Receiver, Sender, SyncSender, channel, sync_channel};
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
    /// The local address in the text form a human reads, empty when the event carried none.
    ///
    /// A listener shows the address it bound to here, which is how `0.0.0.0` and a single
    /// interface are told apart. For client traffic it is the source address the route picked.
    pub local_addr: String,
    /// Local port in host byte order, `0` when the event carried none.
    pub local_port: u16,
    /// Remote port in host byte order, `0` when the event carried none.
    pub remote_port: u16,
    /// The remote address in the text form a human reads, empty when the event carried none.
    ///
    /// This is what makes a destination visible: two connections from one application to two
    /// networks are the same application twice in the log and two different destinations.
    pub remote_addr: String,
    /// IP protocol number: 6 is TCP, 17 is UDP.
    pub protocol: u8,
    /// `true` when the traffic never left the loopback adapter.
    ///
    /// Only the classify arms of an event report this, and a dropped event that is not a classify
    /// drop reports `false` rather than "unknown".
    ///
    /// A connection with this marker set never reaches the feed at all (see
    /// [`shown_in_feed`]), so what the page and the MCP show are external connections; the field
    /// stays for the debug switch that keeps them.
    pub loopback: bool,
    /// `true` when the remote end is on the local segment: private, link-local or unique local.
    ///
    /// Such a connection leaves the machine and is therefore shown, but it is marked so the page
    /// can offer a filter for it. Always `false` for an event that names no remote address.
    pub local_network: bool,
    /// `false` when the firewall blocked the connection.
    pub allowed: bool,
    /// How the event was classified, for the UI label.
    pub kind: String,
    /// The store's id of the filter that decided this, `0` when the event did not name one.
    ///
    /// Ids are handed out per install, so this is only meaningful beside the table of the rebuild
    /// that is currently in the store. It is reported raw so a client can tell "not ours" from "no
    /// filter was named at all".
    pub filter_id: u64,
    /// The rule that filter came from, when the filter is one of ours.
    ///
    /// `None` with a non-zero `filter_id` means the store blamed a filter this tool did not install
    /// — another firewall on the machine — or one of ours that a later rebuild replaced.
    pub rule: Option<String>,
}

/// Whether a text address is a loopback address: all of `127.0.0.0/8` or `::1`.
///
/// Text is what the event carries, so this is a parser rather than a comparison of bytes. An
/// address that does not parse at all is not loopback: refusing to classify it is what keeps an
/// event the engine described oddly from being dropped out of the feed.
#[cfg(windows)]
fn is_loopback_address(address: &str) -> bool {
    use std::net::IpAddr;

    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address.is_loopback(),
        Ok(IpAddr::V6(address)) => {
            address.is_loopback()
                || address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
        Err(_) => false,
    }
}

/// Whether a text address names a network on the local segment rather than the Internet: the
/// private ranges (RFC 1918), link-local (`169.254.0.0/16`, `fe80::/10`) or unique local
/// (`fc00::/7`).
///
/// These connections do leave the machine — a share on another box is not loopback — but they are
/// not the destinations a rule for `*.example.com` is about, so the page marks them and offers a
/// filter for them.
#[cfg(windows)]
fn is_local_network_address(address: &str) -> bool {
    use std::net::IpAddr;

    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            let [first, second, ..] = address.octets();

            first == 10
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 168)
                || (first == 169 && second == 254)
        }
        Ok(IpAddr::V6(address)) => match address.to_ipv4_mapped() {
            Some(mapped) => is_local_network_address(&mapped.to_string()),
            None => {
                let bytes = address.octets();

                (bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80) || bytes[0] & 0xfe == 0xfc
            }
        },
        Err(_) => false,
    }
}

/// Whether a connection never left this machine.
///
/// WFP's own marker is believed when it carries one, which covers the case where both ends are this
/// machine. Without a marker the remote end decides: a connection to a loopback address cannot have
/// left. An event that names no remote end is kept, because a destination the header did not fill
/// is not evidence the traffic stayed home.
#[cfg(windows)]
fn stays_on_this_machine(entry: &NetEvent) -> bool {
    entry.loopback || is_loopback_address(&entry.remote_addr)
}

/// Whether an event belongs in the connection feed.
///
/// Local traffic is dropped here rather than filtered out in the page: a local agent talking to a
/// local server produces a stream of it, and the ring buffer would fill with noise while the
/// connections a user could act on fell out the front. Turning `debug_show_loopback` on keeps the
/// events, which is how the feed behaved before 0.37.0.
#[cfg(windows)]
fn shown_in_feed(entry: &NetEvent, debug_show_loopback: bool) -> bool {
    debug_show_loopback || !stays_on_this_machine(entry)
}

/// Which of our filters the store blames for a verdict, by the id it handed us when the filter went
/// in, pointing at the rule it was installed from.
///
/// A net event names a `filterId` and nothing else, and ids are handed out per install rather than
/// derived from content, so the table only answers for the rebuild that is currently in the store.
/// An id that is not in here belongs to something else on the machine, or to one of our own filters
/// that a later rebuild replaced.
pub type Attribution = HashMap<u64, String>;

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

    /// How many events arrived since the process started, including the ones the bound dropped.
    ///
    /// This is what distinguishes a feed that is running but idle from one that delivers events,
    /// so it counts what came in rather than what the capacity left behind.
    pub fn delivered(&self) -> u64 {
        self.inner.lock().expect("event log lock poisoned").next
    }
}

/// What the event subscription did about being asked to listen.
///
/// A refused subscription is a supported state — an unelevated run cannot open the event session at
/// all — but it used to be visible only in the log, so the page showed an empty connection list
/// with no reason and a reader had to know whether the machine was quiet or the feed was out. It is
/// reported next to the list for that reason.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MonitorStatus {
    /// `starting`, `running`, `refused` or `stopped`.
    pub state: &'static str,
    /// The code that refused it, when one did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Default for MonitorStatus {
    fn default() -> Self {
        Self {
            state: "starting",
            code: None,
        }
    }
}

impl MonitorStatus {
    /// The subscription is open and callbacks may arrive.
    pub fn running() -> Self {
        Self {
            state: "running",
            code: None,
        }
    }

    /// A call on the way to subscribing answered a failure, which ends the feed.
    pub fn refused(code: impl std::fmt::Display) -> Self {
        Self {
            state: "refused",
            code: Some(code.to_string()),
        }
    }

    /// The subscription was closed on the way out.
    pub fn stopped() -> Self {
        Self {
            state: "stopped",
            code: None,
        }
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
    /// `learn_mode` and `default_policy` as they stand right now. A settings change made in the
    /// browser lands here rather than in a copy taken at startup, and a rebuild the callback
    /// queues has to carry the policy, because it writes the whole store including the base
    /// filters.
    live: Arc<crate::server::Live>,
    /// Hand a store rebuild to the WFP worker when an application turns up that no filter knows
    /// yet. The answer is not waited for: the next page load reads the store anyway.
    rebuild: Option<SyncSender<crate::server::WorkItem>>,
    /// The table the WFP worker republishes on every rebuild, read here to name the rule an event
    /// blames. Shared so a rebuild is visible to the callback without restarting the subscription.
    owners: Arc<Mutex<Attribution>>,
    /// Keep connections that never left the machine in the feed instead of dropping them.
    ///
    /// Read once at startup, like `log_level`: the switch exists for a diagnosis run, and a feed
    /// whose rules changed halfway would leave the list behind it hard to read.
    debug_show_loopback: bool,
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
        live: Arc<crate::server::Live>,
        rebuild: Option<SyncSender<crate::server::WorkItem>>,
        owners: Arc<Mutex<Attribution>>,
        debug_show_loopback: bool,
    ) -> Self {
        let (shutdown, receiver) = channel();

        let join = thread::spawn(move || {
            listen(
                log,
                detector,
                rules,
                live,
                rebuild,
                owners,
                debug_show_loopback,
                receiver,
            );
        });

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
///
/// The arguments are the parts of the callback's context, handed over individually because that is
/// what `Monitor::start` is given; bundling them here would mean a struct that only exists to be
/// taken apart again two lines later.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn listen(
    log: Arc<EventLog>,
    detector: Arc<crate::learn::Detector>,
    rules: Arc<Mutex<crate::rules::RuleFile>>,
    live: Arc<crate::server::Live>,
    rebuild: Option<SyncSender<crate::server::WorkItem>>,
    owners: Arc<Mutex<Attribution>>,
    debug_show_loopback: bool,
    shutdown: Receiver<()>,
) {
    use std::ffi::c_void;

    use tracing::{debug, info, warn};
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

    // Kept so the thread can report what subscribing did, after the handle itself moved into the
    // callback's context.
    let reported = Arc::clone(&live);

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

        reported.set_monitor(MonitorStatus::refused(format!("{status:#010x}")));

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
        live,
        rebuild,
        owners,
        debug_show_loopback,
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

        reported.set_monitor(MonitorStatus::refused(format!("{status:#010x}")));

        unsafe {
            let _ = FwpmEngineClose0(engine);

            drop(Box::from_raw(context as *mut Sink));
        }

        return;
    }

    reported.set_monitor(MonitorStatus::running());

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

    reported.set_monitor(MonitorStatus::stopped());

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

        // The event names the deciding filter by id, in whichever arm of the union its type
        // selects. Both classify arms carry a `filterId` and the loopback marker; the IPsec arm
        // does not name a filter we installed, so everything else reports `0` and reads as "not
        // ours".
        let (filter_id, loopback) = unsafe {
            match event.r#type {
                FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW => event
                    .Anonymous
                    .classifyAllow
                    .as_ref()
                    .map_or((0, false), |allow| {
                        (allow.filterId, allow.isLoopback.as_bool())
                    }),
                FWPM_NET_EVENT_TYPE_CLASSIFY_DROP => event
                    .Anonymous
                    .classifyDrop
                    .as_ref()
                    .map_or((0, false), |drop| {
                        (drop.filterId, drop.isLoopback.as_bool())
                    }),
                _ => (0, false),
            }
        };

        // Look the id up in the table the last rebuild left behind. A miss is not an error: it is
        // either a filter another firewall owns or one a later rebuild replaced.
        let rule = if filter_id == 0 {
            None
        } else {
            sink.owners
                .lock()
                .expect("owners lock poisoned")
                .get(&filter_id)
                .cloned()
        };

        let remote_addr = event_address(&event.header, End::Remote);

        let entry = NetEvent {
            seq: 0,
            time_ms: filetime_to_millis(&event.header.timeStamp),
            app: blob_to_string(&event.header.appId),
            local_addr: event_address(&event.header, End::Local),
            local_port: event_port(&event.header, End::Local),
            remote_port: event_port(&event.header, End::Remote),
            // Whether the destination is on the local segment is decided here, where the address
            // already is, so the page can mark it without reading the event again.
            local_network: is_local_network_address(&remote_addr),
            remote_addr,
            protocol: event.header.ipProtocol,
            loopback,
            allowed,
            kind: kind.to_string(),
            filter_id,
            rule,
        };

        // A connection that never left the machine is dropped before it reaches anything: the log,
        // its counter, learning mode and the seen list are all fed from here, and a local agent
        // talking to a local server would otherwise fill the log with traffic nobody can decide on.
        // Dropped before the `observe` below, so it never becomes a Detected entry either.
        if !shown_in_feed(&entry, sink.debug_show_loopback) {
            return;
        }

        // Learning mode looks at the application behind the connection, not at the connection
        // itself, so the log gets a copy and the detector gets the original. With `learn_mode`
        // off the log still fills, because it is what the connection panel shows.
        sink.log.push(entry.clone());

        // The seen list grows whatever the settings say, because it is the set a wildcard rule is
        // expanded against, and the applications a rule already covers are exactly what a pattern
        // wants to match. Learning mode is only the list of undecided applications on top of it.
        let newly_seen = sink.detector.note_app(&entry.app);

        let ruleset = sink.rules.lock().expect("rules lock poisoned").clone();

        let detected = sink.live.learning() && sink.detector.observe(&entry, &ruleset);

        if (newly_seen || detected)
            && let Err(error) = sink.detector.save()
        {
            warn!(reason = %format!("{error:#}"), "could not write learn.json");
        }

        if !newly_seen {
            return;
        }

        // A wildcard rule is a set of exact filters, so an application that did not exist when
        // the rule was written cannot be matched by it. When one turns up and an enabled rule is
        // a pattern, the filters are rebuilt against every application seen so far.
        let pattern_in_use = ruleset
            .rule
            .iter()
            .any(|rule| rule.enabled && crate::rules::is_wildcard(&rule.pattern));

        let Some(rebuild) = &sink.rebuild else {
            return;
        };

        if !pattern_in_use {
            return;
        }

        let (reply, _reply) = sync_channel(1);
        let work = crate::server::StoreWork::Apply {
            rules: ruleset,
            known: sink.detector.apps(),
            policy: sink.live.policy(),
        };

        // A full queue means a rebuild is already on its way, and that rebuild reads the rules
        // and the seen list as they stand by then, so dropping this one loses nothing.
        match rebuild.try_send((work, reply)) {
            Ok(()) => info!(app = %entry.app, "new application, wildcard rebuild queued"),
            Err(error) => debug!(reason = %format!("{error:?}"), "wildcard rebuild not queued"),
        }
    }
}

/// The non-Windows monitor exists so the crate still builds for a doc tool.
#[cfg(not(windows))]
fn listen(
    _log: Arc<EventLog>,
    _detector: Arc<crate::learn::Detector>,
    _rules: Arc<Mutex<crate::rules::RuleFile>>,
    _live: Arc<crate::server::Live>,
    _rebuild: Option<SyncSender<crate::server::WorkItem>>,
    _owners: Arc<Mutex<Attribution>>,
    _debug_show_loopback: bool,
    shutdown: Receiver<()>,
) {
    let _ = shutdown.recv();
}

/// Which end of a connection a field of the event header belongs to.
///
/// Both ends live in the header, and reading one rather than the other is a mistake nothing would
/// catch later, so the readers that can serve either end take this instead of a boolean.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    Local,
    Remote,
}

/// One end of an event as an address in text form, empty when the event did not name one.
///
/// Each end lives in a union of its own selected by `ipVersion`, and the two arms are read
/// differently: the v4 arm is one `u32` holding the octets in the order WFP stores a filter
/// condition's address in, and the v6 arm is sixteen bytes in network order. A connectionless
/// event names no version at all, and then there is no address to report.
///
/// The header also says which ends it actually filled, and that marker is believed over the union
/// contents: an arm left alone still holds whatever the zeroed event put in it, which would read
/// as the perfectly plausible `0.0.0.0`.
#[cfg(windows)]
fn event_address(
    header: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER3,
    end: End,
) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
        FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    };

    let set_flag = match end {
        End::Local => FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
        End::Remote => FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    };

    if header.flags & set_flag != set_flag {
        return String::new();
    }

    if header.ipVersion == FWP_IP_VERSION_V4 {
        // The same conversion the store writes a filter condition with, so what the log shows and
        // what a rule matches are the same number read the same way.
        let raw = unsafe {
            match end {
                End::Local => header.Anonymous1.localAddrV4,
                End::Remote => header.Anonymous2.remoteAddrV4,
            }
        };

        Ipv4Addr::from(raw).to_string()
    } else if header.ipVersion == FWP_IP_VERSION_V6 {
        let bytes = unsafe {
            match end {
                End::Local => header.Anonymous1.localAddrV6,
                End::Remote => header.Anonymous2.remoteAddrV6,
            }
        };

        Ipv6Addr::from(bytes.byteArray16).to_string()
    } else {
        String::new()
    }
}

/// One end of an event as a port in host byte order, `0` when the event did not name one.
///
/// The port is a plain field rather than a union, but the header still says whether it was filled,
/// and a listener that has not bound yet is a real case where it was not.
#[cfg(windows)]
fn event_port(
    header: &windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_NET_EVENT_HEADER3,
    end: End,
) -> u16 {
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
    };

    let (set_flag, value) = match end {
        End::Local => (FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET, header.localPort),
        End::Remote => (FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, header.remotePort),
    };

    if header.flags & set_flag == set_flag {
        value
    } else {
        0
    }
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
            local_addr: String::new(),
            local_port: 49_152,
            remote_port: 443,
            remote_addr: String::new(),
            protocol: 6,
            loopback: false,
            local_network: false,
            allowed: true,
            kind: "allowed".to_owned(),
            filter_id: 0,
            rule: None,
        }
    }

    /// The same event with one end named, which is what decides whether it is shown.
    fn reaching(app: &str, remote_addr: &str) -> NetEvent {
        NetEvent {
            remote_addr: remote_addr.to_owned(),
            ..event(app)
        }
    }

    /// The two ends live in unions of their own, both selected by the version, and reading the
    /// wrong arm would print the peer's address where the local one belongs.
    #[cfg(windows)]
    #[test]
    fn each_end_is_read_out_of_the_union_the_version_selects() {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWP_BYTE_ARRAY16, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6,
            FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET as LOCAL_ADDR_SET,
            FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET as REMOTE_ADDR_SET, FWPM_NET_EVENT_HEADER3,
            FWPM_NET_EVENT_HEADER3_0, FWPM_NET_EVENT_HEADER3_1,
        };

        let mut header = FWPM_NET_EVENT_HEADER3 {
            ipVersion: FWP_IP_VERSION_V4,
            flags: LOCAL_ADDR_SET | REMOTE_ADDR_SET,
            Anonymous1: FWPM_NET_EVENT_HEADER3_0 {
                localAddrV4: u32::from_be_bytes([192, 168, 1, 12]),
            },
            Anonymous2: FWPM_NET_EVENT_HEADER3_1 {
                remoteAddrV4: u32::from_be_bytes([93, 184, 216, 34]),
            },
            ..FWPM_NET_EVENT_HEADER3::default()
        };

        assert_eq!(event_address(&header, End::Local), "192.168.1.12");
        assert_eq!(event_address(&header, End::Remote), "93.184.216.34");

        header.ipVersion = FWP_IP_VERSION_V6;
        header.Anonymous1.localAddrV6 = FWP_BYTE_ARRAY16 {
            byteArray16: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        header.Anonymous2.remoteAddrV6 = FWP_BYTE_ARRAY16 {
            byteArray16: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        assert_eq!(event_address(&header, End::Local), "2001:db8::2");
        assert_eq!(event_address(&header, End::Remote), "2001:db8::1");
    }

    /// A connection that stays on the machine must not reach the log: a local agent talking to a
    /// local server produces a stream of them, and the ring buffer exists for the connections a
    /// user could act on.
    #[cfg(windows)]
    #[test]
    fn a_connection_that_never_left_is_not_shown() {
        let marker = NetEvent {
            loopback: true,
            ..reaching("loopback.exe", "127.0.0.1")
        };

        assert!(stays_on_this_machine(&marker));
        assert!(!shown_in_feed(&marker, false), "off by default");
        assert!(
            shown_in_feed(&marker, true),
            "the debug switch keeps it for a diagnosis",
        );

        for address in ["127.0.0.1", "127.5.6.7", "::1"] {
            assert!(
                is_loopback_address(address),
                "{address} is a loopback address",
            );
            assert!(
                !shown_in_feed(&reaching("any.exe", address), false),
                "{address} is not a destination off this machine",
            );
        }
    }

    /// A LAN destination does leave the machine, so it is shown and only marked. Dropping it
    /// would hide the printer and the file server behind the very panel that exists to notice
    /// them.
    #[cfg(windows)]
    #[test]
    fn a_connection_to_the_local_network_is_shown_and_marked() {
        for address in [
            "10.1.2.3",
            "172.16.4.5",
            "172.31.254.253",
            "192.168.43.9",
            "169.254.11.22",
            "fe80::1",
            "fd12:3456::7",
        ] {
            assert!(
                is_local_network_address(address),
                "{address} is on the local segment",
            );
            assert!(
                shown_in_feed(&reaching("any.exe", address), false),
                "{address} leaves the machine",
            );
        }

        for address in ["172.15.0.1", "172.32.0.1", "168.192.1.1", "93.184.216.34"] {
            assert!(
                !is_local_network_address(address),
                "{address} is not on the local segment",
            );
        }
    }

    /// An event that names no remote end is not evidence of a local connection: the header simply
    /// did not fill the field, and treating that as loopback would quietly drop real traffic.
    #[cfg(windows)]
    #[test]
    fn an_event_without_a_remote_address_is_still_shown() {
        assert!(!is_loopback_address(""));
        assert!(!is_local_network_address(""));
        assert!(!stays_on_this_machine(&reaching("no-remote.exe", "")));
        assert!(shown_in_feed(&reaching("no-remote.exe", ""), false));
    }

    /// An address the event described in a form nothing can parse is treated as external rather
    /// than thrown away, because an unknown destination is still a destination.
    #[cfg(windows)]
    #[test]
    fn an_address_that_does_not_parse_is_not_called_local() {
        for address in ["not-an-address", "*", "10.0.0"] {
            assert!(!is_loopback_address(address), "{address}");
            assert!(!is_local_network_address(address), "{address}");
            assert!(
                shown_in_feed(&reaching("odd.exe", address), false),
                "{address}"
            );
        }
    }

    /// An address the header says it did not fill must read as absent rather than as the
    /// `0.0.0.0` a zeroed union would otherwise report.
    #[cfg(windows)]
    #[test]
    fn an_end_the_header_does_not_claim_has_no_address() {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWP_IP_VERSION_NONE, FWP_IP_VERSION_V4,
            FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET as REMOTE_ADDR_SET, FWPM_NET_EVENT_HEADER3,
            FWPM_NET_EVENT_HEADER3_1,
        };

        let mut header = FWPM_NET_EVENT_HEADER3 {
            ipVersion: FWP_IP_VERSION_V4,
            flags: REMOTE_ADDR_SET,
            Anonymous2: FWPM_NET_EVENT_HEADER3_1 {
                remoteAddrV4: u32::from_be_bytes([93, 184, 216, 34]),
            },
            ..FWPM_NET_EVENT_HEADER3::default()
        };

        assert_eq!(event_address(&header, End::Remote), "93.184.216.34");
        assert_eq!(
            event_address(&header, End::Local),
            "",
            "the local arm was never filled"
        );

        // A version that names no address family means no address, whatever the flags claim.
        header.ipVersion = FWP_IP_VERSION_NONE;

        assert_eq!(event_address(&header, End::Remote), "");
    }

    /// A port follows the same rule as an address: the header says whether it filled it, and a
    /// socket that has not bound yet is reported as `0` rather than as a bound port.
    #[cfg(windows)]
    #[test]
    fn a_port_is_only_reported_when_the_header_claims_it() {
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET as LOCAL_PORT_SET,
            FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET as REMOTE_PORT_SET, FWPM_NET_EVENT_HEADER3,
        };

        let mut header = FWPM_NET_EVENT_HEADER3 {
            localPort: 49_152,
            remotePort: 443,
            flags: LOCAL_PORT_SET | REMOTE_PORT_SET,
            ..FWPM_NET_EVENT_HEADER3::default()
        };

        assert_eq!(event_port(&header, End::Local), 49_152);
        assert_eq!(event_port(&header, End::Remote), 443);

        header.flags = REMOTE_PORT_SET;

        assert_eq!(event_port(&header, End::Remote), 443);
        assert_eq!(
            event_port(&header, End::Local),
            0,
            "the local port was never filled"
        );
    }

    /// The table answers for the ids it holds and for nothing else: a miss is how the monitor
    /// reads "a filter we did not install", and id `0` — the value for "no filter was named" —
    /// is never a key.
    #[test]
    fn the_attribution_table_names_only_the_ids_it_holds() {
        let mut table = Attribution::new();
        table.insert(42, "browser".to_owned());

        assert_eq!(table.get(&42).map(String::as_str), Some("browser"));
        assert_eq!(table.get(&7), None, "an id we did not install is a miss");
        assert_eq!(table.get(&0), None, "the sentinel id is never a key");
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

    /// The point of the status: a refused feed carries the code with it, because "refused" on its
    /// own is not something a reader can act on.
    #[test]
    fn a_refused_status_keeps_the_code_that_refused_it() {
        let status = MonitorStatus::refused(format!("{:#010x}", 5));

        assert_eq!(status.state, "refused");
        assert_eq!(status.code.as_deref(), Some("0x00000005"));

        let json = serde_json::to_value(&status).expect("serialize the status");

        assert_eq!(json["state"], "refused");
        assert_eq!(json["code"], "0x00000005");
    }

    /// A running feed has no code to report, and the page should not have to look for one.
    #[test]
    fn a_running_status_carries_no_code() {
        let json = serde_json::to_value(MonitorStatus::running()).expect("serialize the status");

        assert_eq!(json["state"], "running");
        assert!(json.get("code").is_none(), "nothing refused it: {json}");
    }

    /// Before the thread has reported anything the state reads `starting`, which is neither a live
    /// feed nor a failure.
    #[test]
    fn a_status_before_the_thread_reports_is_starting() {
        let status = MonitorStatus::default();

        assert_eq!(status.state, "starting");
        assert!(status.code.is_none());
    }

    /// The counter answers "did the feed ever deliver?", so it counts what arrived rather than what
    /// the capacity left in the log.
    #[test]
    fn delivered_counts_the_events_the_bound_dropped() {
        let log = EventLog::new();

        for index in 0..LOG_CAPACITY + 5 {
            log.push(event(&format!("app{index}.exe")));
        }

        assert_eq!(log.snapshot().len(), LOG_CAPACITY);
        assert_eq!(log.delivered(), (LOG_CAPACITY + 5) as u64);
    }
}
