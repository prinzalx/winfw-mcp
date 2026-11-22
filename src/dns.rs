//! The answers a name in a rule stood for the last time the filters were built.
//!
//! A rule can name its remote end by name (the `dest` field) as well as by address, but WFP
//! only ever matches an address, so a name is looked up before the filters go to the store. The
//! answers are worth keeping across a restart for one reason: under a default-deny policy the
//! lookup itself needs the network, and a machine that comes up without an answer for a name
//! would install a broader rule than the one written. With the last answers on disk the rule is
//! installed narrow again immediately, whether or not DNS answers this time.
//!
//! The resolver is injected wherever it matters, so the tests never send a query.

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::rules::{Remote, Remotes, Rule};

/// The name an address was queried as, or the name it resolves back to, or `None` when it has
/// neither. The answer is kept for the life of the process, refusals included: the page asks
/// once per address on every repaint of the connection list, and an address without a name
/// should cost no second query.
pub fn reverse(ip: std::net::IpAddr) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CACHE: Mutex<Option<HashMap<std::net::IpAddr, Option<String>>>> = Mutex::new(None);

    let mut guard = CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);

    if let Some(name) = cache.get(&ip) {
        return name.clone();
    }

    let name = client_cache_name(ip).or_else(|| reverse_lookup(ip));

    cache.insert(ip, name.clone());
    name
}

/// The system call behind [`reverse`]. `NI_NAMEREQD` keeps the answer honest: without it a
/// missing name record comes back as the address itself, printed rather than resolved.
#[cfg(windows)]
fn reverse_lookup(ip: std::net::IpAddr) -> Option<String> {
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NI_NAMEREQD, SOCKADDR,
        SOCKADDR_IN, SOCKADDR_IN6, WSADATA, WSAStartup, getnameinfo, socklen_t,
    };

    // Winsock wants to be introduced once per process; the WFP code does not need it, this does.
    static WINSOCK: std::sync::Once = std::sync::Once::new();

    WINSOCK.call_once(|| unsafe {
        let mut data = WSADATA::default();

        if WSAStartup(0x0202, &mut data) != 0 {
            warn!("winsock did not start, addresses will not be named");
        }
    });

    // The name a host answers with is ASCII in practice; 256 bytes hold any of them.
    let mut buffer = [0u8; 256];

    let found = match ip {
        std::net::IpAddr::V4(v4) => {
            let socket = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from(v4).to_be(),
                    },
                },
                ..Default::default()
            };

            unsafe {
                getnameinfo(
                    &socket as *const SOCKADDR_IN as *const SOCKADDR,
                    socklen_t(size_of::<SOCKADDR_IN>() as i32),
                    Some(&mut buffer),
                    None,
                    NI_NAMEREQD.try_into().unwrap_or(0),
                )
            }
        }
        std::net::IpAddr::V6(v6) => {
            let socket = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..Default::default()
            };

            unsafe {
                getnameinfo(
                    &socket as *const SOCKADDR_IN6 as *const SOCKADDR,
                    socklen_t(size_of::<SOCKADDR_IN6>() as i32),
                    Some(&mut buffer),
                    None,
                    NI_NAMEREQD.try_into().unwrap_or(0),
                )
            }
        }
    };

    if found != 0 {
        return None;
    }

    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let name = String::from_utf8_lossy(&buffer[..end]).into_owned();

    if name.is_empty() { None } else { Some(name) }
}

/// Off Windows there is no winsock to ask, and the tool does not run anywhere else.
#[cfg(not(windows))]
fn reverse_lookup(ip: std::net::IpAddr) -> Option<String> {
    let _ = ip;

    None
}

/// The forward name the DNS client cache holds for the address, which is the name the machine
/// actually asked for — the name a PTR record cannot recover behind a CNAME chain, and the one
/// that fills the gaps where no pointer record exists at all.
///
/// This is the technique the competitor does better than us, and it reads the same resolver
/// cache the competitor reads through `MSFT_DNSClientCache`. WMI is reached through the
/// dispatch locator because the plain `DnsGetCacheDataTable` of dnsapi answers null to a
/// non-elevated process, and the property read goes through `IDispatch` because the
/// `windows` crate metadata has no method for it. A machine whose WMI service does not answer
/// is not a failure: the caller still has [`reverse_lookup`].
#[cfg(windows)]
fn client_cache_name(ip: std::net::IpAddr) -> Option<String> {
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize, DISPATCH_PROPERTYGET, DISPPARAMS, IDispatch,
    };
    use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VariantClear};
    use windows::Win32::System::Wmi::ISWbemLocator;
    use windows::core::{BSTR, GUID, Interface, PCWSTR};

    // The locator coclass as machines register it under WbemScripting.SWbemLocator; the C++
    // CLSID_WbemLocator of the SDK headers is not registered (CLASSNOTREG), and the windows
    // crate names no constant for either.
    const WBEM_LOCATOR: GUID = GUID::from_u128(0x76a64158_cb41_11d1_8b02_00600806d9b6);

    // The crate metadata has no ISWbemObject::Get, and this object answers neither that name
    // nor a `Get_` method. It exposes every WQL-selected property as a dynamic dispatch
    // property instead: the name resolves on its own and one property get hands the value
    // back as a VARIANT holding the text as a BSTR.
    unsafe fn read_property(object: &IDispatch, what: &str) -> Option<String> {
        unsafe {
            let property_name = BSTR::from(what);
            let names = [PCWSTR(property_name.as_ptr())];
            let mut dispid = 0i32;

            if object
                .GetIDsOfNames(&GUID::zeroed(), names.as_ptr(), 1, 0x409, &mut dispid)
                .is_err()
            {
                return None;
            }

            let mut value = VARIANT::default();

            let called = object.Invoke(
                dispid,
                &GUID::zeroed(),
                0x409,
                DISPATCH_PROPERTYGET,
                &DISPPARAMS {
                    rgvarg: std::ptr::null_mut(),
                    rgdispidNamedArgs: std::ptr::null_mut(),
                    cArgs: 0,
                    cNamedArgs: 0,
                },
                Some(&raw mut value),
                None,
                None,
            );

            if called.is_err() {
                return None;
            }

            let text = if value.Anonymous.Anonymous.vt == VT_BSTR {
                value.Anonymous.Anonymous.Anonymous.bstrVal.to_string()
            } else {
                String::new()
            };

            let _ = VariantClear(&mut value);

            if text.is_empty() { None } else { Some(text) }
        }
    }

    // The request threads are not COM apartments yet. A thread some other part of the process
    // already initialized in another mode is used as it is, so only a thread that really
    // opened an apartment closes it again.
    let apartment = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

    let found = unsafe {
        let locator: ISWbemLocator =
            CoCreateInstance(&WBEM_LOCATOR, None, CLSCTX_INPROC_SERVER).ok()?;
        let services = locator
            .ConnectServer(
                // The DNS client cache class lives in StandardCimv2; a query against root\CIMV2
                // answers with WBEM_E_INVALID_CLASS on a machine where WMI itself is fine.
                &BSTR::new(),
                &BSTR::from("root\\StandardCimv2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                None,
            )
            .ok()?;

        // ExecQuery, Count and ItemIndex are plain members of these dispatch interfaces. The
        // query carries no WHERE clause on purpose: the legacy dispatcher hands the filter to
        // the provider, and this provider answers a filtered query with no rows at all, so
        // the address comparison runs here over the full enumeration.
        let rows = services
            .ExecQuery(
                &BSTR::from("SELECT Name,Data FROM MSFT_DNSClientCache"),
                &BSTR::from("WQL"),
                0,
                None,
            )
            .ok()?;

        let wanted = ip.to_string();
        let mut name = None;

        let total = rows.Count().unwrap_or(0);

        if cfg!(debug_assertions) {
            eprintln!("probe: total={total} wanted={wanted}");
        }

        for row in 0..total {
            let Ok(object) = rows.ItemIndex(row) else {
                continue;
            };
            let Ok(dispatch) = object.cast::<IDispatch>() else {
                continue;
            };

            let data = read_property(&dispatch, "Data");

            if cfg!(debug_assertions) && row < 40 {
                eprintln!("probe row {row}: data={data:?}");
            }

            if data.as_deref() == Some(wanted.as_str()) {
                name = read_property(&dispatch, "Name");
                break;
            }
        }

        name
    };

    if apartment.is_ok() {
        unsafe { CoUninitialize() };
    }

    found
}

/// Off Windows there is no DNS client cache to read, and the tool does not run anywhere else.
#[cfg(not(windows))]
fn client_cache_name(ip: std::net::IpAddr) -> Option<String> {
    let _ = ip;

    None
}

/// How many addresses one name is allowed to contribute. Twelve is the bound a real service
/// fits in — a browser resolving to twelve addresses is enough — because every address costs a
/// filter per application per layer.
const MAX_NAME_ADDRESSES: usize = 12;

/// How many values the merged remote condition of one rule holds in total, which is the bound
/// the address field of a rule is written with.
const MAX_VALUES: usize = 32;

/// How long an answer is used without asking again. Chosen to be long enough that a rebuild
/// caused by any other change does not query the network, and short enough that a rule written
/// after a server moved is narrowed by the next Apply after the answers are stale.
const MAX_AGE_SECS: u64 = 15 * 60;

/// The addresses a name had, how many the lookup had found before the cap, and the moment they
/// were read. The total is what lets the page tell a complete answer from a truncated one; a
/// file written before the field held counts nothing, which the next lookup corrects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    addresses: Vec<IpAddr>,
    /// How many addresses the lookup found, before [`truncate`] held the name down.
    #[serde(default)]
    total: usize,
    /// Seconds since the Unix epoch, as written in the file.
    at: u64,
}

/// The answers of this run, by lowercased name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answers {
    names: BTreeMap<String, Entry>,
}

impl Answers {
    /// The answers as they were read from disk, an empty set for a file that is not there yet.
    ///
    /// A file that cannot be read is reported as a warning rather than as an error: the answers
    /// are a convenience, and refusing to start over them would be worse than looking them up
    /// again.
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(text) => serde_json::from_slice(&text).unwrap_or_else(|err| {
                warn!("resolved.json is not readable ({err}), names are looked up again");
                Self::default()
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(err) => {
                warn!("resolved.json cannot be read ({err}), names are looked up again");
                Self::default()
            }
        }
    }

    /// Write the answers, leaving a file that cannot be written as a warning: the filters are
    /// already installed, which is the part that decides connections.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_vec_pretty(self).context("serialize resolved.json")?;

        std::fs::write(path, text)
            .with_context(|| format!("write {}", path.display()))
            .map_err(|err| {
                warn!("resolved.json cannot be written: {err:#}");
                err
            })
    }

    /// The addresses a name had, empty when nothing is known about it.
    pub fn addresses(&self, name: &str) -> &[IpAddr] {
        self.names
            .get(name)
            .map_or(&[] as &[IpAddr], |entry| entry.addresses.as_slice())
    }

    /// How many addresses the lookup had found for a name, before the cap.
    pub fn total(&self, name: &str) -> usize {
        self.names.get(name).map_or(0, |entry| entry.total)
    }

    /// Whether nothing at all is known.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The names a set of enabled rules names in its `dest` fields, without duplicates.
    pub fn wanted(rules: &crate::rules::RuleFile) -> Vec<String> {
        let mut names = Vec::new();

        for rule in rules.rule.iter().filter(|rule| rule.enabled) {
            let Some(dest) = rule.dest.as_ref() else {
                continue;
            };

            for name in dest.names() {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }

        names
    }

    /// Refresh the answers for `names`, keeping what [`lookup`] could not improve on.
    ///
    /// An answer younger than [`MAX_AGE_SECS`] is kept without asking, so a rebuild caused by an
    /// unrelated change costs no query. A name that fails to resolve keeps its previous answer,
    /// because a stale address is a better condition to install than none at all: the alternative
    /// is a rule that matches every address, which is the wider mistake.
    pub fn refresh<F>(&mut self, names: &[String], mut lookup: F) -> bool
    where
        F: FnMut(&str) -> Vec<IpAddr>,
    {
        let now = now_secs();
        let mut changed = false;

        for name in names {
            if let Some(entry) = self.names.get(name)
                && now.saturating_sub(entry.at) <= MAX_AGE_SECS
            {
                continue;
            }

            let found = lookup(name);

            if found.is_empty() {
                if self.names.contains_key(name) {
                    warn!("{name} did not resolve, the last answers are kept");
                } else {
                    warn!("{name} did not resolve, its rule matches no address for now");
                }

                continue;
            }

            let total = found.len();
            let addresses = truncate(name, found);

            if self.names.get(name).map(|entry| &entry.addresses) != Some(&addresses) {
                changed = true;
            }

            self.names.insert(
                name.clone(),
                Entry {
                    addresses,
                    total,
                    at: now,
                },
            );
        }

        changed
    }

    /// Drop what no enabled rule names any more, so the file does not collect names forever.
    pub fn retain(&mut self, names: &[String]) {
        self.names.retain(|name, _| names.contains(name));
    }

    /// An answer set built by hand, for the tests.
    #[cfg(test)]
    pub fn from_pairs(pairs: &[(&str, &[IpAddr])]) -> Self {
        let at = now_secs();

        Self {
            names: pairs
                .iter()
                .map(|(name, addresses)| {
                    (
                        (*name).to_string(),
                        Entry {
                            total: addresses.len(),
                            addresses: addresses.to_vec(),
                            at,
                        },
                    )
                })
                .collect(),
        }
    }
}

/// A rule whose `dest` names are replaced by the addresses they stood for, merged into the
/// remote condition.
///
/// `None` when the rule names no destination at all, which is the overwhelming majority of
/// them, so the caller keeps the rule it has. Resolving here rather than in the file is what
/// keeps a name readable in `rules.toml` and in the page while WFP is handed addresses, which
/// is all it can match.
///
/// The merged field is the union the rule asks for: the addresses written in `remote` plus the
/// answers of every name in `dest`, held to [`MAX_VALUES`] values over the whole field. A name
/// nothing has answered for contributes nothing, and a field left without elements offers no
/// layer of any family, so the rule is installed for no address at all. That is the narrow
/// direction: an allow for a name that will not resolve keeps the application blocked rather
/// than letting it reach the whole internet, and the log says so.
pub fn rule_with_answers(rule: &Rule, answers: &Answers) -> Option<Rule> {
    let dest = rule.dest.as_ref()?;

    let mut elements: Vec<Remote> = rule
        .remote
        .as_ref()
        .map_or_else(Vec::new, |field| field.elements().to_vec());

    for name in dest.names() {
        for address in answers.addresses(name) {
            if let Some(remote) = Remote::address(*address) {
                elements.push(remote);
            }
        }
    }

    if elements.len() > MAX_VALUES {
        warn!(
            "rule '{}' resolves to {} remote values, only {MAX_VALUES} are installed",
            rule.name,
            elements.len()
        );
        elements.truncate(MAX_VALUES);
    }

    let merged = Remotes::from_vec(elements);

    if rule.remote.as_ref() == Some(&merged) {
        return None;
    }

    let mut rule = rule.clone();

    rule.remote = Some(merged);
    rule.dest = None;

    Some(rule)
}

/// Hold a name down to the number of filters a field can spend on it, which is the same bound a
/// wildcard pattern spends on applications. What is installed is written to the log, because a
/// server behind a name with fifty addresses is a real situation.
fn truncate(name: &str, mut addresses: Vec<IpAddr>) -> Vec<IpAddr> {
    addresses.sort();

    if addresses.len() > MAX_NAME_ADDRESSES {
        warn!(
            "{name} resolves to {} addresses, only {MAX_NAME_ADDRESSES} are installed",
            addresses.len()
        );
        addresses.truncate(MAX_NAME_ADDRESSES);
    }

    addresses
}

/// The addresses of a name as the operating system answers, both families, without duplicates.
///
/// Port `0` is asked for because only the addresses matter; a service name would need a lookup of
/// its own and no rule writes one.
pub fn lookup(name: &str) -> Vec<IpAddr> {
    match (name, 0u16).to_socket_addrs() {
        Ok(addresses) => {
            let mut seen: Vec<IpAddr> = Vec::new();

            for address in addresses {
                let addr = address.ip();

                if !seen.contains(&addr) {
                    seen.push(addr);
                }
            }

            seen
        }
        Err(err) => {
            warn!("{name} cannot be resolved: {err}");
            Vec::new()
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Dests;

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_name_is_looked_up_once_and_kept_while_young() {
        let mut answers = Answers::default();
        let mut calls = 0;

        let changed = answers.refresh(&["example.com".to_string()], |name| {
            calls += 1;
            assert_eq!(name, "example.com");
            vec![addr("93.184.216.34")]
        });

        assert!(changed, "the first answer is a change");
        assert_eq!(calls, 1);

        let changed = answers.refresh(&["example.com".to_string()], |_| {
            calls += 1;
            vec![addr("1.2.3.4")]
        });

        assert!(!changed, "a young answer is kept without asking");
        assert_eq!(calls, 1);
        assert_eq!(answers.addresses("example.com"), [addr("93.184.216.34")]);
    }

    #[test]
    fn a_name_that_does_not_answer_keeps_its_last_addresses() {
        let mut answers = Answers::from_pairs(&[("old.example", &[addr("93.184.216.34")])]);

        // Age the answer past the window by hand, so the next refresh has to ask.
        answers.names.get_mut("old.example").expect("entry").at = 0;

        let changed = answers.refresh(&["old.example".to_string()], |_| Vec::new());

        assert!(!changed, "nothing changed, the stale answers stayed");
        assert_eq!(
            answers.addresses("old.example"),
            [addr("93.184.216.34")],
            "a failed lookup must not widen a rule by removing its only address"
        );
    }

    /// The answers of a name are merged behind the addresses of the field and the whole
    /// condition is held to the bound the field is written with; what is left of the name is
    /// gone from the rule, because WFP only ever sees the merge.
    #[test]
    fn a_destination_merges_answers_into_the_address_field() {
        let many: Vec<IpAddr> = (0..40).map(|n| addr(&format!("10.7.{n}.1"))).collect();
        let answers = Answers::from_pairs(&[("example.com", many.as_slice())]);
        let rule = Rule {
            remote: Some("10.0.0.0/24".parse::<Remotes>().expect("field")),
            dest: Some("example.com".parse::<Dests>().expect("name")),
            ..Rule::plain("merged", crate::rules::Action::Allow, "C:\\a.exe")
        };

        let resolved = rule_with_answers(&rule, &answers).expect("the rule names a destination");

        assert_eq!(
            resolved
                .remote
                .as_ref()
                .expect("merged field")
                .elements()
                .len(),
            MAX_VALUES,
            "the merged condition is held to the bound of the field"
        );
        assert_eq!(
            resolved.remote.as_ref().expect("merged field").elements()[0],
            rule.remote.as_ref().expect("field").elements()[0],
            "an address written next to a name keeps its place at the front"
        );
        assert_eq!(resolved.dest, None, "the answers replace the name");
    }

    #[test]
    fn a_destination_without_answers_offers_no_address() {
        let rule = Rule {
            dest: Some("example.com".parse::<Dests>().expect("name")),
            ..Rule::plain("unanswered", crate::rules::Action::Allow, "C:\\a.exe")
        };

        let resolved = rule_with_answers(&rule, &Answers::default())
            .expect("a destination is a destination with or without answers");

        assert!(
            resolved.remote.expect("merged field").elements().is_empty(),
            "nothing is known, so no address is claimed"
        );
    }

    #[test]
    fn a_rule_without_a_destination_is_returned_untouched() {
        let rule = Rule::plain("plain", crate::rules::Action::Allow, "C:\\a.exe");

        assert!(rule_with_answers(&rule, &Answers::default()).is_none());
    }

    #[test]
    fn a_name_is_held_to_its_own_cap_when_it_answers() {
        let mut answers = Answers::default();
        let many: Vec<IpAddr> = (0..40).map(|n| addr(&format!("10.9.{n}.1"))).collect();

        answers.refresh(&["many.example".to_string()], |_| many.clone());

        assert_eq!(answers.addresses("many.example").len(), MAX_NAME_ADDRESSES);
        assert_eq!(
            answers.total("many.example"),
            many.len(),
            "the answer says how many the lookup had found, so the page can say what was cut"
        );
    }

    #[test]
    fn the_file_survives_a_round_trip() {
        let dir = crate::testutil::scratch_dir("dns-round-trip");
        let file = dir.join("resolved.json");

        let answers = Answers::from_pairs(&[("example.com", &[addr("93.184.216.34")])]);
        answers.save(&file).expect("save");
        let back = Answers::load(&file);

        assert_eq!(back.addresses("example.com"), [addr("93.184.216.34")]);
    }

    #[test]
    fn a_missing_or_broken_file_is_no_answer_rather_than_a_failure() {
        let dir = crate::testutil::scratch_dir("dns-missing");
        assert!(Answers::load(&dir.join("nothing.json")).is_empty());

        std::fs::write(dir.join("broken.json"), "not json").expect("write");

        assert!(Answers::load(&dir.join("broken.json")).is_empty());
    }

    /// The client cache read runs against the live WMI service, which needs no elevation and
    /// no network. A reserved address no name ever resolved to must come back as none without
    /// panicking, which is the whole promise an offline test may make about a live query.
    #[cfg(windows)]
    #[test]
    fn the_client_cache_says_none_for_an_address_it_never_held() {
        let never = std::net::IpAddr::V4(std::net::Ipv4Addr::new(240, 0, 0, 1));

        assert_eq!(client_cache_name(never), None);
    }

    /// A name resolved by this process lands in the DNS client cache, so reading the cache by
    /// the address it answered with must name it back — which is exactly what the reverse page
    /// asks for and PTR cannot always answer. The row is not always there yet when the first
    /// answer arrives, and a resolver that rotates its cache can evict it again between two
    /// looks, so each attempt asks the resolver anew and reads right after it. Offline there
    /// is nothing to assert.
    #[cfg(windows)]
    #[test]
    fn the_client_cache_names_an_address_the_machine_resolved() {
        let mut found = None;
        let mut resolved = None;

        for _ in 0..20 {
            let addresses = lookup("github.com");

            if let Some(address) = addresses.first() {
                resolved = Some(*address);
                found = client_cache_name(*address);

                if found.is_some() {
                    break;
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let Some(address) = resolved else {
            return;
        };

        assert!(found.is_some(), "the cache should name {address}");
    }

    /// Names come from the `dest` field only, once each, and only from enabled rules.
    #[test]
    fn wanted_names_each_name_once() {
        let mut rules = crate::rules::RuleFile::default();

        rules.rule.push(crate::rules::Rule::plain(
            "one",
            crate::rules::Action::Allow,
            "C:\\a.exe",
        ));
        rules.rule[0].dest = "example.com, EXAMPLE.com".parse::<Dests>().ok();
        rules.rule.push(crate::rules::Rule::plain(
            "off",
            crate::rules::Action::Deny,
            "C:\\b.exe",
        ));
        rules.rule[1].dest = "disabled.example".parse::<Dests>().ok();
        rules.rule[1].enabled = false;

        assert_eq!(Answers::wanted(&rules), vec!["example.com".to_string()]);
    }
}
