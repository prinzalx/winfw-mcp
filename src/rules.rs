use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use tracing::warn;

use crate::store;
use crate::wfp::MAX_WILDCARD_MATCHES;

/// What WFP eventually does with a matching connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// The transport a rule is about.
///
/// Absent on a rule means every transport, which is what a rule was before this dimension existed.
/// The two names the rule file may hold are `tcp` and `udp`; anything else is written as the
/// protocol number, which is how a rule about GRE (47) or ESP (50) is expressed. A number is read
/// from either shape — `protocol = 47` and `protocol = "47"` mean the same rule — and is written
/// back as a number.
///
/// Zero is refused rather than treated as a protocol: a rule that wants every transport leaves the
/// field out, and `0` is what a caller who did not understand that would send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    /// A transport with no name of its own in this tool, named by its number.
    Other(u8),
}

impl Protocol {
    /// The IP protocol number WFP wants in a `FWPM_CONDITION_IP_PROTOCOL` condition.
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Other(number) => number,
        }
    }

    /// The name this protocol is written with, if it has one.
    const fn name(self) -> Option<&'static str> {
        match self {
            Self::Tcp => Some("tcp"),
            Self::Udp => Some("udp"),
            Self::Other(_) => None,
        }
    }

    /// Accept a number from either shape, which is what lets `47` and `"47"` mean one rule.
    fn from_number(number: u64) -> Option<Self> {
        match u8::try_from(number) {
            Ok(0) | Err(_) => None,
            Ok(number) => Some(Self::Other(number)),
        }
    }
}

impl Serialize for Protocol {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.name() {
            Some(name) => serializer.serialize_str(name),
            None => serializer.serialize_u8(self.number()),
        }
    }
}

impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Value;

        impl serde::de::Visitor<'_> for Value {
            type Value = Protocol;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("\"tcp\", \"udp\", or a protocol number from 1 to 255")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Protocol, E> {
                match text {
                    "tcp" => return Ok(Protocol::Tcp),
                    "udp" => return Ok(Protocol::Udp),
                    _ => {}
                }

                // A number that arrives inside a string is still the answer the user meant, and a
                // zero or an over-large one is refused exactly as the numeric form is.
                match text.parse::<u64>().ok().and_then(Protocol::from_number) {
                    Some(protocol) => Ok(protocol),
                    None => Err(E::invalid_value(
                        serde::de::Unexpected::Str(text),
                        &"\"tcp\", \"udp\", or a protocol number from 1 to 255",
                    )),
                }
            }

            fn visit_u64<E: serde::de::Error>(self, number: u64) -> Result<Protocol, E> {
                match Protocol::from_number(number) {
                    Some(protocol) => Ok(protocol),
                    None => Err(E::invalid_value(
                        serde::de::Unexpected::Unsigned(number),
                        &"a protocol number from 1 to 255",
                    )),
                }
            }

            /// TOML hands every integer over as signed, and serde's default for this one only
            /// names the type it did not expect.
            fn visit_i64<E: serde::de::Error>(self, number: i64) -> Result<Protocol, E> {
                match u64::try_from(number) {
                    Ok(number) => self.visit_u64(number),
                    Err(_) => Err(E::invalid_value(
                        serde::de::Unexpected::Signed(number),
                        &"a protocol number from 1 to 255",
                    )),
                }
            }
        }

        deserializer.deserialize_any(Value)
    }
}

/// Which way the connection goes for a rule to apply.
///
/// This decides the layers a rule is installed on: outbound is the ALE connect layer, inbound the
/// ALE recv-accept layer. Absent means both, as it did before the dimension existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// The address family an address belongs to.
///
/// WFP keeps the two families in separate layers, so this decides which of them a rule with an
/// address is installed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The width of an address of this family, which is the longest prefix it accepts.
    pub const fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

/// Read one address of either family into the sixteen bytes WFP is given, with the family that
/// decides which layers a rule about it goes on.
///
/// IPv4 is tried first, because Rust reads a dotted quad as an IPv4-mapped IPv6 address too, and
/// `10.0.0.5` should stay the four byte address the user typed.
fn parse_address(host: &str) -> Result<([u8; 16], Family), String> {
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        let mut addr = [0u8; 16];

        addr[..4].copy_from_slice(&v4.octets());

        Ok((addr, Family::V4))
    } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        Ok((v6.octets(), Family::V6))
    } else {
        Err(format!("'{host}' is not an IP address"))
    }
}

/// A remote address, written `192.168.1.0/24`, `10.0.0.5` or `fe80::/10`.
///
/// A bare address is a prefix as wide as its family, so `10.0.0.5` means `10.0.0.5/32` and
/// `fe80::1` means `fe80::1/128`. Host bits are masked away while the text is read, so what ends
/// up in the file is exactly the network WFP will match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    /// The network address: four significant bytes for v4, sixteen for v6.
    pub addr: [u8; 16],
    /// How many leading bits of `addr` have to match.
    pub prefix: u8,
    /// Which family the address is in.
    pub family: Family,
}

impl Cidr {
    /// The four bytes of a v4 address, which is how WFP wants them in a v4 condition.
    pub fn v4_bytes(&self) -> [u8; 4] {
        [self.addr[0], self.addr[1], self.addr[2], self.addr[3]]
    }

    /// Whether this network contains an address.
    ///
    /// The families never match across: an IPv4 network cannot contain an IPv6 address, which is
    /// the same rule the layers follow.
    pub fn contains(&self, addr: std::net::IpAddr) -> bool {
        // Both sides go into a `u128` *left-aligned*, because a prefix counts from the top: the
        // four bytes of a v4 address have to occupy the top of the number, not its bottom.
        let (network, other) = match (self.family, addr) {
            (Family::V4, std::net::IpAddr::V4(v4)) => (
                u128::from(u32::from_be_bytes(self.v4_bytes())) << 96,
                u128::from(u32::from(v4)) << 96,
            ),
            (Family::V6, std::net::IpAddr::V6(v6)) => {
                (u128::from_be_bytes(self.addr), u128::from(v6))
            }
            _ => return false,
        };

        prefix_covers(network, other, self.prefix)
    }

    /// The v4 mask WFP wants beside the address: the prefix widened to 32 bits, read big-endian
    /// like the address itself. `/0` masks everything away, which matches any address.
    pub fn v4_mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (Family::V4.bits() - self.prefix)
        }
    }
}

impl std::str::FromStr for Cidr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (host, given) = match text.split_once('/') {
            Some((host, prefix)) => (
                host,
                Some(
                    prefix
                        .parse::<u8>()
                        .map_err(|_| format!("'{prefix}' is not a prefix length"))?,
                ),
            ),
            None => (text, None),
        };

        let (addr, family) = parse_address(host)?;

        let prefix = given.unwrap_or_else(|| family.bits());

        if prefix > family.bits() {
            return Err(format!(
                "'{text}' has a prefix longer than {}",
                family.bits()
            ));
        }

        // Keep only the network part, so `10.0.0.5/24` is stored and shown as `10.0.0.0/24`.
        let mut addr = addr;
        for (index, byte) in addr.iter_mut().enumerate() {
            let keep = prefix.saturating_sub(8 * index as u8);

            *byte &= if keep >= 8 {
                0xff
            } else if keep == 0 {
                0
            } else {
                0xffu8 << (8 - keep)
            };
        }

        Ok(Self {
            addr,
            prefix,
            family,
        })
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.family {
            Family::V4 => write!(f, "{}", std::net::Ipv4Addr::from(self.v4_bytes()))?,
            Family::V6 => write!(f, "{}", std::net::Ipv6Addr::from(self.addr))?,
        }

        if self.prefix == self.family.bits() {
            Ok(())
        } else {
            write!(f, "/{}", self.prefix)
        }
    }
}

impl Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
}

/// An inclusive span between two addresses of one family, written `10.0.0.1-10.0.0.9`.
///
/// A prefix cannot express that span: `/24` would also cover `10.0.0.0` and `10.0.0.255`. The
/// reference covers the case with a range of the same shape (`wfp.c`), and WFP keeps it as a
/// `FWP_RANGE_TYPE` rather than an address and mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    /// The first address of the span.
    pub from: [u8; 16],
    /// The last address of the span, inclusive.
    pub to: [u8; 16],
    /// Which family both ends are in.
    pub family: Family,
}

/// What a rule names as its remote destination or its local address: one address, a network, or a
/// span between two addresses. All three are written as text in the file, in JSON and in a share
/// string; a range is told from the other two by the `-` between its ends, which no address text
/// contains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    /// One address or a network, written `10.0.0.5` or `10.0.0.0/24`.
    Network(Cidr),
    /// A span between two addresses, written `10.0.0.1-10.0.0.9`.
    Span(AddressRange),
}

impl Remote {
    /// The family the destination belongs to, which decides the layers a rule is installed on.
    pub const fn family(self) -> Family {
        match self {
            Self::Network(cidr) => cidr.family,
            Self::Span(range) => range.family,
        }
    }

    /// Whether an address is one the rule speaks about.
    pub fn contains(self, addr: std::net::IpAddr) -> bool {
        match self {
            Self::Network(cidr) => cidr.contains(addr),
            Self::Span(range) => {
                // The address goes into the same sixteen byte layout a stored end uses, so the
                // comparison below needs no knowledge of the family it is reading.
                let (other, family) = match addr {
                    std::net::IpAddr::V4(v4) => {
                        let mut bytes = [0u8; 16];

                        bytes[..4].copy_from_slice(&v4.octets());

                        (bytes, Family::V4)
                    }
                    std::net::IpAddr::V6(v6) => (v6.octets(), Family::V6),
                };

                if family != range.family {
                    return false;
                }

                // Both ends and the address are held in the same sixteen byte layout, so an
                // ordinary byte comparison is the numeric comparison the span asks for.
                other >= range.from && other <= range.to
            }
        }
    }
}

impl std::str::FromStr for Remote {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let Some((low, high)) = text.split_once('-') else {
            return text.parse::<Cidr>().map(Self::Network);
        };

        if low.is_empty() || high.is_empty() {
            return Err(format!("'{text}' is not an address range"));
        }

        let (from, family) = parse_address(low)?;
        let (to, high_family) = parse_address(high)?;

        if family != high_family {
            return Err(format!(
                "'{text}' spans two address families, which no rule can match"
            ));
        }

        // A span the other way round matches nothing, and a rule that matches nothing is almost
        // always a typo rather than a wish, so it is refused where the text is read.
        if from > to {
            return Err(format!("'{text}' ends before it starts"));
        }

        Ok(Self::Span(AddressRange { from, to, family }))
    }
}

impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(cidr) => write!(f, "{cidr}"),
            Self::Span(range) => match range.family {
                Family::V4 => write!(
                    f,
                    "{}-{}",
                    std::net::Ipv4Addr::from([
                        range.from[0],
                        range.from[1],
                        range.from[2],
                        range.from[3]
                    ]),
                    std::net::Ipv4Addr::from([range.to[0], range.to[1], range.to[2], range.to[3]]),
                ),
                Family::V6 => write!(
                    f,
                    "{}-{}",
                    std::net::Ipv6Addr::from(range.from),
                    std::net::Ipv6Addr::from(range.to),
                ),
            },
        }
    }
}

impl Serialize for Remote {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Remote {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The port field of a rule: one port, one inclusive range, or a comma-separated list of
/// them such as `80, 443, 8080-8090`.
///
/// It holds at least one element; a field that names no port at all is absent rather than an
/// empty list. The elements are written back joined by commas, so a single value stays a single
/// value and a list comes back as a list. The list is capped at [`MAX_WILDCARD_MATCHES`]
/// elements: each element is installed as a filter of its own per application per layer, and
/// the store is shared with everything else on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports(Vec<PortRange>);

impl Ports {
    /// The elements of the field, in the order they were written.
    pub fn elements(&self) -> &[PortRange] {
        &self.0
    }
}

/// The contents of the port field of a rule, split into validated elements.
impl std::str::FromStr for Ports {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.trim().is_empty() {
            return Err(format!("port '{text}' is not a port"));
        }

        let mut elements = Vec::new();

        for part in text.split(',') {
            let part = part.trim();

            if part.is_empty() {
                return Err(format!("port list '{text}' has an empty element"));
            }

            let (lo, hi) = match part.split_once('-') {
                Some((lo, hi)) => (
                    lo.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("port '{part}' is not a port"))?,
                    hi.trim()
                        .parse::<u16>()
                        .map_err(|_| format!("port '{part}' is not a port"))?,
                ),
                None => (
                    part.parse::<u16>()
                        .map_err(|_| format!("port '{part}' is not a port"))?,
                    part.parse::<u16>()
                        .map_err(|_| format!("port '{part}' is not a port"))?,
                ),
            };

            if lo > hi {
                return Err(format!("port range '{part}' runs backwards"));
            }

            if lo == 0 || hi == 0 {
                return Err(format!("port '{part}' is not a port"));
            }

            elements.push(PortRange { lo, hi });
        }

        if elements.len() > MAX_WILDCARD_MATCHES {
            return Err(format!(
                "port list '{text}' names more than {MAX_WILDCARD_MATCHES} ports"
            ));
        }

        Ok(Self(elements))
    }
}

impl std::fmt::Display for Ports {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let joined = self
            .0
            .iter()
            .map(|element| element.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        f.write_str(&joined)
    }
}

impl Serialize for Ports {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A port, or an inclusive range of them, written `443` or `1024-2048`.
///
/// It is a string in the file and in JSON rather than a number, because a range has no number form
/// and because a port is read as text far more often than it is computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    /// Whether the range names one port, which is how WFP is told about it.
    pub const fn is_single(&self) -> bool {
        self.lo == self.hi
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_single() {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// The error text a bad port answers with, which becomes a serde message and a web error.
type ParseError = String;

impl std::str::FromStr for PortRange {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let parse = |part: &str| {
            part.trim()
                .parse::<u16>()
                .map_err(|_| format!("'{part}' is not a port"))
        };

        let (lo, hi) = match text.split_once('-') {
            Some((lo, hi)) => (parse(lo)?, parse(hi)?),
            None => (parse(text)?, parse(text)?),
        };

        if lo > hi {
            return Err(format!("port range '{text}' runs backwards"));
        }

        Ok(Self { lo, hi })
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;

        text.parse().map_err(serde::de::Error::custom)
    }
}

/// A single user rule.
///
/// `pattern` may contain the wildcards `*` and `?` (PLAN.md section 4). Matching is our job,
/// not the kernel's, so the string is stored exactly as the user typed it.
///
/// `protocol`, `direction`, `port`, `remote` and `local` narrow the rule and are absent when it is
/// about all of them. They are skipped when written out, so a rule that does not use them is
/// stored exactly as
/// it was before they existed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    pub action: Action,
    pub pattern: String,
    #[serde(default = "always_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Ports>,
    /// The remote address the rule is about, written `192.168.1.0/24`, `10.0.0.5` or
    /// `10.0.0.1-10.0.0.9`. Absent means any address, which is also what narrows the rule to the
    /// application alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<Remote>,
    /// The local address the rule is about, written `192.168.1.0/24`, `10.0.0.5` or
    /// `10.0.0.1-10.0.0.9`. Absent means any address, which is also what leaves the rule about the
    /// destination alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local: Option<Remote>,
    /// Why the rule exists, in the words of the person who wrote it.
    ///
    /// It decides nothing: the field is for the reader of a list they did not write. It is skipped
    /// when absent, so a rules file that never uses it is written exactly as it was before the
    /// field existed. The reference has the same field on its rules (`ITEM_RULE`, `main.h`), and
    /// like there it is never sent to the store: a filter is what a rule became, and a wildcard rule
    /// that expands to a dozen filters would repeat the sentence a dozen times.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

const fn always_enabled() -> bool {
    true
}

impl Rule {
    /// A rule that narrows nothing: an enabled rule about an application, with no protocol,
    /// direction, port, remote address or local address. This is what a detected application and an
    /// MCP agent turn into.
    pub fn plain(name: impl Into<String>, action: Action, pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            action,
            pattern: pattern.into(),
            enabled: true,
            protocol: None,
            direction: None,
            port: None,
            remote: None,
            local: None,
            comment: None,
        }
    }
}

/// The characters that make a pattern a wildcard pattern.
const WILDCARD_STAR: char = '*';
const WILDCARD_ANY: char = '?';

/// Refuse a pattern that cannot name a path.
///
/// The reference checks a path the user typed against the shape of a drive path
/// (`_app_isappvalidpath`, `helper.c:574`) and refuses anything else. Doing without that check
/// means a typo is not an error but a rule that silently matches nothing, which is worse for a
/// firewall than for most programs: the connection it was supposed to decide goes the other way.
///
/// A rule may be rooted at a drive (`C:\...`) or at a single separator, because a device path the
/// drive map did not resolve arrives as `\Device\HarddiskVolume3\...`.
pub fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.trim().is_empty() {
        bail!("a rule needs a pattern");
    }

    if pattern.chars().any(char::is_control) {
        bail!("a pattern cannot contain a control character");
    }

    if pattern.contains(['"', '<', '>', '|']) {
        bail!("a pattern cannot contain the characters \" < > |");
    }

    let bytes = pattern.as_bytes();
    let drive_rooted =
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';

    if !drive_rooted && bytes[0] != b'\\' {
        bail!("a pattern must be an absolute path such as C:\\Windows\\*.exe");
    }

    Ok(())
}

/// The longest comment a rule accepts.
///
/// The reference keeps its comments in a fixed buffer, so a longer one is simply cut off there.
/// Refusing is kinder than cutting: the person who typed it finds out at once, and the file never
/// holds a sentence that lost its ending.
pub const COMMENT_LIMIT: usize = 200;

/// Refuse a comment that would not read back the way it was meant.
///
/// A comment is the one field a person pastes rather than types, and pasted text brings control
/// characters with it. TOML would escape a newline and read it back happily, but a rule that spans
/// three lines in a file the user is expected to scan is not worth what it looks like in an editor.
pub fn validate_comment(comment: &str) -> Result<()> {
    if comment.chars().any(char::is_control) {
        bail!("a comment cannot contain a control character");
    }

    if comment.chars().count() > COMMENT_LIMIT {
        bail!("a comment cannot be longer than {COMMENT_LIMIT} characters");
    }

    Ok(())
}

/// Whether a pattern needs matching at all, rather than being an exact path.
pub fn is_wildcard(pattern: &str) -> bool {
    pattern.contains([WILDCARD_STAR, WILDCARD_ANY])
}

/// Match a pattern against text with `*` and `?` placeholders.
///
/// Comparison is case-insensitive, because Windows paths are. Unlike a shell glob, `*` is not
/// stopped by a path separator: a rule about `C:\Windows\*` is meant to cover everything below
/// that directory, separators included, which is the reading PLAN.md section 4 promises.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.to_lowercase().chars().collect();
    let text: Vec<char> = text.to_lowercase().chars().collect();

    // The usual two-pointer match with a single remembered star: `star` is the index of the last
    // star in the pattern, and `given` how much of the text that star has swallowed so far.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut given) = (None, 0usize);

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == WILDCARD_ANY || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == WILDCARD_STAR {
            star = Some(p);
            p += 1;
            given = t;
        } else if let Some(at) = star {
            // The star has to swallow one more character; whatever follows it starts over.
            given += 1;
            t = given;
            p = at + 1;
        } else {
            return false;
        }
    }

    // Whatever is left of the pattern has to be stars matching nothing.
    pattern[p..].iter().all(|&c| c == WILDCARD_STAR)
}

/// Whether one prefix covers an address.
///
/// Both sides are read big-endian, which is the order the octets are written in, so one mask works
/// for either family. `/0` covers everything.
fn prefix_covers(network: u128, addr: u128, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }

    let mask = u128::MAX << (128 - u128::from(prefix));

    network & mask == addr & mask
}

/// Whether any enabled rule covers this path.
///
/// This is the question learning mode asks before showing an application as detected: a
/// connection a rule already speaks about is not new, whatever the store decided to do with it.
pub fn covered_by(rules: &RuleFile, path: &str) -> bool {
    rules
        .rule
        .iter()
        .filter(|rule| rule.enabled)
        .any(|rule| wildcard_match(&rule.pattern, path))
}

/// Whether the destination of an application a rule covers is decided as well.
///
/// A rule that names no destination reaches every address, and a rule that names one has to
/// contain it. A destination no enabled rule of this application contains is new even when the
/// application itself is not, which is what learning mode asks next.
pub fn reaches(rules: &RuleFile, path: &str, addr: std::net::IpAddr) -> bool {
    rules
        .rule
        .iter()
        .filter(|rule| rule.enabled && wildcard_match(&rule.pattern, path))
        .any(|rule| match rule.remote {
            Some(remote) => remote.contains(addr),
            None => true,
        })
}

/// The contents of `rules.toml`. Order is significant: the first matching rule wins, which is
/// why an import has to preserve it (PLAN.md section 2).
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

impl RuleFile {
    /// The two rules a first run writes into `rules.toml`.
    ///
    /// An empty file is a correct default and a poor first screen: nothing on it shows what a rule
    /// is supposed to look like. These two are the shape of the common case - one application
    /// allowed to one network, one denied - and they are deliberately the same pair the manual
    /// talks about. The paths name `C:\test\`, which a normal machine does not have, so a rule
    /// teaches without blocking anything a real program does, and the prefixes are the
    /// documentation ranges of RFC 5737, which no host of this network is ever in.
    pub fn examples() -> Self {
        let mut allow = Rule::plain("example allow", Action::Allow, "C:\\test\\tool1.exe");
        allow.remote = Some(
            "192.0.2.0/24"
                .parse()
                .expect("the example prefix is a literal"),
        );
        allow.comment = Some("the allow shape: this app may reach this network".to_owned());

        let mut deny = Rule::plain("example deny", Action::Deny, "C:\\test\\tool2.exe");
        deny.remote = Some(
            "198.51.100.0/24"
                .parse()
                .expect("the example prefix is a literal"),
        );
        deny.comment = Some("the deny shape: this app may not".to_owned());

        Self {
            rule: vec![allow, deny],
        }
    }
}

/// The version written to a rule file.
///
/// The reference keeps a schema version in its profile files and migrates when it reads an older
/// one. We only ever need to notice the opposite case, because a file with a field we do not know
/// is refused outright: the version turns that refusal into a message that names the versions.
pub const RULE_FILE_VERSION: u32 = 1;

/// What `rules.toml` holds: the version, the checksum of the body, and the rules.
///
/// The version and the checksum are deliberately not fields of [`RuleFile`], which is built by hand
/// in a dozen places and would have to carry two things none of them cares about.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFileDisk {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    rule: Vec<Rule>,
}

/// The checksum a rule file carries over its own body.
///
/// The reference ends its files with a hash of the body, which catches a file that still parses but
/// lost content on the way to disk. This is the same idea with the FNV-1a hash [`Fingerprint`]
/// already uses, because the goal is to notice an accident rather than to withstand an attacker,
/// and the security chapter says that out loud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksum {
    /// What the file named, or `None` when it named nothing.
    stated: Option<String>,
    /// What the rules the file holds hash to.
    actual: String,
}

impl Checksum {
    /// Whether the file and its contents disagree.
    ///
    /// A file that names no checksum disagrees as well, which is the honest answer: an older build
    /// wrote no such line, and a person who deletes it has the same effect.
    fn mismatched(&self) -> bool {
        self.stated.as_deref() != Some(self.actual.as_str())
    }
}

/// The body of a rule file: the rules alone, without the version and without the checksum.
///
/// Serialising the rules rather than cutting the text at the first table keeps the bytes that go
/// into the hash the same on both sides of a round trip, which is the whole point of the field.
fn body_text(rule: &[Rule]) -> Result<String> {
    toml::to_string_pretty(&RuleFile {
        rule: rule.to_vec(),
    })
    .context("serialize the rule body")
}

/// The text a rule file is written as.
///
/// The two scalars come first because TOML would otherwise read them as keys of the last `[[rule]]`
/// table, and `Rule` refuses a field it does not know.
fn file_text(rule: &[Rule]) -> Result<String> {
    let body = body_text(rule)?;
    let sum = Fingerprint::of(body.as_bytes()).hash;

    Ok(format!(
        "version = {RULE_FILE_VERSION}\nchecksum = \"{sum:016x}\"\n{body}"
    ))
}

/// Read one file's bytes, refusing a version this build cannot know.
///
/// A checksum that does not match is not refused here. A hand edit changes it, and a rules file a
/// person edited is an ordinary thing, so the caller is handed both values and decides how loudly to
/// say so.
fn parse_rule_file(bytes: &[u8]) -> std::result::Result<(RuleFile, Checksum), toml::de::Error> {
    use serde::de::Error as _;

    let disk = toml::from_slice::<RuleFileDisk>(bytes)?;

    if disk.version > RULE_FILE_VERSION {
        return Err(toml::de::Error::custom(format!(
            "rule file version {} is newer than {}",
            disk.version, RULE_FILE_VERSION
        )));
    }

    let body = body_text(&disk.rule)
        .map_err(|error| toml::de::Error::custom(format!("checksum of the rule body: {error}")))?;

    Ok((
        RuleFile { rule: disk.rule },
        Checksum {
            stated: disk.checksum,
            actual: format!("{:016x}", Fingerprint::of(body.as_bytes()).hash),
        },
    ))
}

impl RuleFile {
    /// Load the rules, creating an empty file when there is none yet.
    ///
    /// A file that cannot be read is not the end of it: the previous generation written by
    /// [`RuleFile::save`] is tried before the error is reported, which is what makes a torn or
    /// mistyped write survivable. Falling back is logged rather than silent, because the file on
    /// disk still holds what could not be read.
    ///
    /// A file that reads but whose checksum disagrees with its contents is read anyway and warned
    /// about, because the disagreement has the same cause as a hand edit and the same cure.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let Some(bytes) = store::read_if_exists(path)? else {
            let rules = Self::default();
            rules.save(path)?;

            return Ok(rules);
        };

        match parse_rule_file(&bytes) {
            Ok((rules, checksum)) => {
                warn_checksum(path, &checksum);

                Ok(rules)
            }
            Err(error) => {
                let backup = store::backup_path(path);
                let Some(back_bytes) = store::read_if_exists(&backup)? else {
                    return Err(error).with_context(|| format!("parse {}", path.display()));
                };

                let rules = parse_rule_file(&back_bytes)
                    .map(|(rules, _checksum)| rules)
                    .with_context(|| {
                        format!(
                            "parse {} after {} failed: {error}",
                            backup.display(),
                            path.display()
                        )
                    })?;

                warn!(
                    backup = %backup.display(),
                    file = %path.display(),
                    "rules file unreadable, read the backup instead",
                );

                Ok(rules)
            }
        }
    }

    /// Read a whole rule file from text, which is what an import hands over rather than a path.
    ///
    /// This is the same reader [`RuleFile::load_or_create`] uses for the file on disk, so a body
    /// that would fail to start the tool fails an import too: the version, the field names and the
    /// values a rule cannot hold are refused before anything is written.
    pub fn from_text(text: &str) -> Result<Self> {
        let (rules, checksum) =
            parse_rule_file(text.as_bytes()).context("parse the imported rules")?;

        if checksum.mismatched() {
            warn!(
                stated = checksum.stated.as_deref().unwrap_or("none"),
                found = %checksum.actual,
                "imported rules file checksum does not match its contents",
            );
        }

        Ok(rules)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        store::write_backup(path, file_text(&self.rule)?.as_bytes())
    }
}

/// Say so when a file on disk does not hash to what it claims.
fn warn_checksum(path: &Path, checksum: &Checksum) {
    if checksum.mismatched() {
        warn!(
            file = %path.display(),
            stated = checksum.stated.as_deref().unwrap_or("none"),
            found = %checksum.actual,
            "rules file checksum does not match its contents",
        );
    }
}

/// A cheap fingerprint of the contents of a rules file.
///
/// It answers one question: is this still the file the tool wrote, or did something else change
/// it? A length plus an FNV-1a hash answers that without a hashing dependency. The case it does
/// not cover is an attacker deliberately hunting for a collision, which the security chapter says
/// out loud rather than pretending otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// Bytes in the file.
    len: u64,
    /// FNV-1a over those bytes.
    hash: u64,
}

impl Fingerprint {
    /// The fingerprint of bytes exactly as they are on disk.
    fn of(bytes: &[u8]) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;

        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }

        Self {
            len: bytes.len() as u64,
            hash,
        }
    }

    /// Read a file and fingerprint it. `None` means the file is not there, which is a state of its
    /// own rather than an empty file.
    pub fn of_file(path: &Path) -> Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(Self::of(&bytes))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => {
                Err(anyhow::Error::new(error).context(format!("read {}", path.display())))
            }
        }
    }
}

/// The stamp file that belongs to a rules file: `rules.toml` gets `rules.toml.stamp`.
///
/// Living next to the file it describes means a profile needs no bookkeeping of its own, and it
/// follows the `.bak` pattern [`RuleFile::save`] already uses.
pub fn stamp_path(rules_file: &Path) -> PathBuf {
    PathBuf::from(format!("{}.stamp", rules_file.display()))
}

/// Record what the tool just wrote, so the next start can tell its own work from an outside edit.
///
/// A stamp that cannot be written is reported and tolerated: the worst case is that a later change
/// goes unnoticed, which is what every version before this one did all the time.
pub fn write_stamp(rules_file: &Path, fingerprint: Option<Fingerprint>) {
    let path = stamp_path(rules_file);

    let result = match fingerprint {
        Some(fingerprint) => std::fs::write(
            &path,
            format!("{:x}:{:x}\n", fingerprint.len, fingerprint.hash),
        ),
        None => std::fs::remove_file(&path),
    };

    if let Err(error) = result {
        warn!(
            file = %path.display(),
            reason = %error,
            "could not record the rules file fingerprint",
        );
    }
}

/// Read the stamp the tool left behind. `None` covers both no stamp and an unreadable one,
/// because neither can be compared against.
pub fn read_stamp(rules_file: &Path) -> Option<Fingerprint> {
    let text = std::fs::read_to_string(stamp_path(rules_file)).ok()?;
    let (len, hash) = text.trim().split_once(':')?;

    Some(Fingerprint {
        len: u64::from_str_radix(len, 16).ok()?,
        hash: u64::from_str_radix(hash, 16).ok()?,
    })
}

/// A profile name is the stem of one file in `profiles\`: a single component, no separators.
///
/// The empty name is not a profile at all — it means `rules.toml` itself — so it is rejected here;
/// the caller decides what empty means before asking.
pub fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', ':'])
}

/// The names of the profiles stored in `dir`, sorted, without the `.toml` suffix.
///
/// A directory that does not exist or cannot be read simply has no profiles, which is what a
/// fresh install looks like.
pub fn list_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
            {
                return None;
            }

            Some(path.file_stem()?.to_str()?.to_owned())
        })
        .collect();

    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RuleFile {
        RuleFile {
            rule: vec![
                Rule::plain(
                    "browser",
                    Action::Allow,
                    "C:\\Program Files\\*\\browser.exe",
                ),
                Rule {
                    enabled: false,
                    ..Rule::plain("telemetry", Action::Deny, "C:\\Tools\\agent?.exe")
                },
            ],
        }
    }

    #[test]
    fn rules_survive_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("rules").join("rules.toml");
        let rules = sample();

        rules.save(&path).expect("save");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn the_examples_are_one_allow_and_one_deny() {
        let examples = RuleFile::examples();

        assert_eq!(examples.rule.len(), 2);
        assert_eq!(examples.rule[0].action, Action::Allow);
        assert_eq!(examples.rule[1].action, Action::Deny);

        // Both are on, or neither teaches anything.
        assert!(examples.rule.iter().all(|rule| rule.enabled));

        // Each names one application and one network, which is the shape the manual describes.
        for rule in &examples.rule {
            assert!(rule.pattern.contains("C:\\test\\tool"));
            assert!(rule.remote.is_some());
        }
    }

    #[test]
    fn the_examples_survive_a_round_trip_through_disk() {
        let path = crate::testutil::scratch_dir("examples").join("rules.toml");
        let examples = RuleFile::examples();

        examples.save(&path).expect("save");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), examples);
    }

    #[test]
    fn a_star_matches_across_separators() {
        assert!(wildcard_match(
            "C:\\Windows\\*",
            "C:\\Windows\\System32\\a.exe"
        ));
    }

    #[test]
    fn a_question_mark_matches_exactly_one_character() {
        assert!(wildcard_match("C:\\a?.exe", "C:\\ab.exe"));
        assert!(!wildcard_match("C:\\a?.exe", "C:\\abc.exe"));
    }

    #[test]
    fn matching_ignores_case_because_windows_paths_do() {
        assert!(wildcard_match(
            "c:\\WINDows\\SUB\\*.EXE",
            "C:\\windows\\sub\\x\\a.exe"
        ));
    }

    #[test]
    fn a_pattern_must_cover_the_whole_text() {
        assert!(!wildcard_match("C:\\Windows\\*", "C:\\Windows"));
        assert!(wildcard_match("*", "anything"));
        assert!(!wildcard_match("*x", "anything"));
    }

    /// A prefix is the whole difference between `10.0.0.5` and `10.0.0.0/24`, and the families
    /// never match across: a v4 network does not contain a v6 address.
    #[test]
    fn a_prefix_contains_the_addresses_inside_it() {
        let network: Cidr = "10.0.0.0/24".parse().expect("parse a network");
        let host: Cidr = "10.0.0.5".parse().expect("parse an address");
        let six: Cidr = "2001:db8::/32".parse().expect("parse a v6 network");

        assert!(network.contains("10.0.0.5".parse().expect("parse an address")));
        assert!(network.contains("10.0.0.255".parse().expect("parse an address")));
        assert!(!network.contains("10.0.1.5".parse().expect("parse an address")));
        assert!(!network.contains("2001:db8::1".parse().expect("parse a v6 address")));

        assert!(host.contains("10.0.0.5".parse().expect("parse an address")));
        assert!(!host.contains("10.0.0.6".parse().expect("parse an address")));

        assert!(six.contains("2001:db8:99::1".parse().expect("parse a v6 address")));
        assert!(!six.contains("2001:db9::1".parse().expect("parse a v6 address")));
        assert!(!six.contains("10.0.0.5".parse().expect("parse an address")));

        let any: Cidr = "0.0.0.0/0".parse().expect("parse the widest network");

        assert!(any.contains("8.8.8.8".parse().expect("parse an address")));
    }

    /// A span is written between two addresses and keeps both of them: a prefix of the same width
    /// would cover addresses the span leaves out, which is the reason the field is not simply a
    /// `Cidr` with a prefix of 32.
    #[test]
    fn a_span_covers_both_ends_and_nothing_outside_them() {
        let span: Remote = "10.0.0.1-10.0.0.9".parse().expect("parse a span");

        assert_eq!(span.to_string(), "10.0.0.1-10.0.0.9");
        assert!(span.contains("10.0.0.1".parse().expect("parse an address")));
        assert!(span.contains("10.0.0.5".parse().expect("parse an address")));
        assert!(span.contains("10.0.0.9".parse().expect("parse an address")));
        assert!(!span.contains("10.0.0.0".parse().expect("parse an address")));
        assert!(!span.contains("10.0.0.10".parse().expect("parse an address")));
        assert!(!span.contains("2001:db8::1".parse().expect("parse a v6 address")));

        // The comparison runs over whole octets, so a span across an octet boundary has to hold
        // the addresses in between as well.
        let wide: Remote = "10.0.0.250-10.0.2.5".parse().expect("parse a wide span");

        assert!(wide.contains("10.0.1.200".parse().expect("parse an address")));
        assert!(!wide.contains("10.0.2.6".parse().expect("parse an address")));
    }

    /// A v6 span is written the same way and read the same way, and a single address is still a
    /// network, so the two shapes have to stay apart in what they parse into.
    #[test]
    fn a_span_and_a_network_are_told_apart_by_the_dash() {
        let six: Remote = "2001:db8::1-2001:db8::ff".parse().expect("parse a v6 span");

        assert_eq!(six.to_string(), "2001:db8::1-2001:db8::ff");
        assert!(six.contains("2001:db8::7f".parse().expect("parse a v6 address")));
        assert!(!six.contains("2001:db9::1".parse().expect("parse a v6 address")));

        assert!(matches!(
            "10.0.0.5".parse::<Remote>().expect("parse an address"),
            Remote::Network(_)
        ));
        assert!(matches!(
            "10.0.0.0/24".parse::<Remote>().expect("parse a network"),
            Remote::Network(_)
        ));
        assert!(matches!(
            "10.0.0.1-10.0.0.9".parse::<Remote>().expect("parse a span"),
            Remote::Span(_)
        ));
    }

    /// Three mistakes are worth refusing where the text is read: an end that is not an address, a
    /// span between the two families (no layer can match it), and a span the wrong way round.
    #[test]
    fn a_span_that_cannot_match_anything_is_refused() {
        assert!("10.0.0.1-example.com".parse::<Remote>().is_err());
        assert!("10.0.0.1-".parse::<Remote>().is_err());
        assert!("-10.0.0.1".parse::<Remote>().is_err());
        assert!("10.0.0.1-2001:db8::1".parse::<Remote>().is_err());
        assert!("10.0.0.9-10.0.0.1".parse::<Remote>().is_err());

        // A prefix belongs to a network, not to an end of a span, and WFP has no condition for
        // the pair either, so the text is refused rather than quietly read as one address.
        assert!("10.0.0.0/24-10.0.0.9".parse::<Remote>().is_err());
    }

    /// Learning mode asks whether a covered application is decided about a destination too. The
    /// answer comes from the enabled rules of that application alone, and a rule that names no
    /// destination is the reason a destination is not new.
    #[test]
    fn a_destination_is_only_new_for_the_rules_that_do_not_reach_it() {
        let wide = RuleFile {
            rule: vec![Rule::plain("browser", Action::Allow, "C:\\Windows\\*")],
        };
        let narrow = RuleFile {
            rule: vec![Rule {
                remote: Some("10.0.0.0/24".parse().expect("parse a network")),
                ..Rule::plain("browser", Action::Allow, "C:\\Windows\\*")
            }],
        };

        let inside = "10.0.0.5".parse().expect("parse an address");
        let outside = "93.184.216.34".parse().expect("parse an address");

        assert!(reaches(&wide, "C:\\Windows\\a.exe", inside));
        assert!(reaches(&wide, "C:\\Windows\\a.exe", outside));

        assert!(reaches(&narrow, "C:\\Windows\\a.exe", inside));
        assert!(!reaches(&narrow, "C:\\Windows\\a.exe", outside));

        // A rule about a different application decides nothing about this one.
        assert!(!reaches(&narrow, "C:\\other\\a.exe", inside));
    }

    #[test]
    fn only_enabled_rules_can_cover_a_path() {
        let rules = RuleFile {
            rule: vec![Rule {
                enabled: false,
                ..Rule::plain("windows", Action::Deny, "C:\\Windows\\*")
            }],
        };

        assert!(!covered_by(&rules, "C:\\Windows\\a.exe"));
    }

    #[test]
    fn an_empty_rule_file_round_trips() {
        let path = crate::testutil::scratch_dir("rules-empty").join("rules.toml");

        RuleFile::default().save(&path).expect("save");

        assert_eq!(RuleFile::load_or_create(&path).expect("load").rule.len(), 0);
    }

    #[test]
    fn a_profile_name_is_a_single_component() {
        assert!(is_valid_profile_name("work"));
        assert!(is_valid_profile_name("home.v2"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name(".."));
        assert!(!is_valid_profile_name("a\\b"));
        assert!(!is_valid_profile_name("a/b"));
        assert!(!is_valid_profile_name("c:d"));
    }

    #[test]
    fn profile_names_are_listed_without_their_suffix() {
        let dir = crate::testutil::scratch_dir("profile-names");
        std::fs::create_dir_all(&dir).expect("create dir");
        std::fs::write(dir.join("work.toml"), "").expect("write work");
        std::fs::write(dir.join("home.toml"), "").expect("write home");
        std::fs::write(dir.join("notes.txt"), "").expect("write notes");

        assert_eq!(list_names(&dir), vec!["home".to_owned(), "work".to_owned()]);
    }

    #[test]
    fn actions_are_written_lowercase() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        assert!(text.contains("action = \"allow\""), "{text}");
        assert!(text.contains("action = \"deny\""), "{text}");
    }

    #[test]
    fn a_port_range_reads_both_of_its_forms() {
        let single: PortRange = "443".parse().expect("parse a single port");

        assert_eq!((single.lo, single.hi, single.is_single()), (443, 443, true));

        let range: PortRange = "1024-2048".parse().expect("parse a range");

        assert_eq!((range.lo, range.hi, range.is_single()), (1024, 2048, false));
    }

    #[test]
    fn a_port_range_refuses_what_is_not_one() {
        assert!("".parse::<PortRange>().is_err());
        assert!("http".parse::<PortRange>().is_err());
        assert!(
            "2048-1024".parse::<PortRange>().is_err(),
            "it runs backwards"
        );
        assert!("70000".parse::<PortRange>().is_err(), "past a u16");
        assert!("1024-".parse::<PortRange>().is_err(), "no upper end");
    }

    /// A prefix is read in both families, a bare address is one host, and the host bits of a
    /// network do not survive the read.
    #[test]
    fn a_cidr_reads_its_written_forms() {
        let network: Cidr = "192.168.1.0/24".parse().expect("parse a network");
        assert_eq!(network.family, Family::V4);
        assert_eq!(network.prefix, 24);
        assert_eq!(network.v4_bytes(), [192, 168, 1, 0]);
        assert_eq!(network.v4_mask(), 0xffff_ff00);

        let host: Cidr = "10.0.0.5".parse().expect("parse a host");
        assert_eq!(host.prefix, 32);
        assert_eq!(host.to_string(), "10.0.0.5");

        let scoped: Cidr = "fe80::1/64".parse().expect("parse a scoped network");
        assert_eq!(scoped.family, Family::V6);
        assert_eq!(scoped.prefix, 64);
        assert_eq!(scoped.to_string(), "fe80::/64");

        // A whole family is a prefix as wide as the family, and is written without one.
        let any: Cidr = "::/0".parse().expect("parse the whole family");
        assert_eq!(any.prefix, 0);
        assert_eq!(any.to_string(), "::/0");
    }

    /// Reading a prefix keeps the network and drops the host bits, so what is stored is what WFP
    /// matches.
    #[test]
    fn a_cidr_keeps_only_its_network_part() {
        for (text, expected) in [
            ("10.0.0.5/24", "10.0.0.0/24"),
            ("10.0.0.5/32", "10.0.0.5"),
            ("10.0.0.5/0", "0.0.0.0/0"),
            ("2001:db8::5/48", "2001:db8::/48"),
        ] {
            let parsed: Cidr = text
                .parse()
                .unwrap_or_else(|error| panic!("parse {text}: {error}"));

            assert_eq!(parsed.to_string(), expected, "keep the network of {text}");
        }
    }

    /// What is refused: text that is not an address, a prefix that is not a number, and a prefix
    /// wider than the family.
    #[test]
    fn a_cidr_refuses_what_is_not_one() {
        for text in [
            "example.com",
            "10.0.0.5/abc",
            "10.0.0.5/33",
            "10.0.0.5/",
            "::/129",
            "",
        ] {
            assert!(text.parse::<Cidr>().is_err(), "'{text}' is not a prefix");
        }
    }

    #[test]
    fn a_port_range_is_written_as_it_is_read() {
        assert_eq!(
            "443".parse::<PortRange>().expect("parse").to_string(),
            "443"
        );
        assert_eq!(
            "1024-2048".parse::<PortRange>().expect("parse").to_string(),
            "1024-2048",
        );
    }

    /// A port field reads a single value as one element and a comma-separated text as a
    /// list, where every element is a port or a range in its own right.
    #[test]
    fn a_port_field_reads_a_list_and_a_single_value() {
        let single: Ports = "443".parse().expect("parse a single port");
        assert_eq!(single.elements(), &[PortRange { lo: 443, hi: 443 }]);

        let list: Ports = "80, 443, 8080-8090".parse().expect("parse a port list");
        assert_eq!(
            list.elements(),
            &[
                PortRange { lo: 80, hi: 80 },
                PortRange { lo: 443, hi: 443 },
                PortRange { lo: 8080, hi: 8090 },
            ],
        );
    }

    /// What a list element refuses is answered with the field named and the offending
    /// element quoted: an empty element, a port zero, a number past a u16, a range the wrong
    /// way round, and text that is not a port at all.
    #[test]
    fn a_port_field_refuses_malformed_elements() {
        for (text, offender) in [
            ("80, , 443", "80, , 443"),
            ("80, 0", "0"),
            ("80, 70000", "70000"),
            ("80, 90-80", "90-80"),
            ("80, http", "http"),
        ] {
            let refused = text
                .parse::<Ports>()
                .expect_err("a malformed element is refused");

            assert!(refused.contains("port"), "{text}: {refused}");
            assert!(refused.contains(offender), "{text}: {refused}");
        }
    }

    /// The cap that holds a wildcard pattern down holds a port list too, because each
    /// element is installed as a filter of its own.
    #[test]
    fn a_port_field_is_capped_like_a_wildcard_pattern() {
        let at_cap = (1..=MAX_WILDCARD_MATCHES)
            .map(|port| port.to_string())
            .collect::<Vec<String>>()
            .join(", ");

        assert_eq!(
            at_cap
                .parse::<Ports>()
                .expect("a list at the cap")
                .elements()
                .len(),
            MAX_WILDCARD_MATCHES,
        );

        let over_cap = format!("{at_cap}, 60001");
        assert!(
            over_cap.parse::<Ports>().is_err(),
            "one element past the cap is refused: {over_cap}",
        );
    }

    /// A single value is written back as a single value and a list as a list: the text
    /// the field was read from is the text it writes.
    #[test]
    fn a_port_field_is_written_as_it_is_read() {
        for text in ["443", "80-90", "80, 443", "80, 443, 8080-8090"] {
            let ports: Ports = text.parse().expect("parse");

            assert_eq!(ports.to_string(), text, "written back as read");
        }
    }

    /// The file holds the text the field was read from: one port is written exactly as it
    /// was before lists existed, and a list round-trips as the comma-separated string.
    #[test]
    fn a_port_field_survives_a_round_trip_through_the_file() {
        let path = crate::testutil::scratch_dir("rules-port-list").join("rules.toml");
        let rules = RuleFile {
            rule: vec![
                Rule {
                    port: Some("80".parse().expect("parse a port")),
                    ..Rule::plain("one port", Action::Allow, "C:\\Tools\\one.exe")
                },
                Rule {
                    port: Some("80, 443, 8080-8090".parse().expect("parse a port list")),
                    ..Rule::plain("a list", Action::Allow, "C:\\Tools\\many.exe")
                },
            ],
        };

        rules.save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("port = \"80\""), "{text}");
        assert!(text.contains("port = \"80, 443, 8080-8090\""), "{text}");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    /// The JSON form is the same comma-separated text the file writes, which is what lets
    /// `/api/state` and a share string carry the list as well.
    #[test]
    fn a_port_field_is_written_to_json_as_the_text_that_reads_back() {
        let rule = Rule {
            port: Some("80, 443".parse().expect("parse a port list")),
            ..Rule::plain("json", Action::Allow, "C:\\Tools\\json.exe")
        };

        let json = serde_json::to_string(&rule).expect("serialize");
        assert!(json.contains(r#""port":"80, 443""#), "{json}");

        let back: Rule = serde_json::from_str(&json).expect("read back");
        assert_eq!(back, rule);
    }

    /// The share string is Base64 around JSON, and a rule whose port field is a list comes
    /// back from it as the same rule.
    #[test]
    fn the_share_string_carries_a_rule_with_a_port_list() {
        let rule = Rule {
            port: Some("80, 443, 8080-8090".parse().expect("parse a port list")),
            ..Rule::plain("shared", Action::Allow, "C:\\Tools\\shared.exe")
        };

        let shared = crate::export::decode(&crate::export::encode(&rule).expect("encode"))
            .expect("decode a rule with a port list");

        assert_eq!(shared, rule);
    }

    #[test]
    fn a_rule_without_narrowing_is_written_as_it_used_to_be() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        for key in ["protocol", "direction", "port", "local"] {
            assert!(
                !text.contains(key),
                "{key} appeared for a rule that has none: {text}"
            );
        }
    }

    /// A local address is written to the file and read back exactly like the remote one is, which
    /// is what lets a rule about an interface and a rule about a destination live in one list.
    #[test]
    fn a_local_address_survives_a_round_trip() {
        let path = crate::testutil::scratch_dir("rules-local").join("rules.toml");
        let rules = RuleFile {
            rule: vec![Rule {
                remote: Some("192.168.1.0/24".parse().expect("parse a network")),
                local: Some("10.0.0.1-10.0.0.9".parse().expect("parse a span")),
                ..Rule::plain("ssh", Action::Allow, "C:\\Tools\\ssh.exe")
            }],
        };

        rules.save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains(r#"remote = "192.168.1.0/24""#), "{text}");
        assert!(text.contains(r#"local = "10.0.0.1-10.0.0.9""#), "{text}");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn the_narrowing_of_a_rule_survives_a_round_trip() {
        let path = crate::testutil::scratch_dir("rules-narrowing").join("rules.toml");
        let rules = RuleFile {
            rule: vec![Rule {
                protocol: Some(Protocol::Tcp),
                direction: Some(Direction::Out),
                port: Some("1024-2048".parse().expect("parse a port")),
                ..Rule::plain("ssh", Action::Allow, "C:\\Tools\\ssh.exe")
            }],
        };

        rules.save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("protocol = \"tcp\""), "{text}");
        assert!(text.contains("direction = \"out\""), "{text}");
        assert!(text.contains("port = \"1024-2048\""), "{text}");

        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn a_rule_file_refuses_a_local_address_it_cannot_read() {
        let parsed = rule_file_with("local = \"10.0.0.256\"");

        assert!(parsed.is_err(), "an octet has a maximum");
    }

    #[test]
    fn a_rule_file_refuses_a_port_it_cannot_read() {
        let parsed: Result<RuleFile, toml::de::Error> = toml::from_str(
            "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"a\"\nport = \"http\"\n",
        );

        assert!(parsed.is_err(), "a port must be a port");
    }

    #[test]
    fn a_rule_file_refuses_a_protocol_it_does_not_know() {
        let parsed = rule_file_with("protocol = \"sctp\"");

        assert!(parsed.is_err(), "a name that is not tcp or udp is refused");
    }

    /// Read one rule file whose only interesting field is the text given.
    fn rule_file_with(field: &str) -> Result<RuleFile, toml::de::Error> {
        toml::from_str(&format!(
            "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"a\"\n{field}\n"
        ))
    }

    #[test]
    fn a_bare_protocol_number_survives_a_round_trip() {
        let path = crate::testutil::scratch_dir("rules-protocol-number").join("rules.toml");
        let rules = RuleFile {
            rule: vec![Rule {
                protocol: Some(Protocol::Other(47)),
                ..Rule::plain("gre", Action::Allow, "C:\\Tools\\gre.exe")
            }],
        };

        rules.save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("protocol = 47"), "{text}");
        assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);
    }

    #[test]
    fn a_protocol_number_is_the_same_rule_whether_it_is_quoted_or_not() {
        let bare = rule_file_with("protocol = 47").expect("read the bare number");
        let quoted = rule_file_with("protocol = \"47\"").expect("read the quoted number");

        assert_eq!(bare, quoted, "one number is one rule");
    }

    #[test]
    fn a_protocol_number_outside_one_byte_or_zero_is_refused() {
        for field in ["protocol = 0", "protocol = 256", "protocol = -1"] {
            assert!(
                rule_file_with(field).is_err(),
                "{field} should not name a protocol of this rule"
            );
        }
    }

    /// The state answer, the API body and the share string all go through JSON, so both directions
    /// of the shape are pinned: a name stays a name, a number stays a number, and a client that
    /// sends the number means the same rule the file spells it.
    #[test]
    fn a_protocol_travels_as_its_name_or_as_its_number() {
        assert_eq!(
            serde_json::to_string(&Protocol::Tcp).expect("tcp"),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&Protocol::Udp).expect("udp"),
            "\"udp\""
        );
        assert_eq!(
            serde_json::to_string(&Protocol::Other(47)).expect("a number"),
            "47"
        );

        for text in ["47", "\"47\""] {
            assert_eq!(
                serde_json::from_str::<Protocol>(text).expect("a protocol read from JSON"),
                Protocol::Other(47),
                "{text} should read as the same protocol",
            );
        }

        assert!(
            serde_json::from_str::<Protocol>("0").is_err(),
            "zero is not a protocol"
        );
    }

    #[test]
    fn a_pattern_must_be_an_absolute_path() {
        assert!(validate_pattern("C:\\Windows\\*\\browser.exe").is_ok());
        assert!(validate_pattern("C:\\\\").is_ok(), "a drive root is a path");
        assert!(validate_pattern("\\device\\harddiskvolume3\\x.exe").is_ok());
        assert!(validate_pattern("browser.exe").is_err(), "no root at all");
        assert!(validate_pattern("").is_err(), "nothing is not a path");
    }

    #[test]
    fn a_pattern_refuses_what_a_path_cannot_hold() {
        for bad in ["C:\\a<b.exe", "C:\\a>b.exe", "C:\\a|b.exe", "C:\\a\"b.exe"] {
            assert!(validate_pattern(bad).is_err(), "{bad} cannot be a path");
        }

        assert!(
            validate_pattern("C:\\a\nb.exe").is_err(),
            "a pasted newline is a control character"
        );
    }

    /// A comment is the one field that is prose, so it is the one field a person is most likely to
    /// paste in from somewhere else. It has to survive the file exactly as it was typed.
    #[test]
    fn a_comment_survives_the_file_and_the_share_string() {
        let mut rule = Rule::plain("browser", Action::Allow, "C:\\Windows\\*");
        rule.comment = Some("vpn client, must not be blocked \u{2014} see ticket 42".to_owned());

        let text = toml::to_string_pretty(&RuleFile {
            rule: vec![rule.clone()],
        })
        .expect("serialize");

        assert!(text.contains("comment ="), "{text}");

        let loaded = RuleFile::from_text(&text).expect("read the file back");

        assert_eq!(loaded.rule[0], rule, "the comment must not be rewritten");
        assert_eq!(
            crate::export::decode(&crate::export::encode(&rule).expect("encode"))
                .expect("decode the share"),
            rule,
            "a shared rule keeps its reason"
        );
    }

    /// A rule that has no comment must not grow one, and an empty file must not grow the key at
    /// all: this is the first field an older `rules.toml` is certain not to have.
    #[test]
    fn a_rule_without_a_comment_is_written_exactly_as_it_used_to_be() {
        let text = toml::to_string_pretty(&sample()).expect("serialize");

        assert!(!text.contains("comment"), "{text}");

        let plain: RuleFile = toml::from_str(
            "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"C:\\\\a.exe\"\n",
        )
        .expect("a file without the key still reads");

        assert_eq!(plain.rule[0].comment, None);
    }

    #[test]
    fn a_comment_refuses_what_a_line_cannot_hold() {
        assert!(
            validate_comment("").is_ok(),
            "an empty comment is a question for the UI"
        );
        assert!(validate_comment("block telemetry until the vendor fixes it").is_ok());
        assert!(
            validate_comment("two\nlines").is_err(),
            "a comment is one line of a file the user scans"
        );
        assert!(
            validate_comment(&"x".repeat(COMMENT_LIMIT + 1)).is_err(),
            "too long is refused rather than cut"
        );
        assert!(validate_comment(&"x".repeat(COMMENT_LIMIT)).is_ok());
    }

    /// The first screen teaches the field as well as the shape of a rule.
    #[test]
    fn the_example_rules_explain_themselves() {
        let examples = RuleFile::examples();

        for rule in &examples.rule {
            let comment = rule.comment.as_deref().unwrap_or_default();

            assert!(
                comment.starts_with("the "),
                "{comment} should read as a reason"
            );
            assert!(validate_comment(comment).is_ok(), "{comment} is too long");
        }
    }

    #[test]
    fn a_shared_rule_still_passes_the_pattern_check() {
        let shared =
            crate::export::decode(&crate::export::encode(&sample().rule[0]).expect("encode"))
                .expect("decode");

        assert!(
            validate_pattern(&shared.pattern).is_ok(),
            "{}",
            shared.pattern
        );
    }

    /// The previous generation written by `save` is what a file nothing can make sense of falls
    /// back to, which is the point of keeping it.
    #[test]
    fn an_unreadable_rules_file_falls_back_to_its_backup() {
        let path = crate::testutil::scratch_dir("rules-backup").join("rules.toml");

        sample().save(&path).expect("first save");
        sample()
            .save(&path)
            .expect("second save, which makes the backup");

        std::fs::write(&path, b"not toml at all ((").expect("corrupt the file");

        let loaded = RuleFile::load_or_create(&path).expect("the backup has to answer");

        assert_eq!(loaded, sample());
    }

    /// A file written by a later version names both versions rather than failing on a field it
    /// refuses to know.
    #[test]
    fn a_rule_file_from_a_later_version_is_refused_by_name() {
        let path = crate::testutil::scratch_dir("rules-version").join("rules.toml");

        std::fs::write(&path, "version = 99\n").expect("write");

        let text = format!(
            "{:#}",
            RuleFile::load_or_create(&path).expect_err("a newer version is an error")
        );

        assert!(text.contains("99"), "the version should be named: {text}");
        assert!(
            text.contains(&RULE_FILE_VERSION.to_string()),
            "our version should be named too: {text}"
        );
    }

    /// A file the tool wrote agrees with itself, which is the baseline the field is judged
    /// against: write and read must hash the body the same way.
    #[test]
    fn a_written_rule_file_carries_a_checksum_of_its_body() {
        let path = crate::testutil::scratch_dir("rules-checksum").join("rules.toml");

        sample().save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read back");

        assert!(
            text.contains("[[rule]]") && text.contains("checksum = \""),
            "the version and the checksum are written before the body: {text}"
        );

        let (_rules, checksum) = parse_rule_file(text.as_bytes()).expect("parse");

        assert!(
            !checksum.mismatched(),
            "a file the tool wrote agrees with itself: {checksum:?}"
        );
    }

    /// The case the field exists for: a body that still parses but lost content on the way.
    #[test]
    fn a_body_edited_by_hand_disagrees_with_its_checksum() {
        let path = crate::testutil::scratch_dir("rules-checksum-edit").join("rules.toml");

        sample().save(&path).expect("save");

        let text = std::fs::read_to_string(&path).expect("read back");
        let edited = text.replace("telemetry", "telemetry2");

        let (rules, checksum) = parse_rule_file(edited.as_bytes()).expect("the edited body parses");

        assert_eq!(rules.rule.len(), 2, "the edit leaves both rules standing");
        assert!(
            checksum.mismatched(),
            "a changed body must not agree with the checksum it carries: {checksum:?}"
        );
    }

    /// A file from before the field carries nothing to compare against, which is a disagreement of
    /// its own rather than a pass.
    #[test]
    fn a_file_without_a_checksum_is_read_and_reported() {
        let (_rules, checksum) = parse_rule_file(
            b"version = 1\n\n[[rule]]\nname = \"one\"\naction = \"allow\"\npattern = 'C:\\one.exe'\n",
        )
        .expect("a file without a checksum still reads");

        assert_eq!(checksum.stated, None, "the file names no checksum");
        assert!(
            checksum.mismatched(),
            "a missing checksum is reported, not passed over: {checksum:?}"
        );
    }
}
