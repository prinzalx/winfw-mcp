//! Addresses a rule can name: a single one, a range, or a subnet.

use serde::{Deserialize, Serialize};

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

/// Turn one address into the sixteen bytes it is stored as, with the family that decides
/// which layers a rule about it goes on.
fn addr_bytes(addr: std::net::IpAddr) -> ([u8; 16], Family) {
    match addr {
        std::net::IpAddr::V4(v4) => {
            let mut bytes = [0u8; 16];

            bytes[..4].copy_from_slice(&v4.octets());

            (bytes, Family::V4)
        }
        std::net::IpAddr::V6(v6) => (v6.octets(), Family::V6),
    }
}

/// Read one address of either family into the sixteen bytes WFP is given, with the family that
/// decides which layers a rule about it goes on.
///
/// IPv4 is tried first, because Rust reads a dotted quad as an IPv4-mapped IPv6 address too, and
/// `10.0.0.5` should stay the four byte address the user typed.
fn parse_address(host: &str) -> Result<([u8; 16], Family), String> {
    host.parse::<std::net::IpAddr>()
        .map(addr_bytes)
        .map_err(|_| format!("'{host}' is not an IP address"))
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
///
/// A name is not one of these. Names belong to the `dest` field of a rule and are resolved to
/// addresses when the filters are built; see [`Dests`]. Keeping the two apart means the address
/// field never guesses: `10.0.0.256` is an error there, not a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remote {
    /// One address or a network, written `10.0.0.5` or `10.0.0.0/24`.
    Network(Cidr),
    /// A span between two addresses, written `10.0.0.1-10.0.0.9`.
    Span(AddressRange),
}

impl Remote {
    /// The families the element can be installed in, which decides the layers a rule is
    /// offered.
    pub fn families(&self) -> Vec<Family> {
        match self {
            Self::Network(cidr) => vec![cidr.family],
            Self::Span(range) => vec![range.family],
        }
    }

    /// The element an address stands for on its own: a host of its family, written as a
    /// network with the full prefix.
    pub fn address(addr: std::net::IpAddr) -> Option<Self> {
        let text = match addr {
            std::net::IpAddr::V4(v4) => format!("{v4}/32"),
            std::net::IpAddr::V6(v6) => format!("{v6}/128"),
        };

        text.parse::<Cidr>().ok().map(Self::Network)
    }

    /// Whether an address is one the rule speaks about.
    pub fn contains(&self, addr: std::net::IpAddr) -> bool {
        match self {
            Self::Network(cidr) => cidr.contains(addr),
            Self::Span(range) => {
                // The address goes into the same sixteen byte layout a stored end uses, so the
                // comparison below needs no knowledge of the family it is reading.
                let (other, family) = addr_bytes(addr);

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

        // Both halves have to be addresses before the text is taken for a span; anything
        // else is read as an address, and a name written here is an error the user sees.
        if !(parse_address(low).is_ok() && parse_address(high).is_ok()) {
            return text.parse::<Cidr>().map(Self::Network);
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
