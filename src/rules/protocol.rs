//! The transport a rule is about.
//!
//! Absent on a rule means every transport. A rule file may name `tcp` and `udp`; anything else is
//! written as the protocol number, which is how a rule about GRE (47) or ESP (50) is expressed.

use serde::{Deserialize, Serialize};

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
