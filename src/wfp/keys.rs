//! The wide-string helper and the stable keys derived from rule names.

use crate::wfp::*;

/// FNV-1a parameters, used to derive a filter key from a rule name.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Encode a string as the NUL terminated UTF-16 buffer the WFP structs point at.
pub(super) fn wide(value: &str) -> Vec<u16> {
    let mut units: Vec<u16> = value.encode_utf16().collect();
    units.push(0);
    units
}

fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;

    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

/// The bytes of a GUID in the order a UUID is written down.
fn guid_bytes(guid: &GUID) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);

    bytes.extend_from_slice(&guid.data1.to_be_bytes());
    bytes.extend_from_slice(&guid.data2.to_be_bytes());
    bytes.extend_from_slice(&guid.data3.to_be_bytes());
    bytes.extend_from_slice(&guid.data4);

    bytes
}

/// A stable filter key for one rule on one layer.
///
/// A key derived from the rule name, rather than a randomly generated one, is what lets a rule be
/// recognised again after a restart. Two FNV-1a chains with different seeds fill the 128 bits; the
/// second chain also takes the layer, because a filter key has to be unique across the store and
/// one rule installs a filter per layer. The version and variant nibbles are fixed up so the
/// result is a well formed UUID if any other tool looks at it.
pub fn filter_key(name: &str, layer: &GUID) -> GUID {
    let high = fnv1a(FNV_OFFSET, name.as_bytes());
    let low = fnv1a(!FNV_OFFSET, &guid_bytes(layer));
    let low = fnv1a(low, name.as_bytes());

    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&high.to_be_bytes());
    raw[8..].copy_from_slice(&low.to_be_bytes());

    raw[6] = (raw[6] & 0x0F) | 0x50; // version 5
    raw[8] = (raw[8] & 0x3F) | 0x80; // RFC 4122 variant

    GUID::from_u128(u128::from_be_bytes(raw))
}
