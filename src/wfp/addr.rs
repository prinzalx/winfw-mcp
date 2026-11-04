//! Address conditions: the value a condition carries in each family, and the ranges built from
//! them.

use crate::wfp::*;

/// The value an address condition carries, in whichever family the address is in. A span keeps
/// only its bounds here; the `FWP_RANGE0` that points at them is built next to it.
pub(super) enum AddrValue {
    V4(FWP_V4_ADDR_AND_MASK),
    V6(FWP_V6_ADDR_AND_MASK),
    V4Range([u32; 2]),
    V6Range([FWP_BYTE_ARRAY16; 2]),
}

/// The value a rule names one end of a connection with. A destination of names is
/// merged into the addresses by [`crate::dns::rule_with_answers`] before the rule
/// reaches this point, so nothing here holds a name.
pub(super) fn addr_value(address: Remote) -> AddrValue {
    match address {
        Remote::Network(cidr) => match cidr.family {
            Family::V4 => AddrValue::V4(FWP_V4_ADDR_AND_MASK {
                addr: u32::from_be_bytes(cidr.v4_bytes()),
                mask: cidr.v4_mask(),
            }),
            Family::V6 => AddrValue::V6(FWP_V6_ADDR_AND_MASK {
                addr: cidr.addr,
                prefixLength: cidr.prefix,
            }),
        },
        Remote::Span(range) => match range.family {
            Family::V4 => AddrValue::V4Range([bound32(range.from), bound32(range.to)]),
            Family::V6 => AddrValue::V6Range([
                FWP_BYTE_ARRAY16 {
                    byteArray16: range.from,
                },
                FWP_BYTE_ARRAY16 {
                    byteArray16: range.to,
                },
            ]),
        },
    }
}

/// The range a span condition points at, or nothing for an address, which WFP matches by prefix.
///
/// The reference fills the same shape: a v4 bound is the address byteswapped, which is the number
/// `bound32` of the octets gives, and a v6 bound is a pointer to the octets.
pub(super) fn span_range(value: Option<&AddrValue>) -> Option<FWP_RANGE0> {
    match value {
        Some(AddrValue::V4Range([lo, hi])) => Some(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: *lo },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_VALUE0_0 { uint32: *hi },
            },
        }),
        Some(AddrValue::V6Range([lo, hi])) => Some(FWP_RANGE0 {
            valueLow: FWP_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_VALUE0_0 {
                    byteArray16: lo as *const FWP_BYTE_ARRAY16 as *mut _,
                },
            },
            valueHigh: FWP_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_VALUE0_0 {
                    byteArray16: hi as *const FWP_BYTE_ARRAY16 as *mut _,
                },
            },
        }),
        _ => None,
    }
}

/// The value of every element of an address field, in the order the field was written.
///
/// A field that names no address yields no value at all, which [`addr_variants`] turns into the
/// single empty variant a rule without an address has always had.
pub(super) fn addr_values(field: Option<&Remotes>) -> Vec<AddrValue> {
    field
        .map_or(&[][..], Remotes::elements)
        .iter()
        .map(|element| addr_value(*element))
        .collect()
}

/// The range each value of a field points at, in a vector parallel to it, empty for a field that
/// names no address.
pub(super) fn span_ranges(values: &[AddrValue]) -> Vec<Option<FWP_RANGE0>> {
    values.iter().map(|value| span_range(Some(value))).collect()
}

/// Which elements of a field are installed as a condition on a layer of the given family, each
/// paired with the empty variant a field that names no address is matched with.
pub(super) fn addr_variants(values: &[AddrValue], family: Family) -> Vec<Option<&AddrValue>> {
    if values.is_empty() {
        return vec![None];
    }

    values
        .iter()
        .filter(|value| addr_family(value) == family)
        .map(Some)
        .collect()
}

/// Which family an installed value belongs to, whichever of the four shapes it has.
pub(super) fn addr_family(value: &AddrValue) -> Family {
    match value {
        AddrValue::V4(_) | AddrValue::V4Range(_) => Family::V4,
        AddrValue::V6(_) | AddrValue::V6Range(_) => Family::V6,
    }
}

/// The condition that names one end of a connection: the remote address, or the local one.
///
/// A span is matched as a range and so points at the bounds [`span_range`] built; an address is
/// matched by prefix straight out of its own value.
pub(super) fn addr_condition(
    field: GUID,
    addr: &AddrValue,
    range: Option<&FWP_RANGE0>,
) -> FWPM_FILTER_CONDITION0 {
    match addr {
        AddrValue::V4(addr) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: addr as *const FWP_V4_ADDR_AND_MASK as *mut _,
                },
            },
        },
        AddrValue::V6(addr) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    v6AddrMask: addr as *const FWP_V6_ADDR_AND_MASK as *mut _,
                },
            },
        },
        AddrValue::V4Range(_) | AddrValue::V6Range(_) => FWPM_FILTER_CONDITION0 {
            fieldKey: field,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: range
                        .map(|range| range as *const FWP_RANGE0 as *mut _)
                        .unwrap_or(std::ptr::null_mut()),
                },
            },
        },
    }
}

/// The four octets of a v4 address as WFP numbers them: most significant octet first.
pub(super) fn bound32(addr: [u8; 16]) -> u32 {
    u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]])
}
