//! The write path of a filter: the values a rule's conditions point into, the condition list
//! itself, and the functions that hand a filter to the engine.

use crate::wfp::addr::*;
use crate::wfp::app_id::*;
use crate::wfp::keys::*;
use crate::wfp::layers::*;
use crate::wfp::*;

/// The values the conditions of one rule's filters point into.
///
/// WFP keeps a pointer to each of them rather than a copy, so everything a condition refers
/// to is owned here for as long as the filters of the rule are being added.
struct FilterValues<'a> {
    /// The elements of the port field, which the port ranges below are parallel to.
    ports: &'a [PortRange],
    /// One range per element of the port field; an element that is a single port owns a
    /// range no condition points into.
    port_ranges: Vec<FWP_RANGE0>,
    remote_values: Vec<AddrValue>,
    remote_ranges: Vec<Option<FWP_RANGE0>>,
    local_values: Vec<AddrValue>,
    local_ranges: Vec<Option<FWP_RANGE0>>,
}

impl<'a> FilterValues<'a> {
    fn new(rule: &'a Rule) -> Self {
        let ports = rule.port.as_ref().map_or(&[][..], Ports::elements);
        let port_ranges: Vec<FWP_RANGE0> = ports
            .iter()
            .map(|port| FWP_RANGE0 {
                valueLow: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.lo },
                },
                valueHigh: FWP_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_VALUE0_0 { uint16: port.hi },
                },
            })
            .collect();
        let remote_values = addr_values(rule.remote.as_ref());
        let remote_ranges = span_ranges(&remote_values);
        let local_values = addr_values(rule.local.as_ref());
        let local_ranges = span_ranges(&local_values);

        Self {
            ports,
            port_ranges,
            remote_values,
            remote_ranges,
            local_values,
            local_ranges,
        }
    }
}

/// The condition list one combination of application, protocol, port and addresses stands
/// for. Every pointer in it points into `values` or `app`, which the caller keeps alive for
/// as long as the filter is being added.
#[allow(clippy::too_many_arguments)]
fn condition_list(
    values: &FilterValues<'_>,
    layer: GUID,
    app: &AppId,
    protocol: Option<FWPM_FILTER_CONDITION0>,
    port: Option<&PortRange>,
    port_index: usize,
    remote: Option<&AddrValue>,
    remote_index: usize,
    local: Option<&AddrValue>,
    local_index: usize,
) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut conditions = vec![FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_ALE_APP_ID,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_BYTE_BLOB_TYPE,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                byteBlob: &raw const app.blob as *mut _,
            },
        },
    }];

    if let Some(condition) = protocol {
        conditions.push(condition);
    }

    if let Some(port) = port {
        // One port is matched exactly; a range needs the range type and the range the store
        // keeps a pointer to.
        conditions.push(if port.is_single() {
            FWPM_FILTER_CONDITION0 {
                fieldKey: port_condition(layer),
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: port.lo },
                },
            }
        } else {
            FWPM_FILTER_CONDITION0 {
                fieldKey: port_condition(layer),
                matchType: FWP_MATCH_RANGE,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_RANGE_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        rangeValue: &raw const values.port_ranges[port_index] as *mut _,
                    },
                },
            }
        });
    }

    if let Some(remote) = remote {
        conditions.push(addr_condition(
            FWPM_CONDITION_IP_REMOTE_ADDRESS,
            remote,
            values.remote_ranges[remote_index].as_ref(),
        ));
    }

    if let Some(local) = local {
        conditions.push(addr_condition(
            FWPM_CONDITION_IP_LOCAL_ADDRESS,
            local,
            values.local_ranges[local_index].as_ref(),
        ));
    }

    conditions
}

impl Engine {
    /// Install one rule as one filter per application per layer, and once more per element when
    /// the port field names a list: a range is not a value that could ride in one condition
    /// beside single ports, so every element of the list becomes a filter of its own. Which
    /// layers that is depends on the direction of the rule; with no direction both an outbound
    /// and an inbound connection are covered, for both address families. Returns the number of
    /// filters installed.
    pub(super) fn add_rule(
        &self,
        rule: &Rule,
        known: &[String],
        answers: &crate::dns::Answers,
        owners: &mut Owners,
    ) -> Result<usize> {
        // A destination of names is answered before the rule reaches WFP; what is left is
        // what the kernel can compare against.
        let resolved = crate::dns::rule_with_answers(rule, answers);
        let rule = resolved.as_ref().unwrap_or(rule);
        let expansion = app_ids(&rule.pattern, known);
        let truncated = expansion.truncated();
        let matches = expansion.matches;
        let installed = expansion.installed();
        let apps = expansion.apps;

        if truncated {
            // A firewall that quietly stops matching is a firewall nobody can reason about, so the
            // cap is named out loud with the numbers behind it.
            warn!(
                rule = %rule.name,
                pattern = %rule.pattern,
                matches,
                installed,
                "the wildcard pattern matched more applications than the cap allows",
            );
        }

        let action = match rule.action {
            Action::Allow => FWP_ACTION_PERMIT,
            Action::Deny => FWP_ACTION_BLOCK,
        };

        // Deny outranks allow by weight, so a matching deny wins whatever the order in the file
        // is. Among rules of the same action the earlier rule still wins, because equal weights
        // are resolved in creation order and we install in file order.
        let weight = match rule.action {
            Action::Allow => WEIGHT_ALLOW,
            Action::Deny => WEIGHT_DENY,
        };

        // A deny also has to win over the permit filters of other software, which is what
        // clearing the action right of lower-weight filters does. Mirrors the reference
        // implementation.
        let mut flags = FWPM_FILTER_FLAG_PERSISTENT | FWPM_FILTER_FLAG_INDEXED;

        if rule.action == Action::Deny {
            flags |= FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;
        }

        // Everything a condition of this rule's filters points into, owned for as long as the
        // filters are being added.
        let values = FilterValues::new(rule);

        // Each element of the port field is installed as a filter of its own. A rule that
        // names no port gets the single empty variant it always had, so a rule from before
        // the list exists installs exactly what it installed then.
        let port_variants: Vec<Option<&PortRange>> = if values.ports.is_empty() {
            vec![None]
        } else {
            values.ports.iter().map(Some).collect()
        };

        // The protocol condition is the same for every filter of the rule.
        let protocol = rule.protocol.map(|protocol| FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: protocol.number(),
                },
            },
        });

        let mut installed = 0;

        // One set of conditions per application, because the application condition points into
        // that application's blob.
        for (index, app) in apps.iter().enumerate() {
            for layer in rule_layers(rule) {
                // Only an element of the layer's own family can be matched on it, so a list
                // that mixes families is installed in both stacks, one element per filter.
                let remote_variants = addr_variants(&values.remote_values, layer_family(layer));
                let local_variants = addr_variants(&values.local_values, layer_family(layer));

                for (port_index, port) in port_variants.iter().enumerate() {
                    for (remote_index, remote) in remote_variants.iter().enumerate() {
                        for (local_index, local) in local_variants.iter().enumerate() {
                            let conditions = condition_list(
                                &values,
                                layer,
                                app,
                                protocol,
                                *port,
                                port_index,
                                *remote,
                                remote_index,
                                *local,
                                local_index,
                            );

                            // The key stays exactly what a rule with one element per field
                            // always used; only a field that names more elements tells its
                            // filters apart by the element number, so no two of them collide.
                            let mut key = format!("{}#{index}", rule.name);

                            if port_variants.len() > 1 {
                                key.push_str(&format!(".{port_index}"));
                            }

                            if remote_variants.len() > 1 {
                                key.push_str(&format!(".{remote_index}"));
                            }

                            if local_variants.len() > 1 {
                                key.push_str(&format!(".{local_index}"));
                            }

                            self.install_filter(
                                &rule.name,
                                &key,
                                layer,
                                action,
                                weight,
                                flags,
                                &conditions,
                                "rule",
                                owners,
                            )?;

                            installed += 1;
                        }
                    }
                }
            }
        }

        Ok(installed)
    }

    /// Install the base filters of the default-deny policy, mirroring the reference
    /// (`reference wfp.c:1605-1688` and `1827-1838`).
    ///
    /// An unconditional block sits at the very bottom of the four authorization layers, so
    /// traffic no rule mentions is denied rather than falling through to whatever the rest of
    /// the machine decides. Above it sit the permits without which the policy would break the
    /// machine itself: loopback (the browser has to reach this tool's own web server), 6to4,
    /// and the ICMPv6 neighbor and router messages the IPv6 stack needs.
    pub(super) fn add_base_filters(&self, owners: &mut Owners) -> Result<usize> {
        // Not from the windows crate under the name we would wish for it: `IPPROTO_IPV6` there
        // is the IPv6 *socket option* level, the same number 41 the reference uses as the
        // protocol value of the 6to4 permit.
        const IPPROTO_IPV6: u8 = 41;

        // Router solicitation/advertisement and neighbor solicitation/advertisement.
        const ICMPV6_TYPES: [u16; 4] = [133, 134, 135, 136];

        let mut installed = 0;

        let loopback = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ANY_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK
                        | FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK,
                },
            },
        }];

        for layer in LAYERS {
            self.add_filter(
                "base#loopback",
                layer,
                FWP_ACTION_PERMIT,
                WEIGHT_BASE_PERMIT,
                &loopback,
                owners,
            )?;

            installed += 1;
        }

        let sixtofour = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint8: IPPROTO_IPV6,
                },
            },
        }];

        self.add_filter(
            "base#6to4",
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            FWP_ACTION_PERMIT,
            WEIGHT_BASE_PERMIT,
            &sixtofour,
            owners,
        )?;

        installed += 1;

        for icmp_type in ICMPV6_TYPES {
            let permit = [FWPM_FILTER_CONDITION0 {
                // `FWPM_CONDITION_ICMP_TYPE` is not a GUID of its own: the SDK spells it as an
                // alias for the local port (`fwpmu.h:1720`), which the windows crate exports.
                fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: icmp_type },
                },
            }];

            self.add_filter(
                &format!("base#icmpv6-{icmp_type}"),
                FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                FWP_ACTION_PERMIT,
                WEIGHT_BASE_PERMIT,
                &permit,
                owners,
            )?;

            installed += 1;
        }

        for layer in LAYERS {
            self.add_filter(
                "base#block",
                layer,
                FWP_ACTION_BLOCK,
                WEIGHT_BASE_BLOCK,
                &[],
                owners,
            )?;

            installed += 1;
        }

        Ok(installed)
    }

    /// Install one filter of the base, as opposed to one installed from a rule.
    pub(super) fn add_filter(
        &self,
        name: &str,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        conditions: &[FWPM_FILTER_CONDITION0],
        owners: &mut Owners,
    ) -> Result<()> {
        self.install_filter(
            name,
            name,
            layer,
            action,
            weight,
            FWPM_FILTER_FLAG_PERSISTENT,
            conditions,
            "base filter",
            owners,
        )
    }

    /// Hand one filter to WFP and record it under the name that owns it.
    ///
    /// `name` is what the filter is labeled with and what a failure names; `key` is the
    /// identity the store uses to find the filter again. For a base filter the two are the
    /// same; a rule tells the filters it spawns apart by the key alone. `kind` only appears
    /// in the error message.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn install_filter(
        &self,
        name: &str,
        key: &str,
        layer: GUID,
        action: FWP_ACTION_TYPE,
        weight: u8,
        flags: FWPM_FILTER_FLAGS,
        conditions: &[FWPM_FILTER_CONDITION0],
        kind: &str,
        owners: &mut Owners,
    ) -> Result<()> {
        let mut provider_key = PROVIDER_KEY;

        let owner = wide(APP_NAME);
        let label = wide(name);

        let mut filter = FWPM_FILTER0 {
            filterKey: filter_key(key, &layer),
            displayData: FWPM_DISPLAY_DATA0 {
                name: PWSTR(owner.as_ptr() as *mut _),
                description: PWSTR(label.as_ptr() as *mut _),
            },
            flags,
            providerKey: &mut provider_key,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: weight },
            },
            numFilterConditions: conditions.len() as u32,
            ..Default::default()
        };

        if !conditions.is_empty() {
            filter.filterCondition = conditions.as_ptr() as *mut FWPM_FILTER_CONDITION0;
        }

        filter.action = FWPM_ACTION0 {
            r#type: action,
            ..Default::default()
        };

        let mut filter_id = 0u64;

        // SAFETY: every pointer in the filter points into memory owned by the caller of this
        // function, the condition slice and the two wide buffers, and all of it outlives the
        // call. WFP copies what it needs.
        let status = unsafe { FwpmFilterAdd0(self.handle, &filter, None, Some(&mut filter_id)) };

        if status != 0 {
            bail!(
                "FwpmFilterAdd0 failed with 0x{status:08X} for {kind} '{name}' on layer {}",
                layer_index(layer),
            );
        }

        owners.insert(filter_id, name.to_owned());

        Ok(())
    }
}
