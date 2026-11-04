//! Which ALE authorization layer a rule belongs on, and the layer dependent condition fields.

use crate::wfp::*;

/// The four ALE authorization layers a rule is installed on: outbound connect and inbound accept,
/// for both address families.
pub(super) const LAYERS: [GUID; 4] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

/// The layers a rule is installed on.
///
/// A rule with no direction is installed on all four, which is what every rule did before the
/// dimension existed. Outbound is the connect layer of each address family, inbound the
/// recv-accept layer of each, mirroring where a connection is authorized in each direction.
///
/// A rule with a remote address is installed only on the layers of that address's family, because
/// a v4 address condition is refused on a v6 layer and could not match a v6 connection anyway.
pub(super) fn layers_for(direction: Option<Direction>, family: Option<Family>) -> Vec<GUID> {
    let layers = match direction {
        None => LAYERS.to_vec(),
        Some(Direction::Out) => vec![LAYERS[0], LAYERS[1]],
        Some(Direction::In) => vec![LAYERS[2], LAYERS[3]],
    };

    match family {
        None => layers,
        Some(family) => layers
            .into_iter()
            .filter(|layer| layer_family(*layer) == family)
            .collect(),
    }
}

/// Which family a layer belongs to.
pub(super) fn layer_family(layer: GUID) -> Family {
    if layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || layer == FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 {
        Family::V4
    } else {
        Family::V6
    }
}

/// The layers a rule is installed on, narrowed by its direction and by both of its addresses.
///
/// The remote field decides which families have a layer at all, and the local field narrows what
/// is left over to the families it names too. A rule whose two fields name no family in common
/// ends up on no layer at all, because no connection has ends of two families; a list that spans
/// both families is what makes a rule reach into both stacks.
pub(super) fn rule_layers(rule: &Rule) -> Vec<GUID> {
    layers_for(rule.direction, None)
        .into_iter()
        .filter(|layer| {
            rule.remote
                .as_ref()
                .is_none_or(|remote| remote.families().contains(&layer_family(*layer)))
                && rule
                    .local
                    .as_ref()
                    .is_none_or(|local| local.families().contains(&layer_family(*layer)))
        })
        .collect()
}

/// The condition that names the port a connection is about on a layer.
///
/// On an outbound layer the port the user means is the remote one, because that is where the
/// connection goes; on an inbound layer it is the local one. Picking one of the two for every layer
/// would make a port rule apply in only one direction, whatever its direction says.
pub(super) fn port_condition(layer: GUID) -> GUID {
    if layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4 || layer == FWPM_LAYER_ALE_AUTH_CONNECT_V6 {
        FWPM_CONDITION_IP_REMOTE_PORT
    } else {
        FWPM_CONDITION_IP_LOCAL_PORT
    }
}

/// Which of the four layers a GUID is, so an error message can name the position in `LAYERS`.
pub(super) fn layer_index(layer: GUID) -> usize {
    LAYERS
        .iter()
        .position(|candidate| *candidate == layer)
        .unwrap_or(LAYERS.len())
}
