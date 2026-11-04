use super::*;
use crate::rules::{Cidr, Protocol};
use crate::wfp::app_id::*;
use crate::wfp::keys::*;
use crate::wfp::layers::*;

/// A path that exists on every Windows install, so the application-id resolution succeeds.
const TEST_APP: &str = r"C:\Windows\System32\notepad.exe";

/// The text of an application field, read as the rule file reads it.
fn patterns(text: &str) -> crate::rules::Patterns {
    text.parse().expect("parse the application field")
}

/// Start a write test from a clean store, or say the test is skipped.
///
/// A process without the rights to write the store is the normal reason a WFP test cannot
/// run here, and skipping it beats failing it; anything but "access denied" (0x00000005)
/// is a real failure and stays an assertion.
fn clean_store_or_skip(engine: &Engine) -> bool {
    match engine.clear() {
        Ok(leftovers) => {
            println!("cleared {leftovers} leftover filters");
            true
        }
        Err(error) => {
            let reason = format!("{error:#}");
            assert!(reason.contains("0x00000005"), "unexpected failure {reason}");
            println!("write path skipped, access denied");
            false
        }
    }
}

/// A rule with no direction is installed everywhere, and each direction picks the two layers
/// where its connections are authorized.
#[test]
fn a_direction_narrows_the_layers_a_rule_is_installed_on() {
    assert_eq!(layers_for(None, None).len(), LAYERS.len());
    assert_eq!(
        layers_for(Some(Direction::Out), None),
        vec![LAYERS[0], LAYERS[1]]
    );
    assert_eq!(
        layers_for(Some(Direction::In), None),
        vec![LAYERS[2], LAYERS[3]]
    );
}

/// An address of one family cannot match on a layer of the other, so a rule with a remote
/// address is only installed on the layers it could ever fire on. The two families together
/// are exactly the layers the rule would be installed on without an address.
#[test]
fn a_remote_address_narrows_the_layers_to_its_family() {
    let v4: Cidr = "192.168.1.0/24".parse().expect("parse a v4 network");
    let v6: Cidr = "fe80::/10".parse().expect("parse a v6 network");

    assert_eq!(
        layers_for(None, Some(v4.family)),
        vec![LAYERS[0], LAYERS[2]]
    );
    assert_eq!(
        layers_for(None, Some(v6.family)),
        vec![LAYERS[1], LAYERS[3]]
    );
    assert_eq!(
        layers_for(Some(Direction::In), Some(v4.family)),
        vec![LAYERS[2]]
    );
    assert_eq!(
        layers_for(Some(Direction::Out), Some(v6.family)),
        vec![LAYERS[1]]
    );

    // Both families together are the unaddressed case again, so nothing is lost.
    let mut both = layers_for(None, Some(v4.family));
    both.extend(layers_for(None, Some(v6.family)));
    assert_eq!(both.len(), LAYERS.len());
}

/// A local address narrows the layers exactly like a remote one does, and the two of them have
/// to agree on a family: a rule about a v4 destination behind a v6 interface can match no
/// connection, so it is installed on no layer at all.
#[test]
fn a_local_address_narrows_the_layers_to_its_family() {
    let v4: Cidr = "192.168.1.0/24".parse().expect("parse a v4 network");
    let v6: Cidr = "fe80::/10".parse().expect("parse a v6 network");

    let layers_of = |remote: Option<Cidr>, local: Option<Cidr>| {
        rule_layers(&Rule {
            remote: remote.map(|cidr| Remotes::from(Remote::Network(cidr))),
            local: local.map(|cidr| Remotes::from(Remote::Network(cidr))),
            ..Rule::plain("local layer test", Action::Deny, TEST_APP)
        })
    };

    assert_eq!(layers_of(None, Some(v4)), vec![LAYERS[0], LAYERS[2]]);
    assert_eq!(layers_of(None, Some(v6)), vec![LAYERS[1], LAYERS[3]]);
    assert_eq!(layers_of(Some(v4), Some(v4)), vec![LAYERS[0], LAYERS[2]]);
    assert_eq!(
        layers_of(Some(v4), Some(v6)),
        Vec::<GUID>::new(),
        "an address of each family matches nothing",
    );
}

/// A field that names addresses of both families reaches the layers of both, which is the
/// difference a list makes over a single address: the rule of one family is installed on one
/// stack, the rule of a list that spans both is installed on both.
#[test]
fn an_address_list_reaches_the_layers_of_every_family_it_names() {
    let both: Remotes = "192.168.1.0/24, fe80::/10"
        .parse()
        .expect("parse a list of both families");
    let layers = rule_layers(&Rule {
        remote: Some(both.clone()),
        local: None,
        ..Rule::plain("list layer test", Action::Deny, TEST_APP)
    });

    assert_eq!(
        layers,
        vec![LAYERS[0], LAYERS[1], LAYERS[2], LAYERS[3]],
        "a list of both families has a layer in each stack",
    );

    // The local field narrows what the remote field opened, exactly as a single address did.
    let v4: Remotes = "192.168.1.0/24".parse().expect("parse a v4 network");
    let narrowed = rule_layers(&Rule {
        remote: Some(both),
        local: Some(v4),
        ..Rule::plain("list layer test", Action::Deny, TEST_APP)
    });

    assert_eq!(
        narrowed,
        vec![LAYERS[0], LAYERS[2]],
        "a local address of one family keeps the v4 layers",
    );
}

/// A broad pattern is capped: the store gets the applications up to the limit. Without the cap
/// one careless `*` turns into thousands of filters in a store that is shared with everything
/// else on the machine.
#[test]
fn a_wildcard_pattern_is_expanded_up_to_the_cap() {
    let known: Vec<String> = (0..MAX_WILDCARD_MATCHES + 8)
        .map(|index| crate::device::to_device_path(&format!("C:\\test\\app{index}.exe")))
        .collect();

    assert_eq!(
        app_ids(&patterns("C:\\test\\*.exe"), &known).apps.len(),
        MAX_WILDCARD_MATCHES,
        "the cap holds the expansion down",
    );
}

/// The cap is not silent any more. The expansion carries the number of matches next to the
/// number of applications it hands out, so a pattern over the limit reports itself as
/// truncated and a pattern within the limit does not.
#[test]
fn a_pattern_over_the_cap_reports_its_truncation() {
    let known: Vec<String> = (0..MAX_WILDCARD_MATCHES + 8)
        .map(|index| crate::device::to_device_path(&format!("C:\\test\\app{index}.exe")))
        .collect();

    let over = app_ids(&patterns("C:\\test\\*.exe"), &known);
    assert_eq!(
        over.matches,
        MAX_WILDCARD_MATCHES + 8,
        "all matches are counted"
    );
    assert!(over.truncated(), "a pattern over the cap is truncated");

    let within = app_ids(
        &patterns("C:\\test\\app*.exe"),
        &known[..MAX_WILDCARD_MATCHES],
    );
    assert_eq!(
        within.matches, MAX_WILDCARD_MATCHES,
        "the matches within the cap"
    );
    assert!(!within.truncated(), "a pattern at the cap is not truncated");

    let exact = app_ids(&patterns("C:\\test\\app0.exe"), &known[..4]);
    assert!(!exact.truncated(), "an exact pattern is never truncated");

    assert_eq!(
        pattern_reach(&patterns("C:\\test\\*.exe"), &known),
        (MAX_WILDCARD_MATCHES + 8, MAX_WILDCARD_MATCHES),
        "the state view reports the same numbers",
    );
    assert_eq!(
        pattern_reach(
            &patterns("C:\\test\\app*.exe"),
            &known[..MAX_WILDCARD_MATCHES]
        ),
        (MAX_WILDCARD_MATCHES, MAX_WILDCARD_MATCHES),
        "a pattern at the cap is not truncated in the state view either",
    );
    assert_eq!(
        pattern_reach(&patterns("C:\\test\\app0.exe"), &known),
        (1, 1),
        "an exact pattern reaches exactly itself",
    );
}

/// The bound is spent over the whole field rather than per element. A field of applications
/// multiplies with the ports and the addresses of the rule, and every application costs a
/// filter per layer in a store that is shared with everything else on the machine.
#[test]
fn the_bound_is_spent_over_the_whole_field() {
    let known: Vec<String> = (0..MAX_WILDCARD_MATCHES + 8)
        .map(|index| crate::device::to_device_path(&format!("C:\\test\\app{index}.exe")))
        .collect();

    // Two elements that both reach the whole set, written as one field.
    let expansion = app_ids(&patterns("C:\\test\\*.exe, C:\\test\\app?.exe"), &known);

    assert_eq!(
        expansion.installed(),
        MAX_WILDCARD_MATCHES,
        "the second element adds nothing once the field has used the bound"
    );
    assert!(expansion.truncated(), "and says so");

    assert_eq!(
        pattern_reach(&patterns("C:\\test\\*.exe, C:\\test\\app?.exe"), &known),
        ((MAX_WILDCARD_MATCHES + 8) + 10, MAX_WILDCARD_MATCHES),
        "the state view counts the same numbers",
    );
}

/// An exact path and a wildcard share one field, and the exact application is not the one
/// that falls off the end when the bound is reached.
#[test]
fn an_exact_path_and_a_wildcard_share_one_field() {
    let known = vec![crate::device::to_device_path("C:\\test\\app0.exe")];

    let expansion = app_ids(&patterns("C:\\other\\tool.exe, C:\\test\\*.exe"), &known);

    assert_eq!(
        expansion.installed(),
        2,
        "both elements get their application"
    );
    assert!(!expansion.truncated());
}

/// Two applications in one field are two sets of filters, and the key of the second must not
/// be the key of the first, or the store would hold one of them.
#[test]
fn two_applications_in_one_field_get_keys_of_their_own() {
    let apps = app_ids(&patterns("C:\\test\\tool1.exe, C:\\test\\tool2.exe"), &[]).apps;

    assert_eq!(apps.len(), 2, "one application per element");

    let mut keys = Vec::new();

    for index in 0..apps.len() {
        let key = filter_key(&format!("list#{index}"), &FWPM_LAYER_ALE_AUTH_CONNECT_V4);

        assert!(!keys.contains(&key), "one key per application");
        keys.push(key);
    }
}

/// An exact path has nothing to expand, so the applications this tool has seen are not looked
/// at — which is what lets a rule for one file install one filter set rather than a search.
#[test]
fn an_exact_pattern_ignores_the_applications_that_have_been_seen() {
    let known: Vec<String> = (0..4)
        .map(|index| crate::device::to_device_path(&format!("C:\\other\\app{index}.exe")))
        .collect();

    assert_eq!(app_ids(&patterns(TEST_APP), &known).apps.len(), 1);
}

/// A wildcard that has matched nothing so far still goes into the store as its own text. The
/// alternative is a rule that is installed as nothing at all, which the user cannot see in the
/// store and cannot explain.
#[test]
fn a_wildcard_that_matches_nothing_seen_yet_still_installs_its_pattern() {
    assert_eq!(app_ids(&patterns("C:\\test\\*.exe"), &[]).apps.len(), 1);
}

/// The port a user means is the remote one on the way out and the local one on the way in.
#[test]
fn a_port_is_matched_on_the_side_the_connection_is_about() {
    assert_eq!(
        port_condition(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
        FWPM_CONDITION_IP_REMOTE_PORT
    );
    assert_eq!(
        port_condition(FWPM_LAYER_ALE_AUTH_CONNECT_V6),
        FWPM_CONDITION_IP_REMOTE_PORT
    );
    assert_eq!(
        port_condition(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4),
        FWPM_CONDITION_IP_LOCAL_PORT
    );
    assert_eq!(
        port_condition(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6),
        FWPM_CONDITION_IP_LOCAL_PORT
    );
}

/// Read the live store, and assert on whatever we are allowed to read.
///
/// Measured on this machine: an unelevated process opens the engine without problem but every
/// enumeration answers `0x00000005`, so reading the store needs elevation just like writing it
/// does. A run that is allowed to read must see entries, which is the case the assertions
/// cover; a run that is refused reports it and is visible with `--nocapture`.
#[test]
fn the_live_store_reads_or_reports_access_denied() {
    let engine = Engine::open().expect("open engine");

    for (category, entries) in [
        ("providers", engine.providers()),
        ("sublayers", engine.sublayers()),
        ("filters", engine.filters()),
    ] {
        match entries {
            Ok(names) => {
                assert!(!names.is_empty(), "{category}: Windows always has entries");
                println!("{category}: read {} entries", names.len());
            }
            Err(error) => {
                let reason = format!("{error:#}");
                assert!(
                    reason.contains("0x00000005"),
                    "{category}: unexpected failure {reason}",
                );
                println!("{category}: skipped, access denied");
            }
        }
    }
}

/// The write path is exercised against the live store, because that is the only place it has
/// to work. Whatever it installs, it removes again before returning.
#[test]
fn a_rule_is_installed_and_removed_from_the_live_store() {
    let engine = Engine::open().expect("open engine");

    let rules = RuleFile {
        rule: vec![
            Rule::plain("winfw-mcp write test", Action::Deny, TEST_APP),
            Rule::plain("winfw-mcp write test allow", Action::Allow, TEST_APP),
        ],
    };

    // Both actions have to be installed, because they differ in more than their name.
    let expected = rules.rule.len() * LAYERS.len();

    // Start from a clean store, so a count of zero means what it says.
    if !clean_store_or_skip(&engine) {
        return;
    }

    let applied = engine
        .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
        .expect("apply the rule");

    assert_eq!(applied.installed, expected, "one filter per rule and layer");
    assert_eq!(applied.removed, 0, "the store was cleared first");

    let rebuilt = engine
        .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
        .expect("apply the same rule again");

    assert_eq!(
        rebuilt.removed, expected,
        "a rebuild must remove exactly what the run before installed"
    );

    let cleared = engine.clear().expect("clear the store");

    assert_eq!(
        cleared, expected,
        "clearing removes every filter we installed"
    );
}

/// A rule narrowed by protocol, direction and a port is installed on the two layers of its
/// direction alone, and the store accepts the conditions it carries. Both port encodings are
/// exercised: a single port is matched exactly, a range needs the range type. The conditions
/// are the point here — one WFP could not read would fail this test rather than quietly widen
/// the rule to every port.
#[test]
fn a_narrowed_rule_is_installed_on_its_direction_alone() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    for port in ["443", "1024-2048"] {
        let rules = RuleFile {
            rule: vec![Rule {
                protocol: Some(Protocol::Tcp),
                direction: Some(Direction::Out),
                port: Some(port.parse().expect("parse a port")),
                ..Rule::plain("winfw-mcp narrow test", Action::Allow, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
            .expect("apply the narrowed rule");

        assert_eq!(
            applied.installed, 2,
            "port '{port}': outbound is the connect layer of both address families, not four",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(
            cleared, 2,
            "port '{port}': a narrowed rule leaves nothing on the other layers",
        );
    }
}

/// A port list is installed as one filter per element, on each layer the rule reaches: a
/// range cannot ride in one condition beside the single ports, so the list multiplies the
/// filters rather than the conditions. The store accepting every variant is the assertion
/// that the pointers into the per-element ranges were well formed.
#[test]
fn a_port_list_is_installed_as_one_filter_per_element() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    for (ports, expected) in [("443", 2usize), ("80, 443", 4), ("80, 1024-2048", 4)] {
        let rules = RuleFile {
            rule: vec![Rule {
                direction: Some(Direction::Out),
                port: Some(ports.parse().expect("parse a port field")),
                ..Rule::plain("winfw-mcp port list test", Action::Allow, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
            .expect("apply the listed rule");

        assert_eq!(
            applied.installed, expected,
            "port '{ports}': one filter per element on the two layers of the direction",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(cleared, expected, "port '{ports}': nothing is left behind");
    }
}

/// An address field with more than one element is installed as one filter per element, the
/// same way a port list is. A list that names both families is installed in both stacks, one
/// element per filter there too, which is what the two-layer counts of the mixed case show.
#[test]
fn an_address_list_is_installed_as_one_filter_per_element() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    for (addresses, expected) in [
        ("10.0.0.5", 1usize),
        ("10.0.0.5, 10.0.0.9", 2),
        ("10.0.0.5, 10.0.0.9, 192.168.1.0/24", 3),
        ("10.0.0.5, 2001:db8::1", 2),
    ] {
        let rules = RuleFile {
            rule: vec![Rule {
                direction: Some(Direction::Out),
                remote: Some(addresses.parse().expect("parse an address field")),
                ..Rule::plain("winfw-mcp address list test", Action::Allow, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
            .expect("apply the listed rule");

        assert_eq!(
            applied.installed, expected,
            "addresses '{addresses}': one filter per element of the field",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(
            cleared, expected,
            "addresses '{addresses}': nothing is left behind"
        );
    }
}

/// A remote address is installed as a real condition on the layers of its family only. This
/// is what exercises the pointer WFP keeps to the address-and-mask struct, which is the same
/// trap the port range is: an `Option` there is a pointer to the wrong thing.
#[test]
fn a_remote_address_is_installed_on_the_layers_of_its_family() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    for address in [
        "192.168.1.0/24",
        "10.0.0.5",
        "fe80::/10",
        "2001:db8::1/64",
        "192.168.1.10-192.168.1.20",
        "2001:db8::1-2001:db8::ff",
    ] {
        let rules = RuleFile {
            rule: vec![Rule {
                remote: Some(address.parse().expect("parse an address")),
                ..Rule::plain("winfw-mcp address test", Action::Deny, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
            .expect("apply the addressed rule");

        assert_eq!(
            applied.installed, 2,
            "'{address}': an address narrows four layers to the two of its family",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(cleared, 2, "'{address}': nothing is left behind");
    }
}

/// A local address is installed as a real condition on the layers of its family only, exactly
/// like the remote one, and it keeps a pointer of its own to an address-and-mask struct. A rule
/// that names both ends carries both conditions on one filter, so a filter the store accepts
/// there is the assertion that both of them were well formed.
#[test]
fn a_local_address_is_installed_on_the_layers_of_its_family() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    for address in [
        "192.168.1.0/24",
        "10.0.0.5",
        "fe80::/10",
        "2001:db8::1/64",
        "192.168.1.10-192.168.1.20",
        "2001:db8::1-2001:db8::ff",
    ] {
        let rules = RuleFile {
            rule: vec![Rule {
                local: Some(address.parse().expect("parse an address")),
                ..Rule::plain("winfw-mcp local test", Action::Deny, TEST_APP)
            }],
        };

        let applied = engine
            .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
            .expect("apply the locally addressed rule");

        assert_eq!(
            applied.installed, 2,
            "'{address}': an address narrows four layers to the two of its family",
        );

        let cleared = engine.clear().expect("clear the store");

        assert_eq!(cleared, 2, "'{address}': nothing is left behind");
    }

    let rules = RuleFile {
        rule: vec![Rule {
            remote: Some("192.168.1.0/24".parse().expect("parse a network")),
            local: Some("10.0.0.1-10.0.0.9".parse().expect("parse a span")),
            ..Rule::plain("winfw-mcp both ends test", Action::Deny, TEST_APP)
        }],
    };

    let applied = engine
        .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
        .expect("apply a rule naming both ends");

    assert_eq!(
        applied.installed, 2,
        "two addresses of one family narrow four layers to the same two",
    );

    let cleared = engine.clear().expect("clear the store");

    assert_eq!(cleared, 2, "nothing is left behind");
}

/// The default-deny policy adds the base filters on top of the rules: a loopback permit on
/// each of the four authorization layers, one 6to4 permit, one permit per ICMPv6 type the
/// IPv6 stack needs, and one unconditional block per layer. All of them carry our provider
/// key, so `clear` takes them out again exactly like a rule filter.
#[test]
fn the_default_deny_policy_installs_the_base_filters() {
    const BASE_FILTERS: usize = 4 + 1 + 4 + 4;

    let engine = Engine::open().expect("open engine");

    // Start from a clean store, so a count of zero means what it says.
    if !clean_store_or_skip(&engine) {
        return;
    }

    let applied = engine
        .apply(
            &RuleFile::default(),
            &[],
            &crate::dns::Answers::default(),
            Policy::Deny,
        )
        .expect("apply the base filters");

    assert_eq!(
        applied.installed, BASE_FILTERS,
        "four loopback permits, one 6to4, four ICMPv6, four blocks"
    );

    let cleared = engine.clear().expect("clear the store");

    assert_eq!(cleared, BASE_FILTERS, "clearing removes the base filters");
}

/// Every filter `apply` installs is accounted for in the table it hands back, so an event
/// naming one of those ids can be read back as the rule it came from. Ids are never zero, the
/// value the monitor reads as "no filter was named".
#[test]
fn apply_accounts_for_every_filter_it_installs() {
    let engine = Engine::open().expect("open engine");

    if !clean_store_or_skip(&engine) {
        return;
    }

    let rules = RuleFile {
        rule: vec![Rule::plain(
            "winfw-mcp attribution test",
            Action::Deny,
            TEST_APP,
        )],
    };

    let applied = engine
        .apply(&rules, &[], &crate::dns::Answers::default(), Policy::Allow)
        .expect("apply the rule");

    // One table entry per installed filter: nothing we put in the store is unaccounted for.
    assert_eq!(
        applied.owners.len(),
        applied.installed,
        "every installed filter is in the table",
    );
    assert!(
        applied.owners.keys().all(|id| *id != 0),
        "WFP never hands out id 0, which the monitor uses as the sentinel",
    );
    assert!(
        applied
            .owners
            .values()
            .all(|name| name == "winfw-mcp attribution test"),
        "a table entry names the rule its filter came from",
    );

    engine.clear().expect("clear the store");
}

/// A filter key has to survive a restart, and a rule installed on several layers needs a
/// distinct key per layer.
#[test]
fn a_filter_key_is_stable_and_distinct_per_rule_and_layer() {
    assert_eq!(
        filter_key("browser", &LAYERS[0]),
        filter_key("browser", &LAYERS[0])
    );
    assert_ne!(
        filter_key("browser", &LAYERS[0]),
        filter_key("browser", &LAYERS[1])
    );
    assert_ne!(filter_key("one", &LAYERS[0]), filter_key("two", &LAYERS[0]));
}

/// A handle that was never opened must not be handed to `FwpmEngineClose0`.
#[test]
fn a_default_handle_counts_as_invalid() {
    assert!(HANDLE::default().is_invalid());
}

/// A deny has to win over an allow no matter where the two rules sit in the file, and inside
/// the engine that is decided by filter weight rather than by rule order.
#[test]
fn a_deny_rule_outranks_an_allow_rule() {
    assert!(WEIGHT_DENY > WEIGHT_ALLOW);
}

/// The retry loop is the whole of the boot-time policy, so it is tested without an engine:
/// an attempt that fails twice and succeeds must be reached over exactly the two waits that
/// precede it, with no sleep before the first try and none after the successful one.
#[test]
fn opening_waits_between_attempts_but_not_around_them() {
    let waits = [
        Duration::from_millis(1),
        Duration::from_millis(2),
        Duration::from_millis(3),
    ];
    let mut slept = Vec::new();
    let mut calls = 0;

    let outcome = retry_open(
        &waits,
        || {
            calls += 1;

            if calls < 3 {
                bail!("not yet {calls}");
            }

            Ok(calls)
        },
        |wait| slept.push(wait),
    );

    assert_eq!(outcome.expect("the third attempt is reached"), 3);
    assert_eq!(
        slept,
        vec![waits[0], waits[1]],
        "waits only between attempts"
    );
}

/// The other half: an attempt that never succeeds must stop after the last wait and hand
/// back its last error rather than spin forever — a machine whose firewall service is
/// disabled should be slow to start, not started slowly.
#[test]
fn opening_gives_up_after_the_last_wait() {
    let waits = [Duration::from_millis(1), Duration::from_millis(2)];
    let mut slept = Vec::new();
    let mut calls = 0;

    let outcome: Result<u32> = retry_open(
        &waits,
        || {
            calls += 1;
            bail!("never")
        },
        |wait| slept.push(wait),
    );

    assert_eq!(outcome.expect_err("all attempts fail").to_string(), "never");
    assert_eq!(calls, 3, "one attempt before the waits and one per wait");
    assert_eq!(slept, vec![waits[0], waits[1]]);
}

/// The waits are boot policy, not a mood: ascending, and short enough that a machine whose
/// engine never comes up still shows its page within seconds.
#[test]
fn the_open_waits_add_up_to_seconds_not_minutes() {
    assert!(
        OPEN_WAITS.windows(2).all(|pair| pair[0] <= pair[1]),
        "later attempts get more room, not less",
    );

    let total: Duration = OPEN_WAITS.iter().copied().sum();

    assert!(total < Duration::from_secs(10), "got {total:?}");
}
