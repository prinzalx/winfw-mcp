//! Tests for the rule model.
//!
//! The store is not involved here: these tests read and write rule data, nothing that needs
//! elevation.

use super::*;

use crate::rules::disk::parse_rule_file;

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
        assert!(rule.pattern.to_string().contains("C:\\test\\tool"));
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

    assert!(reaches(
        &wide,
        "C:\\Windows\\a.exe",
        inside,
        &crate::dns::Answers::default(),
    ));
    assert!(reaches(
        &wide,
        "C:\\Windows\\a.exe",
        outside,
        &crate::dns::Answers::default(),
    ));

    assert!(reaches(
        &narrow,
        "C:\\Windows\\a.exe",
        inside,
        &crate::dns::Answers::default(),
    ));
    assert!(!reaches(
        &narrow,
        "C:\\Windows\\a.exe",
        outside,
        &crate::dns::Answers::default(),
    ));

    // A rule about a different application decides nothing about this one.
    assert!(!reaches(
        &narrow,
        "C:\\other\\a.exe",
        inside,
        &crate::dns::Answers::default(),
    ));
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
fn a_temporary_rule_survives_a_round_trip_through_the_file() {
    let path = crate::testutil::scratch_dir("temporary").join("rules.toml");
    let mut temp = Rule::plain("temp", Action::Allow, "C:\\test\\tool1.exe");
    temp.temporary = true;

    let rules = RuleFile {
        rule: vec![
            temp,
            Rule::plain("kept", Action::Deny, "C:\\test\\tool2.exe"),
        ],
    };

    rules.save(&path).expect("save");

    assert_eq!(RuleFile::load_or_create(&path).expect("load"), rules);

    let text = std::fs::read_to_string(&path).expect("read back");

    assert_eq!(
        text.matches("temporary").count(),
        1,
        "only the rule that uses the field is written with it:\n{text}",
    );
}

#[test]
fn a_rule_written_before_the_field_existed_reads_as_not_temporary() {
    let text = r#"version = 1
checksum = "0000000000000000"

[[rule]]
name = "old"
action = "allow"
pattern = 'C:\\test\\tool1.exe'
enabled = true
"#;

    let (rules, _checksum) = parse_rule_file(text.as_bytes()).expect("an older file reads");

    assert!(!rules.rule[0].temporary);
}

#[test]
fn a_temporary_rule_is_pruned_when_its_program_is_not_running() {
    let mut temp = Rule::plain("gone", Action::Allow, "C:\\test\\tool1.exe");
    temp.temporary = true;

    let mut rules = RuleFile {
        rule: vec![
            temp,
            Rule::plain("keeper", Action::Deny, "C:\\test\\tool2.exe"),
        ],
    };

    assert_eq!(prune_temporary(&mut rules, &[]), ["gone".to_owned()]);
    assert_eq!(rules.rule.len(), 1);
}

#[test]
fn a_temporary_rule_with_a_running_program_is_kept() {
    let mut temp = Rule::plain("here", Action::Allow, "C:\\test\\tool?.exe");
    temp.temporary = true;

    let rules = RuleFile { rule: vec![temp] };

    assert!(
        expired_temporary(&rules, &["C:\\test\\tool1.exe".to_owned()]).is_empty(),
        "a wildcard program is still there when a process matches it",
    );
}

#[test]
fn a_permanent_rule_sharing_a_name_with_an_expired_one_is_not_pruned() {
    let mut temp = Rule::plain("same", Action::Allow, "C:\\test\\a.exe");
    temp.temporary = true;

    let mut rules = RuleFile {
        rule: vec![temp, Rule::plain("same", Action::Deny, "C:\\test\\b.exe")],
    };

    assert_eq!(prune_temporary(&mut rules, &[]), ["same".to_owned()]);
    assert_eq!(rules.rule.len(), 1);
    assert_eq!(rules.rule[0].action, Action::Deny);
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
    assert!(
        "0".parse::<PortRange>().is_err(),
        "zero is what WFP uses for no port"
    );
    assert!(
        "0-80".parse::<PortRange>().is_err(),
        "a range does not start at zero either"
    );
    assert!(
        "80-0".parse::<PortRange>().is_err(),
        "nor ends at it, whatever the order"
    );
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

/// An address field keeps the elements it was written with, in order, and refuses what a
/// single address refuses: an empty element, an element that is not an address, and one
/// element past the cap a wildcard pattern is capped at.
#[test]
fn an_address_field_holds_its_elements_or_refuses_them() {
    let list = "10.0.0.5, 192.168.1.0/24, 10.0.0.1-10.0.0.9"
        .parse::<Remotes>()
        .expect("parse a list of three");

    assert_eq!(
        list.elements()
            .iter()
            .map(|remote| remote.to_string())
            .collect::<Vec<String>>(),
        vec![
            "10.0.0.5".to_owned(),
            "192.168.1.0/24".to_owned(),
            "10.0.0.1-10.0.0.9".to_owned(),
        ],
    );

    // A field of one element is written back exactly as the single address was written
    // before lists existed.
    let one = "10.0.0.5".parse::<Remotes>().expect("parse a single");

    assert_eq!(one.elements().len(), 1);
    assert_eq!(one.to_string(), "10.0.0.5");

    for text in [
        "10.0.0.5,,10.0.0.9",
        "10.0.0.5, ,",
        "10.0.0.5, example.com",
        "",
        "  ",
    ] {
        assert!(text.parse::<Remotes>().is_err(), "refused: {text}");
    }

    let at_cap = (1..=MAX_WILDCARD_MATCHES)
        .map(|octet| format!("10.0.{octet}.5"))
        .collect::<Vec<String>>()
        .join(", ");

    assert_eq!(
        at_cap
            .parse::<Remotes>()
            .expect("a list at the cap")
            .elements()
            .len(),
        MAX_WILDCARD_MATCHES,
    );

    let over_cap = format!("{at_cap}, 10.0.99.5");
    assert!(
        over_cap.parse::<Remotes>().is_err(),
        "one element past the cap is refused: {over_cap}",
    );
}

/// The list contains an address whenever any of its elements does, and the families it is
/// written in are the distinct families of its elements: one family for a normal list, two
/// only for a list that really names both stacks.
#[test]
fn an_address_field_contains_any_of_its_elements() {
    let list = "10.0.0.0/24, 192.168.1.0/24"
        .parse::<Remotes>()
        .expect("parse a list of networks");

    assert!(list.contains("10.0.0.7".parse().expect("parse an address")));
    assert!(list.contains("192.168.1.7".parse().expect("parse an address")));
    assert!(!list.contains("172.16.0.7".parse().expect("parse an address")));
    assert_eq!(list.families(), vec![Family::V4]);

    // The union with `dest` is tested on the rule itself, where both fields meet.

    let mixed = "10.0.0.0/24, 2001:db8::/32"
        .parse::<Remotes>()
        .expect("parse a list of both families");

    assert_eq!(mixed.families(), vec![Family::V4, Family::V6]);
}

/// A list survives a write and a read of the rules file, and a file written before lists
/// existed reads back as a list of one element, which is what keeps an old file unchanged
/// when the tool writes it again.
#[test]
fn an_address_field_survives_a_round_trip() {
    let dir = crate::testutil::scratch_dir("address-round-trip");
    let path = dir.join("rules.toml");

    let written = RuleFile {
        rule: vec![Rule {
            remote: Some("10.0.0.5, 192.168.1.0/24".parse().expect("parse a list")),
            local: Some("fe80::/10".parse().expect("parse a single")),
            ..Rule::plain("address round trip", Action::Allow, "C:\\test\\tool1.exe")
        }],
    };

    written.save(&path).expect("write the rules file");

    let text = std::fs::read_to_string(&path).expect("read the rules file");

    assert!(
        text.contains("remote = \"10.0.0.5, 192.168.1.0/24\""),
        "the list is written as the text it was read from: {text}",
    );

    let read = RuleFile::load_or_create(&path).expect("read the rules file back");

    assert_eq!(read, written, "a list comes back as the same list");

    // The single value of a file from before lists is the same one-element rule.
    let old = text.replace(
        "remote = \"10.0.0.5, 192.168.1.0/24\"",
        "remote = \"10.0.0.5\"",
    );

    std::fs::write(&path, old).expect("write an old file");

    let read = RuleFile::load_or_create(&path).expect("read the old file");

    assert_eq!(
        read.rule[0]
            .remote
            .as_ref()
            .expect("the field is read")
            .elements()
            .len(),
        1,
        "a single address is a list of one",
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

/// A name list reads a single name and a comma-separated list, lowercases every element,
/// and refuses what is not a name: an empty element, an element with a wildcard, an element
/// with an empty label.
#[test]
fn a_name_field_reads_names_and_refuses_the_rest() {
    let list = "WWW.example.com, a.example"
        .parse::<Dests>()
        .expect("parse a name list");

    assert_eq!(
        list.names(),
        &["www.example.com".to_owned(), "a.example".to_owned()],
    );
    assert_eq!(list.to_string(), "www.example.com, a.example");

    for bad in ["", " ", "*.example.com", "a..b", "a,b,"] {
        assert!(bad.parse::<Dests>().is_err(), "'{bad}' is not a name list");
    }
}

/// A name is held once whatever the field writes it as, and the cap is spent over the
/// elements the field writes rather than over the names that survive the deduplication.
#[test]
fn a_name_field_drops_duplicates_and_caps_the_written_elements() {
    let list = "a.com, b.com, A.COM"
        .parse::<Dests>()
        .expect("parse a name list");

    assert_eq!(list.names(), &["a.com".to_owned(), "b.com".to_owned()]);

    let mut written: Vec<String> = (0..MAX_WILDCARD_MATCHES)
        .map(|index| format!("host{index}.example"))
        .collect();

    assert!(written.join(", ").parse::<Dests>().is_ok(), "at the cap");

    written.push("host0.example".to_owned());

    assert!(
        written.join(", ").parse::<Dests>().is_err(),
        "one name too many over the elements the field writes, duplicate or not"
    );
}

/// `remote` and `dest` are a union: an address matches when the address field names it or
/// when a name was answered with it, and a name nothing answered for adds nothing.
#[test]
fn a_destination_is_a_union_of_addresses_and_answers() {
    let rule = Rule {
        remote: Some("10.0.0.0/24".parse().expect("parse a network")),
        dest: Some("www.example.com".parse().expect("parse a name")),
        ..Rule::plain("union", Action::Allow, "C:\\a.exe")
    };

    let answered = "93.184.216.34".parse().expect("parse an address");
    let answers = crate::dns::Answers::from_pairs(&[(
        "www.example.com",
        &["93.184.216.34"
            .parse::<std::net::IpAddr>()
            .expect("parse an address")][..],
    )]);

    assert!(rule.reaches("10.0.0.5".parse().expect("parse an address"), &answers));
    assert!(rule.reaches(answered, &answers));
    assert!(!rule.reaches("93.184.216.35".parse().expect("parse an address"), &answers));

    // Without an answer the same rule knows only its address half.
    assert!(!rule.reaches(answered, &crate::dns::Answers::default()));
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
        "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"C:\\\\a.exe\"\nport = \"http\"\n",
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
        "[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"C:\\\\a.exe\"\n{field}\n"
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

/// One rule can name a handful of applications, which is what keeps the action, the ports and
/// the addresses from being written once per program.
#[test]
fn a_pattern_field_can_name_a_list_of_applications() {
    let patterns: Patterns = "C:\\test\\tool1.exe, C:\\test\\tool2.exe"
        .parse()
        .expect("parse a list of applications");

    assert_eq!(patterns.elements().len(), 2);
    assert_eq!(
        patterns.to_string(),
        "C:\\test\\tool1.exe, C:\\test\\tool2.exe",
        "the field is written back the way it was read"
    );
    assert!(patterns.matches("C:\\test\\tool2.exe"));
    assert!(!patterns.matches("C:\\test\\tool3.exe"));
    assert!(!patterns.has_wildcard(), "neither element needs matching");
}

/// A list of one is written back exactly as a single path was written before lists existed,
/// which is what lets a file of an older version read back and be saved again unchanged.
#[test]
fn a_pattern_field_of_one_element_keeps_the_old_text() {
    let patterns: Patterns = "C:\\test\\tool1.exe".parse().expect("parse one path");

    assert_eq!(patterns.to_string(), "C:\\test\\tool1.exe");
    assert_eq!(
        patterns, "C:\\test\\tool1.exe",
        "the field is that one path"
    );
    assert_ne!(
        patterns, "C:\\test\\tool2.exe",
        "and not any other single path"
    );
}

/// The field is written as text and read back as elements, so a file that names several
/// applications in one rule stays ordinary TOML a person can edit by hand.
#[test]
fn a_pattern_list_survives_a_round_trip_through_the_file() {
    let path = crate::testutil::scratch_dir("rules-pattern-list").join("rules.toml");
    let rules = RuleFile {
        rule: vec![Rule::plain(
            "browsers",
            Action::Allow,
            "C:\\Program Files\\*\\firefox.exe, C:\\Program Files\\*\\waterfox.exe",
        )],
    };

    rules.save(&path).expect("save");

    let text = std::fs::read_to_string(&path).expect("read");

    // TOML writes a path with no escape of its own as a literal string, which is the shape a
    // person editing the file by hand would write.
    assert!(
        text.contains(
            "pattern = 'C:\\Program Files\\*\\firefox.exe, C:\\Program Files\\*\\waterfox.exe'"
        ),
        "{text}"
    );
    assert_eq!(
        RuleFile::load_or_create(&path).expect("load"),
        rules,
        "the list reads back as the field it was"
    );
}

/// A path may hold a comma on Windows, and the split then cuts it in two. The second half is
/// no absolute path, so the field is refused out loud rather than installed as a rule that
/// silently matches half of what it names.
#[test]
fn a_pattern_that_holds_a_comma_is_refused_loudly() {
    let err = "C:\\a,b\\tool.exe"
        .parse::<Patterns>()
        .expect_err("the comma cuts the path in two");

    assert!(
        err.contains("absolute path"),
        "the reason names the shape, not the comma: {err}"
    );
}

/// The same bounds the other list fields hold themselves: an element that names nothing is
/// refused, and so is a field longer than the store can carry.
#[test]
fn a_pattern_list_refuses_an_empty_element_and_a_long_list() {
    assert!("C:\\a.exe,,C:\\b.exe".parse::<Patterns>().is_err());
    assert!(
        " ".parse::<Patterns>().is_err(),
        "nothing names no application"
    );

    let within = (0..MAX_WILDCARD_MATCHES)
        .map(|index| format!("C:\\test\\app{index}.exe"))
        .collect::<Vec<String>>()
        .join(", ");
    let over = format!("{within}, C:\\test\\one.exe");

    assert!(
        within.parse::<Patterns>().is_ok(),
        "{MAX_WILDCARD_MATCHES} elements fit"
    );
    assert!(
        over.parse::<Patterns>().is_err(),
        "one more than the bound is refused"
    );
}

/// A wildcard in any element makes the field one that has to be expanded, which is the
/// question the monitor asks before it rebuilds the filters for a newly seen application.
#[test]
fn any_wildcard_element_makes_the_field_a_pattern() {
    let mixed: Patterns = "C:\\test\\tool1.exe, C:\\Windows\\*.exe"
        .parse()
        .expect("parse a mixed field");

    assert!(mixed.has_wildcard());
    assert!(mixed.matches("C:\\Windows\\notepad.exe"));
    assert!(!mixed.matches("C:\\other\\notepad.exe"));
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

    let plain: RuleFile =
        toml::from_str("[[rule]]\nname = \"x\"\naction = \"allow\"\npattern = \"C:\\\\a.exe\"\n")
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
    let shared = crate::export::decode(&crate::export::encode(&sample().rule[0]).expect("encode"))
        .expect("decode");

    let text = shared.pattern.to_string();

    assert!(
        text.parse::<Patterns>().is_ok(),
        "{text} should read back as a field the store accepts"
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

/// The service field reads one name and a list, and writes itself back in the shape the file
/// taught the other list fields.
#[test]
fn services_read_one_name_and_a_list() {
    let one: Services = "Dnscache".parse().expect("one name");

    assert_eq!(one.names(), ["Dnscache"]);

    let list: Services = "Dnscache, Dhcp".parse().expect("a list");

    assert_eq!(list.names(), ["Dnscache", "Dhcp"]);
    assert_eq!(list.to_string(), "Dnscache, Dhcp");
}

#[test]
fn services_refuse_an_empty_field_and_a_name_that_cannot_be_one() {
    let empty = "  ".parse::<Services>().expect_err("blanks are no service");

    assert_eq!(empty, "a rule needs a service");

    let element = "Dnscache,"
        .parse::<Services>()
        .expect_err("a dangling comma");

    assert!(element.contains("empty element"), "{element}");

    let chars = "Dnscac he"
        .parse::<Services>()
        .expect_err("a space is not a name");

    assert!(chars.contains("is not a service name"), "{chars}");
}
