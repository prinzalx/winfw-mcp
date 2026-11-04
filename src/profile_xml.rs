//! Reading a profile written by the C original.
//!
//! The profile format of the reference stores its rules as XML, and its vocabulary is wider than
//! this tool's: an item
//! can name several applications, several ports and several addresses at once, it can speak about
//! a service instead of a path, and it carries fields this tool has no place for (a rule class, an
//! OS version gate, a per-application comment). The reference has no importer at all, so there is
//! no existing translation to copy; what follows is stated in full here.
//!
//! The mapping is deliberately narrow and never silent. What this tool cannot express is named in
//! the comment of the rule it came from, or in [`Import::notes`] when no rule came from it at all.

use anyhow::{Context, Result};
use quick_xml::Reader;
use quick_xml::events::Event;

use crate::rules::{Action, Direction, Protocol, Remote, Rule, RuleFile, validate_comment};

/// What reading a profile produced: the rules this tool can use, and one sentence per part of the
/// profile it could not turn into a rule.
#[derive(Debug, Default)]
pub struct Import {
    pub rules: RuleFile,
    /// One sentence each for the items that produced no rule, and for the parts of an item that
    /// were left out. In document order.
    pub notes: Vec<String>,
}

/// Read the XML text of an exported profile.
///
/// The items of `rules_custom` and `rules_system` are read, in document order; those are the two
/// sections that hold rules. Every other section is left alone: `rules_config` only records which
/// built-in rules are switched on, and `rules_blocklist` is a list of addresses rather than rules
/// of the same shape, and the `apps` list holds per-application notes.
pub fn parse(text: &str) -> Result<Import> {
    let mut reader = Reader::from_str(text);
    let mut import = Import::default();
    let mut section = Section::None;

    loop {
        let event = reader.read_event().context("read the profile XML")?;

        match event {
            Event::Eof => break,
            Event::Start(start) => {
                let name = start.name();

                if name.as_ref() == "rules_custom" || name.as_ref() == "rules_system" {
                    section = Section::Rules;
                } else if name.as_ref() == "item" && matches!(section, Section::Rules) {
                    // An item with children is unusual but legal; its attributes are still the
                    // whole of what matters, so whatever follows them is skipped.
                    let item = read_attributes(&start)?;

                    loop {
                        let inner = reader.read_event().context("skip to the end of the item")?;

                        if matches!(&inner, Event::End(end) if end.name().as_ref() == "item")
                            || matches!(inner, Event::Eof)
                        {
                            break;
                        }
                    }

                    one(&item, &mut import);
                }
            }
            Event::Empty(empty) if empty.name().as_ref() == "item" => {
                if matches!(section, Section::Rules) {
                    let item = read_attributes(&empty)?;

                    one(&item, &mut import);
                }
            }
            Event::End(end) => {
                let name = end.name();

                // The two sections are siblings, and a section that has ended must not lend its
                // name to the items of the section that follows it.
                if name.as_ref() == "rules_custom" || name.as_ref() == "rules_system" {
                    section = Section::None;
                }
            }
            _ => {}
        }
    }

    Ok(import)
}

/// Which section the reader is inside. Only the two rule sections are of interest, and inside them
/// there is nothing left to tell apart.
#[derive(Debug, Default, PartialEq, Eq)]
enum Section {
    #[default]
    None,
    Rules,
}

/// The attributes of one `item`, as text. Only the names the mapping uses are kept.
#[derive(Debug, Default)]
struct Item {
    name: String,
    apps: String,
    rule: String,
    rule_local: String,
    comment: String,
    dir: String,
    protocol: String,
    is_block: String,
    is_enabled: String,
    is_services: String,
    is_kernel: String,
    os_version: String,
    address_family: String,
}

fn read_attributes(element: &quick_xml::events::BytesStart<'_>) -> Result<Item> {
    let mut item = Item::default();

    for attribute in element.attributes() {
        let attribute = attribute.context("read an attribute of an item")?;
        let value = attribute
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .context("unescape an attribute of an item")?;

        match attribute.key.as_ref() {
            "name" => item.name = value.into_owned(),
            "apps" => item.apps = value.into_owned(),
            "rule" => item.rule = value.into_owned(),
            "rule_local" => item.rule_local = value.into_owned(),
            "comment" => item.comment = value.into_owned(),
            "dir" => item.dir = value.into_owned(),
            "protocol" => item.protocol = value.into_owned(),
            "is_block" => item.is_block = value.into_owned(),
            "is_enabled" => item.is_enabled = value.into_owned(),
            "is_services" => item.is_services = value.into_owned(),
            "is_kernel" => item.is_kernel = value.into_owned(),
            "os_version" => item.os_version = value.into_owned(),
            "version" => item.address_family = value.into_owned(),
            _ => {}
        }
    }

    Ok(item)
}

/// Turn one item into rules, appending to `import`.
///
/// An item names a *list* of applications and this tool's rule holds exactly one pattern, so one
/// item with three applications becomes three rules that differ only in their pattern. The
/// reference reaches the same shape internally: it installs one filter per application.
fn one(item: &Item, import: &mut Import) {
    if item.name.trim().is_empty() {
        import.notes.push("an item without a name".to_owned());

        return;
    }

    let applications = split(&item.apps);

    if applications.is_empty() {
        import
            .notes
            .push(format!("'{}' names no application", item.name));

        return;
    }

    let mut dropped = Vec::new();

    let protocol = match item.protocol.trim() {
        "" => None,
        text => match text.parse::<u8>() {
            Ok(0) => None,
            Ok(6) => Some(Protocol::Tcp),
            Ok(17) => Some(Protocol::Udp),
            Ok(number) => Some(Protocol::Other(number)),
            Err(_) => {
                dropped.push(format!("protocol '{text}'"));

                None
            }
        },
    };

    // Absent and 0 are outbound, 1 is inbound, and 2 is the reference's own "any", which is what
    // leaving the field out means here.
    let direction = match item.dir.trim() {
        "" | "0" => Some(Direction::Out),
        "1" => Some(Direction::In),
        "2" => None,
        text => {
            dropped.push(format!("direction '{text}'"));

            None
        }
    };

    // One port or one address, which is what a single entry of an item can be; the import never
    // collects several entries into the list a rule's port field can hold. Anything wider stays
    // in the comment, because "port 53" and "224.0.0.0/4" are different claims about the traffic.
    let entries = split(&item.rule);
    let mut port = None;
    let mut remote = None;

    match entries.as_slice() {
        [] => {}
        [only] => {
            if let Ok(parsed) = only.parse() {
                port = Some(parsed);
            } else if let Ok(parsed) = only.parse::<Remote>() {
                remote = Some(parsed);
            } else {
                dropped.push(format!("rule '{only}'"));
            }
        }
        many => dropped.push(format!(
            "the {} entries of rule '{}'",
            many.len(),
            item.rule
        )),
    }

    if !item.rule_local.trim().is_empty() {
        dropped.push(format!("rule_local '{}'", item.rule_local));
    }

    if is_true(&item.is_services) {
        dropped.push("is_services".to_owned());
    }

    if is_true(&item.is_kernel) {
        dropped.push("is_kernel".to_owned());
    }

    if !item.os_version.trim().is_empty() {
        dropped.push(format!("os_version '{}'", item.os_version));
    }

    // The reference gates a rule on an address family; this tool picks the family from the remote
    // address, and a rule with no remote address covers both. Only a number that narrows it to
    // one family is worth a sentence.
    match item.address_family.trim() {
        "" | "0" => {}
        "2" => dropped.push("address family IPv4".to_owned()),
        "23" => dropped.push("address family IPv6".to_owned()),
        text => dropped.push(format!("address family '{text}'")),
    }

    let comment = comment(item, &dropped);

    for app in applications {
        // A pattern here is always a path. The reference also matches services by name and UWP
        // packages by id, and neither is a path this tool could put in a pattern.
        if !app.contains('\\') {
            import.notes.push(format!(
                "'{}' names '{app}', which is not a path",
                item.name
            ));

            continue;
        }

        import.rules.rule.push(Rule {
            name: item.name.clone(),
            action: if is_true(&item.is_block) {
                Action::Deny
            } else {
                Action::Allow
            },
            pattern: app,
            enabled: is_true(&item.is_enabled),
            protocol,
            direction,
            // The port field holds a list, which is not `Copy` as a single value once was, and
            // one item's port belongs to every rule the item spreads over.
            port: port.clone(),
            remote,
            local: None,
            comment: comment.clone(),
        });
    }
}

/// The comment of an imported rule: what the person wrote, plus what the import could not carry.
///
/// The sentences are kept short because the comment shows in the page on every row.
fn comment(item: &Item, dropped: &[String]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();

    if !item.comment.trim().is_empty() {
        parts.push(item.comment.trim().to_owned());
    }

    if !dropped.is_empty() {
        parts.push(format!("left out: {}", dropped.join(", ")));
    }

    if parts.is_empty() {
        return None;
    }

    let text = parts.join("; ");

    // The comment has a shape the API enforces, and an imported file should not carry something a
    // later write would refuse. A control character is what XML allows and a rule comment does not.
    let cleaned: String = text
        .chars()
        .filter(|character| !character.is_control())
        .collect();

    validate_comment(&cleaned).ok()?;

    Some(cleaned)
}

/// Split a `;`-separated list the way the reference writes one, dropping empty entries.
fn split(text: &str) -> Vec<String> {
    text.split(';')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect()
}

/// How the reference writes a boolean: the attribute is absent when false.
fn is_true(text: &str) -> bool {
    text.trim() == "true"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A profile cut down to the shapes an import has to answer for, in the reference's own
    /// attribute order.
    const PROFILE: &str = r#"<?xml version="1.0" ?>
<root timestamp="1784741706" type="4" version="6">
    <rules_custom>
        <item name="browser" apps="C:\Program Files\Browser\browser.exe" is_enabled="true" />
        <item name="ssh" apps="C:\Tools\ssh.exe" rule="22" protocol="6" dir="0" is_enabled="true" />
        <item name="mdns" apps="C:\Tools\a.exe;C:\Tools\b.exe" rule="224.0.0.251:5353" protocol="17" is_enabled="true" />
        <item name="netbios" apps="C:\Windows\System32\drivers.exe" rule_local="137-139" dir="1" is_services="true" />
        <item name="blocked" apps="C:\Tools\old.exe" is_block="true" comment="no idea why" />
        <item name="wide" apps="C:\Tools\wide.exe" rule="53;123;443" dir="2" is_enabled="true" />
        <item name="service" apps="CryptSvc" is_enabled="true" />
        <item name="empty" rule="80" is_enabled="true" />
    </rules_custom>
    <apps>
        <item name="C:\Tools\other.exe" comment="not a rule" is_enabled="true" />
    </apps>
</root>
"#;

    #[test]
    fn a_profile_becomes_one_rule_per_application() {
        let import = parse(PROFILE).expect("read the profile");

        // Eight items, one of which names no application and one a service: six produce rules,
        // and the item with two applications produces two.
        let names: Vec<&str> = import
            .rules
            .rule
            .iter()
            .map(|rule| rule.name.as_str())
            .collect();

        assert_eq!(
            names,
            vec![
                "browser", "ssh", "mdns", "mdns", "netbios", "blocked", "wide",
            ],
            "the applications decide how many rules an item becomes: {names:?}",
        );

        assert_eq!(
            import.rules.rule[2].pattern, "C:\\Tools\\a.exe",
            "the first application comes first",
        );
        assert_eq!(import.rules.rule[3].pattern, "C:\\Tools\\b.exe");
    }

    #[test]
    fn the_fields_an_item_carries_land_on_the_rule() {
        let import = parse(PROFILE).expect("read the profile");
        let ssh = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.pattern == "C:\\Tools\\ssh.exe")
            .expect("the ssh rule");

        assert!(ssh.enabled, "is_enabled is the enabled flag");
        assert_eq!(ssh.action, Action::Allow);
        assert_eq!(ssh.protocol, Some(Protocol::Tcp));
        assert_eq!(ssh.direction, Some(Direction::Out));
        assert_eq!(
            ssh.port.as_ref().map(|port| port.elements()[0].lo),
            Some(22),
            "the one port the item names is the field's only element",
        );

        let blocked = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.pattern == "C:\\Tools\\old.exe")
            .expect("the blocked rule");

        assert_eq!(blocked.action, Action::Deny, "is_block is a deny");
        assert!(!blocked.enabled, "absent is_enabled means disabled");
        assert!(
            blocked
                .comment
                .as_deref()
                .expect("a comment")
                .starts_with("no idea why"),
            "the person's own comment is kept",
        );

        let netbios = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.name == "netbios")
            .expect("the netbios rule");

        assert_eq!(netbios.direction, Some(Direction::In), "dir 1 is inbound");

        let wide = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.name == "wide")
            .expect("the wide rule");

        assert_eq!(
            wide.port, None,
            "three ports do not fit in one field, so none is claimed",
        );
        assert_eq!(
            wide.direction, None,
            "the reference's own 'any' is leaving the field out",
        );
    }

    #[test]
    fn what_cannot_come_across_is_named_in_the_comment() {
        let import = parse(PROFILE).expect("read the profile");
        let wide = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.name == "wide")
            .expect("the wide rule");

        let comment = wide.comment.as_deref().expect("a comment");

        assert!(
            comment.contains("the 3 entries of rule '53;123;443'"),
            "the dropped list has to say what was left: {comment}",
        );

        let netbios = import
            .rules
            .rule
            .iter()
            .find(|rule| rule.name == "netbios")
            .expect("the netbios rule");

        let comment = netbios.comment.as_deref().expect("a comment");

        assert!(
            comment.contains("rule_local '137-139'") && comment.contains("is_services"),
            "both parts have to be named: {comment}",
        );
    }

    #[test]
    fn an_item_that_produces_no_rule_is_explained() {
        let import = parse(PROFILE).expect("read the profile");

        assert!(
            import
                .notes
                .iter()
                .any(|note| note == "'empty' names no application"),
            "{:?}",
            import.notes,
        );
        assert!(
            import
                .notes
                .iter()
                .any(|note| note == "'service' names 'CryptSvc', which is not a path"),
            "{:?}",
            import.notes,
        );
    }

    /// The `apps` section of a profile is a list of per-application notes, not a list of rules, so
    /// the items inside it must not be read as rules.
    #[test]
    fn a_section_that_is_not_rules_contributes_nothing() {
        let import = parse(PROFILE).expect("read the profile");

        assert!(
            !import
                .rules
                .rule
                .iter()
                .any(|rule| rule.name == "C:\\Tools\\other.exe"),
            "the applications section is not rules",
        );
    }

    /// An address in `rule` is an address, not a port, and the two are told apart by their shape;
    /// the reference makes the same distinction when it parses the same text.
    #[test]
    fn a_destination_in_the_profile_is_read_as_an_address() {
        let text = r#"<root><rules_custom>
            <item name="igmp" apps="C:\Tools\x.exe" rule="224.0.0.0/4" protocol="2" dir="2" is_enabled="true" />
        </rules_custom></root>"#;

        let import = parse(text).expect("read the profile");
        let rule = &import.rules.rule[0];

        assert_eq!(rule.port, None, "224.0.0.0/4 is not a port");
        assert_eq!(
            rule.remote.map(|remote| remote.to_string()),
            Some("224.0.0.0/4".to_owned())
        );
        assert_eq!(
            rule.protocol,
            Some(Protocol::Other(2)),
            "protocol 2 is IGMP"
        );
    }

    #[test]
    fn a_file_that_is_not_xml_at_all_is_an_error() {
        // The reader is lenient about a tag it never sees closed, so what has to fail is a tag
        // that ends in the middle of itself.
        let error = parse("<item apps=").expect_err("an attribute name cut off is not XML");

        assert!(format!("{error:#}").contains("XML"), "{error:#}");
    }
}
