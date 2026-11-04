//! The list fields of a rule, read as one shape.
//!
//! Four fields of a rule hold a list of strings that name something outside the program itself:
//! `Remotes`, `Dests`, `Patterns` and `Ports`. They are read by one code path on purpose, so the
//! bounds of a list cannot be checked in one place and forgotten in another.

use serde::{Deserialize, Serialize};

use crate::rules::MAX_WILDCARD_MATCHES;
use crate::rules::ParseError;
use crate::rules::address::Family;
use crate::rules::address::Remote;
use crate::rules::pattern::is_wildcard;
use crate::rules::pattern::validate_pattern;
use crate::rules::pattern::wildcard_match;

/// The address field of a rule: one address, network or span, or a comma-separated list of them
/// such as `10.0.0.5, 192.168.1.0/24, 10.0.0.1-10.0.0.9`.
///
/// It holds at least one element; a field that names no address at all is absent rather than an
/// empty list. The elements are written back joined by commas, so a single value stays exactly the
/// single value it was before lists existed and a file written by an older version reads back
/// unchanged. The list is capped at [`MAX_WILDCARD_MATCHES`] elements: each element is installed as
/// a filter of its own per application per layer, and the store is shared with everything else on
/// the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remotes(Vec<Remote>);

impl Remotes {
    /// The elements of the field, in the order they were written.
    pub fn elements(&self) -> &[Remote] {
        &self.0
    }

    /// Whether any of the elements is an address the rule speaks about.
    pub fn contains(&self, addr: std::net::IpAddr) -> bool {
        self.0.iter().any(|remote| remote.contains(addr))
    }

    /// The elements as a field, without the check the text of a field goes through. Used
    /// where the elements were built rather than read, which is what resolving a name does.
    pub fn from_vec(elements: Vec<Remote>) -> Self {
        debug_assert!(
            elements.len() <= MAX_WILDCARD_MATCHES,
            "a built field holds no more elements than a read field may name"
        );

        Self(elements)
    }

    /// The distinct families the elements are written in. A list that mixes v4 and v6 yields both,
    /// which is what lets such a rule have filters in both stacks.
    pub fn families(&self) -> Vec<Family> {
        let mut families = Vec::new();

        for remote in &self.0 {
            for family in remote.families() {
                if !families.contains(&family) {
                    families.push(family);
                }
            }
        }

        families
    }
}

/// A list of one, which is what a single address is.
impl From<Remote> for Remotes {
    fn from(remote: Remote) -> Self {
        Self(vec![remote])
    }
}

/// The shared parts of the four list fields a rule carries: `remote`, `dest`, `pattern` and
/// `port`.
///
/// Every one of them is a comma-separated field that is written back joined by `", "`, refuses an
/// empty element, and is capped at [`MAX_WILDCARD_MATCHES`] elements because each element can
/// become a filter of its own. Only how an element is read, and the words the refusals are
/// written with, differ; both are named by the caller of [`read_field`].
///
/// Which word goes with which field is fixed here so the four messages stay one family:
///
/// | field | element | unit | empty-field refusal |
/// |---|---|---|---|
/// | `remote` | `address` | `addresses` | `address '{text}' is not an address` |
/// | `dest` | `name` | `names` | — (an empty element refuses it first) |
/// | `pattern` | `pattern` | `applications` | `a rule needs a pattern` |
/// | `port` | `port` | `ports` | `port '{text}' is not a port` |
///
/// The words one list field writes its refusals with.
struct FieldWords {
    /// What one element is called, as in `address list '...'`.
    list: &'static str,
    /// What the elements are called in the cap message.
    unit: &'static str,
}

/// Split one list field, trim its elements, refuse an empty element and cap the count.
///
/// `read` turns one element of text into the element value; `empty_field` is the refusal for a
/// field that holds nothing but blanks, and `None` leaves that case to `read`, which is how
/// `dest` behaves.
fn read_field<T>(
    text: &str,
    words: &FieldWords,
    empty_field: Option<&str>,
    mut read: impl FnMut(&str) -> Result<T, ParseError>,
) -> Result<Vec<T>, ParseError> {
    if text.trim().is_empty() {
        return match empty_field {
            Some(message) => Err(message.to_owned()),
            None => Err(format!("{} '{text}' is not a {}", words.list, words.list)),
        };
    }

    let mut elements = Vec::new();

    for part in text.split(',') {
        let part = part.trim();

        if part.is_empty() {
            return Err(format!("{} list '{text}' has an empty element", words.list));
        }

        elements.push(read(part)?);
    }

    if elements.len() > MAX_WILDCARD_MATCHES {
        return Err(format!(
            "{} list '{text}' names more than {MAX_WILDCARD_MATCHES} {}",
            words.list, words.unit
        ));
    }

    Ok(elements)
}

/// The contents of an address field of a rule, split into validated elements.
///
/// An element is the text of a single address parsed on its own, so an element that would be
/// refused as the whole field is refused here too. The list is capped at
/// [`MAX_WILDCARD_MATCHES`] elements, which is the same bound a wildcard pattern is capped
/// at, for the same reason: every element of the list can become a filter of its own.
impl std::str::FromStr for Remotes {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // Splitting on commas is safe for every element form: neither a network nor a span
        // contains a comma, and an IPv6 address never is written with one.
        Ok(Self(read_field(
            text,
            &FieldWords {
                list: "address",
                unit: "addresses",
            },
            None,
            |part| {
                part.parse::<Remote>()
                    .map_err(|err| format!("{part}: {err}"))
            },
        )?))
    }
}

/// The destination field of a rule: names, written `www.example.com`, and a comma-separated
/// list of them for more than one. Unlike `remote`, which holds addresses, this field holds
/// names and is resolved to addresses when the filters are built.
///
/// A name is stored lowercased, because a name is matched without regard to case and the file
/// is written back as it was read. A name holds no wildcard: `*` is not valid in a hostname,
/// and a rule that wants a whole domain resolves the names it can see.
///
/// The list is capped at [`MAX_WILDCARD_MATCHES`] names; every name resolves to at most
/// [`crate::dns::MAX_NAME_ADDRESSES`] addresses, which is a bound on the answers, not on the
/// field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dests(Vec<String>);

impl Dests {
    /// The names of the field, lowercased, in the order they were written.
    pub fn names(&self) -> &[String] {
        &self.0
    }

    /// Whether the addresses a name was answered with include the given address. A name
    /// nothing has answered for speaks about nothing, so an unresolved destination matches
    /// no connection and the Detected list still shows it.
    pub fn contains(&self, addr: std::net::IpAddr, answers: &crate::dns::Answers) -> bool {
        self.0
            .iter()
            .any(|name| answers.addresses(name).contains(&addr))
    }
}

/// Whether the text is shaped like a name: labels of letters, digits and hyphens separated by
/// dots, at least one dot, no label empty, no label longer than 63 characters and the whole text
/// no longer than 253, which is what a name may hold.
///
/// A trailing dot is refused, because the file is written back as it was read and the
/// difference between `example.com` and `example.com.` would show up as a rule that changed.
fn is_name(text: &str) -> bool {
    text.len() <= 253
        && text.contains('.')
        && text.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

impl std::str::FromStr for Dests {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        // The refusal a field of nothing but blanks answers with, kept in the words this field
        // has always used for it.
        let names = read_field(
            text,
            &FieldWords {
                list: "name",
                unit: "names",
            },
            Some("name list has an empty element"),
            |part| {
                if !is_name(part) {
                    return Err(format!("'{part}' is not a name"));
                }

                Ok(part.to_lowercase())
            },
        )?;

        // A name is one name however often it is written, and the file is written back as the
        // field reads, so the second copy of a name is dropped here rather than at every reader.
        let mut unique: Vec<String> = Vec::new();

        for name in names {
            if !unique.contains(&name) {
                unique.push(name);
            }
        }

        Ok(Self(unique))
    }
}

/// The application field of a rule: one path, or a comma-separated list of them such as
/// `C:\test\tool1.exe, C:\test\tool2.exe`.
///
/// It holds at least one element; a field that names no application at all is refused. The
/// elements are written back joined by commas, so a single path stays exactly the single path it
/// was before lists existed and a file written by an older version reads back unchanged.
///
/// A path may hold a comma on Windows, and splitting on commas then cuts it in two: the second
/// half is no absolute path, so such a pattern is refused out loud rather than installed as a rule
/// that silently matches nothing. The wildcard the directory tree offers is the way around it.
///
/// The list is capped at [`MAX_WILDCARD_MATCHES`] elements. That is a bound on the text of the
/// field; the bound on what reaches the store is over the whole field, because every application
/// costs a filter per layer and the store is shared with everything else on the machine. See
/// [`crate::wfp::pattern_reach`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patterns(Vec<String>);

impl Patterns {
    /// The elements of the field, in the order they were written.
    pub fn elements(&self) -> &[String] {
        &self.0
    }

    /// Whether any element needs matching at all rather than being an exact path. Only such an
    /// element is expanded against the applications this tool has seen.
    pub fn has_wildcard(&self) -> bool {
        self.0.iter().any(|element| is_wildcard(element))
    }

    /// Whether any of the elements speaks about this path.
    pub fn matches(&self, path: &str) -> bool {
        self.0.iter().any(|element| wildcard_match(element, path))
    }
}

/// The contents of the application field of a rule, split into validated elements.
///
/// Every element is validated on its own, so an element that would be refused as the whole field
/// is refused here too.
impl std::str::FromStr for Patterns {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Ok(Self(read_field(
            text,
            &FieldWords {
                list: "pattern",
                unit: "applications",
            },
            Some("a rule needs a pattern"),
            |part| {
                validate_pattern(part).map_err(|err| err.to_string())?;

                Ok(part.to_owned())
            },
        )?))
    }
}

/// A list of one, which is what a path that came from elsewhere is.
///
/// The text is split the way the field is split, so the elements always are what writing the
/// field back would read as. A text that cannot be split into valid elements is kept whole: this
/// constructor cannot report an error, and a rule that came from a file is validated there.
impl From<String> for Patterns {
    fn from(text: String) -> Self {
        text.parse().unwrap_or_else(|_| Self(vec![text]))
    }
}

/// A list of one, which is what a path that came from elsewhere is.
impl From<&str> for Patterns {
    fn from(text: &str) -> Self {
        text.to_owned().into()
    }
}

/// A field that names exactly this path is equal to it, which is how a caller compares a rule
/// against one application without going through the text of the field.
impl PartialEq<str> for Patterns {
    fn eq(&self, other: &str) -> bool {
        self.0.len() == 1 && self.0[0] == other
    }
}

/// A field that names exactly this path is equal to it.
impl PartialEq<&str> for Patterns {
    fn eq(&self, other: &&str) -> bool {
        self == *other
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
        Ok(Self(read_field(
            text,
            &FieldWords {
                list: "port",
                unit: "ports",
            },
            None,
            |part| part.parse::<PortRange>(),
        )?))
    }
}

/// Writing a list field back, and reading it through serde.
///
/// The four list fields a rule carries are stored as one text joined by `", "` in the file, in
/// JSON and on the page, so all four write and read themselves the same way.
macro_rules! list_field {
    ($name:ident) => {
        impl std::fmt::Display for $name {
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

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;

                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

list_field!(Remotes);
list_field!(Dests);
list_field!(Patterns);
list_field!(Ports);

/// A port, or an inclusive range of them, written `443` or `1024-2048`.
///
/// Zero is not a port. WFP reserves it for "no port", so a rule that named it would never match a
/// connection; refusing it here is what keeps a typo out of the store.
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

        if lo == 0 || hi == 0 {
            return Err(format!("port '{text}' is not a port"));
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
