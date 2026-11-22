//! The rule model.
//!
//! A rule names what WFP should do with the connections of one application: an action, a
//! direction, a transport, a port and the remote side it is about. This module holds that data.
//! Installing it into the filter engine is [`crate::wfp`], keeping the files on disk in step is
//! [`crate::store`], and what the web page shows of it is [`crate::server`].

use serde::{Deserialize, Serialize};

pub mod address;
pub mod disk;
pub mod fields;
pub mod pattern;
pub mod protocol;
pub mod stamp;

pub use address::*;
pub use disk::*;
pub use fields::*;
pub use pattern::*;
pub use protocol::*;
pub use stamp::*;

/// How many entries one rule field may name, and how many applications one wildcard pattern may
/// be expanded into.
///
/// A pattern is allowed to be broad, but the store is shared and every match costs four filters.
/// The cap keeps a careless `*` from turning one rule into thousands, and it is the same bound for
/// every list a rule carries, so one rule can never spend more than this many filters per layer.
pub const MAX_WILDCARD_MATCHES: usize = 32;

/// What WFP eventually does with a matching connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Which way the connection goes for a rule to apply.
///
/// This decides the layers a rule is installed on: outbound is the ALE connect layer, inbound the
/// ALE recv-accept layer. Absent means both, as it did before the dimension existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

/// The error text a bad port answers with, which becomes a serde message and a web error.
pub(crate) type ParseError = String;

#[cfg(test)]
mod tests;
