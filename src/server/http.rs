//! The HTTP/1.1 pieces: what the transport reads, what a route answers with, and the status a
//! failure is mapped to.

use anyhow::Result;
use serde::Serialize;

/// The request headers the guards read.
///
/// Only these four matter to this server, and they are matched case-insensitively because a guard
/// that is not would be a guard a client could confuse by capitalising differently.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    pub(super) host: Option<String>,
    pub(super) origin: Option<String>,
    pub(super) content_type: Option<String>,
    pub(super) token: Option<String>,
}

impl Headers {
    /// Pick the four interesting fields out of the lines the transport read, in order.
    ///
    /// A field sent twice keeps the first value: that is what a browser sends, and it is the
    /// reading least likely to turn a confused proxy into a surprise.
    pub(super) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut headers = Self::default();

        for (name, value) in pairs {
            let value = value.trim().to_owned();

            match name.to_ascii_lowercase().as_str() {
                "host" if headers.host.is_none() => headers.host = Some(value),
                "origin" if headers.origin.is_none() => headers.origin = Some(value),
                "content-type" if headers.content_type.is_none() => {
                    headers.content_type = Some(value);
                }
                "x-winfw-token" if headers.token.is_none() => headers.token = Some(value),
                _ => {}
            }
        }

        headers
    }
}

/// A parsed request. Only the parts a local, single-user server needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) body: Vec<u8>,
    pub(super) headers: Headers,
}

impl Request {
    #[allow(dead_code)] // the tests route a request directly; the socket path uses `with_headers`
    pub fn new(method: &str, path: &str, body: Vec<u8>) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body,
            headers: Headers::default(),
        }
    }

    /// A request as the transport read it, headers included.
    pub fn with_headers(method: &str, path: &str, body: Vec<u8>, headers: Headers) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            body,
            headers,
        }
    }
}

/// A response ready to be written on the wire.
pub struct Response {
    pub(super) status: u16,
    pub(super) content_type: &'static str,
    pub(super) body: Vec<u8>,
}

impl Response {
    pub(super) fn text(status: u16, body: impl Into<String>) -> Self {
        let body = body.into();

        Self {
            status,
            content_type: "text/plain; charset=utf-8",
            body: body.into_bytes(),
        }
    }

    pub(super) fn json<T: Serialize>(status: u16, value: &T) -> Result<Self> {
        Ok(Self {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(value)?,
        })
    }

    /// The status line plus framing, for the tests and for `write_all`.
    ///
    /// The content security policy is part of the framing rather than of one route: the page is
    /// embedded, so it can only ever come from this server, and a policy that names no origin
    /// outside is what keeps a future template from quietly pulling in a CDN.
    pub(super) fn header(&self) -> String {
        format!(
            "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\ncache-control: no-store\r\ncontent-security-policy: {}\r\nconnection: close\r\n\r\n",
            status_text(self.status),
            self.content_type,
            self.body.len(),
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'",
        )
    }
}

/// A request body the server could not read. The client sent it and the client can fix it, so a
/// route that fails this way answers `400` rather than `500`.
#[derive(Debug)]
struct BadRequest(String);

impl std::fmt::Display for BadRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BadRequest {}

/// Parse a JSON request body. Anything the server cannot read — a syntax error, a wrong field
/// type, a name outside an enum — is the client's mistake, not the server's.
pub(super) fn parse_body<T>(body: &[u8], what: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_slice(body)
        .map_err(|error| anyhow::Error::new(BadRequest(format!("body must be {what}: {error}"))))
}

/// Parse a JSON body that may legitimately be empty, as `curl -d ''` and a UI button that sends no
/// payload both produce.
pub(super) fn parse_or_default<T>(body: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned + Default,
{
    if body.is_empty() {
        return Ok(T::default());
    }

    parse_body(body, "a JSON object")
}

/// Turn a routed result into a response. A body the server could not read answers `400`; any
/// other failure — a store that refused the change, a file that would not write — is `500`.
pub(super) fn respond(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| {
        let status = if error.downcast_ref::<BadRequest>().is_some() {
            400
        } else {
            500
        };

        Response::text(status, format!("{error:#}"))
    })
}

/// Map a status code to the reason phrase we send.
fn status_text(status: u16) -> &'static str {
    match status {
        200 => "200 OK",
        400 => "400 Bad Request",
        401 => "401 Unauthorized",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        415 => "415 Unsupported Media Type",
        _ => "500 Internal Server Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;
    use crate::server::WfpWorker;
    use crate::server::testsupport::state;

    /// A body the server could not read is the client's mistake and must answer as one. Found by
    /// a live run of 0.32.0: an unreadable theme answered `500`, which told the user the server
    /// had broken rather than that the value was wrong.
    #[test]
    fn an_unreadable_settings_body_answers_bad_request() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        for body in [r#"{"theme":"neon"}"#, r#"{"policy":"deny"}"#, "{"] {
            let response = respond(Server::route(
                &server_state,
                &worker,
                &Request::new("POST", "/api/settings", body.as_bytes().to_vec()),
            ));

            assert_eq!(response.status, 400, "not the server's fault: {body}");
        }
    }

    /// The other half of the mapping: a failure that is not a bad body stays a `500`. Naming an
    /// index outside the rule list parses fine, so only the refusal path can answer for it.
    #[test]
    fn a_failure_that_is_not_a_bad_body_stays_internal() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let response = respond(Server::route(
            &server_state,
            &worker,
            &Request::new("POST", "/api/rules/share", br#"{"index":40}"#.to_vec()),
        ));

        assert_eq!(response.status, 500, "a refusal is not a parse error");
    }
}
