//! The guard every request passes before a route runs, and the session token a writing request
//! has to carry.

use std::net::Ipv4Addr;

use tracing::warn;

use super::http::{Request, Response};

/// The secret a writing request has to carry, made once when the server starts.
///
/// Sixteen bytes from the operating system, printed as hex so the tray can put it in a URL without
/// escaping. A process that cannot read random bytes has no business handing out a secret, but it
/// serves anyway with a value that is merely guessable, and says so in the log. The token itself is
/// never logged.
pub fn session_token() -> String {
    let mut bytes = [0u8; 16];

    match getrandom::fill(&mut bytes) {
        Ok(()) => bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
        Err(error) => {
            warn!(reason = %error, "could not read random bytes for the session token");

            "loopback-session".to_owned()
        }
    }
}

/// Reject a request the wire says should not reach a route (plan section 11).
///
/// The four checks answer four different mistakes, so they answer with four different codes:
///
/// * a `Host` that is not loopback is DNS rebinding — a page under another name talked to us
///   because the name resolved here, and it may read nothing but it certainly may not write;
/// * an `Origin` that is not ours is a cross-site request: the page is somewhere else and the
///   browser sent the request anyway;
/// * a `content-type` that is not JSON is a body no page of ours sends, which a route would only
///   misread;
/// * a missing or wrong token is a page that does not know the secret the tray handed out.
///
/// `GET` is held to the `Host` check only, which is what lets the page, the event stream and an
/// MCP client ask questions without carrying anything. `/mcp` is exempt from the rest of it: the
/// endpoint has no token, and since 0.36.0 it has no writing tools either, so it cannot reach a
/// route that changes a file.
pub(super) fn guard(request: &Request, token: &str) -> Option<Response> {
    let headers = &request.headers;

    if let Some(host) = &headers.host
        && !is_loopback_host(host)
    {
        return Some(Response::text(
            403,
            format!("host '{host}' is not 127.0.0.1 or localhost"),
        ));
    }

    // A missing Host header is left alone on purpose. HTTP/1.1 asks every request for one and a
    // browser always sends it, so the check can only ever catch a name that is wrong, which is the
    // rebinding case, rather than a command line client that omitted it.
    if request.method == "GET" || request.method == "HEAD" || request.path == "/mcp" {
        return None;
    }

    if let Some(origin) = &headers.origin
        && !is_loopback_origin(origin)
    {
        return Some(Response::text(
            403,
            format!("origin '{origin}' is not this page"),
        ));
    }

    match &headers.content_type {
        Some(text)
            if text
                .trim()
                .to_ascii_lowercase()
                .starts_with("application/json") => {}
        Some(text) => {
            return Some(Response::text(
                415,
                format!("content-type '{text}' is not application/json"),
            ));
        }
        None => {
            return Some(Response::text(
                415,
                "a writing request needs content-type: application/json",
            ));
        }
    }

    match &headers.token {
        Some(given) if given == token => None,
        Some(_) => Some(Response::text(
            401,
            "the session token is not the one issued",
        )),
        None => Some(Response::text(
            401,
            "a writing request needs the session token",
        )),
    }
}

/// Whether a `Host` header names this machine on the loopback interface.
///
/// The port is not checked: a request only reaches the process on the port it listens on, so a
/// page that got the port wrong never arrived in the first place, and a DNS-rebinding page arrives
/// with a name rather than with a port we could usefully have compared.
fn is_loopback_host(host: &str) -> bool {
    let name = host
        .rsplit_once(']')
        .map_or(host, |(_, rest)| rest)
        .trim_start_matches(['[', ':']);

    let name = name.split(':').next().unwrap_or(name);

    name.eq_ignore_ascii_case("localhost")
        || name.parse::<Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || name == "::1"
}

/// Whether an `Origin` header is the page this server serves.
///
/// `null` is refused: it is what a sandboxed frame or a `file://` page sends, and neither is the
/// page the tray opened.
fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin
        .trim()
        .strip_prefix("http://")
        .or_else(|| origin.trim().strip_prefix("https://"))
    else {
        return false;
    };

    is_loopback_host(rest.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Headers;
    use crate::server::testsupport::TEST_TOKEN;

    /// The token is the whole defence a writing request has, so it is worth pinning down that what
    /// the operating system hands out is long enough to guess nothing and different every run.
    #[test]
    fn a_session_token_is_long_and_different_every_time() {
        let first = session_token();
        let second = session_token();

        assert_eq!(first.len(), 32, "sixteen bytes as hex is 128 bits of token");
        assert!(
            first.chars().all(|c| c.is_ascii_hexdigit()),
            "the token has to survive a URL query: {first}"
        );
        assert_ne!(first, second, "two starts must not share a token");
    }

    /// The guard is what stands between a page on another machine and a rule written to disk, so
    /// each of its checks gets a test of its own rather than one test that happens to pass.
    fn guarded(
        method: &str,
        host: Option<&str>,
        origin: Option<&str>,
        ctype: Option<&str>,
        token: Option<&str>,
    ) -> Response {
        let pairs: Vec<(String, String)> = [
            host.map(|value| ("host".to_owned(), value.to_owned())),
            origin.map(|value| ("origin".to_owned(), value.to_owned())),
            ctype.map(|value| ("content-type".to_owned(), value.to_owned())),
            token.map(|value| ("x-winfw-token".to_owned(), value.to_owned())),
        ]
        .into_iter()
        .flatten()
        .collect();

        let request = Request::with_headers(
            method,
            "/api/rules",
            "",
            br#"{"rule":[]}"#.to_vec(),
            Headers::from_pairs(&pairs),
        );

        guard(&request, TEST_TOKEN).unwrap_or_else(|| Response::text(200, "allowed"))
    }

    #[test]
    fn a_writing_request_without_a_token_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://127.0.0.1:8788"),
            Some("application/json"),
            None,
        );

        assert_eq!(
            response.status, 401,
            "the token is what identifies the page"
        );
    }

    #[test]
    fn a_writing_request_with_the_wrong_token_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://127.0.0.1:8788"),
            Some("application/json"),
            Some("some-other-token"),
        );

        assert_eq!(response.status, 401);
    }

    /// A page on another host can still reach the socket; what it may not do is write.
    #[test]
    fn a_writing_request_from_another_origin_is_refused() {
        let response = guarded(
            "POST",
            Some("127.0.0.1:8788"),
            Some("http://example.com"),
            Some("application/json"),
            Some(TEST_TOKEN),
        );

        assert_eq!(response.status, 403, "a wrong origin is the CSRF case");
    }

    /// DNS rebinding makes `example.com` resolve to `127.0.0.1` *after* the page loaded, so the
    /// `Host` header of the requests that follow is the only thing that names the name in use.
    #[test]
    fn a_request_for_another_host_is_refused() {
        let response = guarded("GET", Some("example.com"), None, None, None);

        assert_eq!(
            response.status, 403,
            "a read is guarded against rebinding too"
        );
    }

    #[test]
    fn a_writing_request_without_a_json_body_is_refused() {
        let response = guarded(
            "POST",
            Some("localhost:8788"),
            Some("http://localhost:8788"),
            Some("text/plain"),
            Some(TEST_TOKEN),
        );

        assert_eq!(response.status, 415);
    }

    /// The browser learns the token from the URL the tray opens, and a `GET` is what reads it
    /// back, so a read must never be refused for not carrying it.
    #[test]
    fn a_reading_request_is_allowed_without_token_or_content_type() {
        let response = guarded("GET", Some("127.0.0.1:8788"), None, None, None);

        assert_eq!(response.status, 200);
    }

    /// The MCP endpoint is deliberately outside the token: an agent is configured with a URL
    /// rather than with a session, and it only reads.
    #[test]
    fn the_mcp_endpoint_is_allowed_without_a_token() {
        let request = Request::with_headers(
            "POST",
            "/mcp",
            "",
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_vec(),
            Headers::from_pairs(&[]),
        );

        assert!(guard(&request, TEST_TOKEN).is_none());
    }
}
