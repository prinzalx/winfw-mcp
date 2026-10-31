//! The JSON-RPC 2.0 messages of the `/mcp` endpoint.
//!
//! Only the part of the protocol an MCP client actually sends on a stateless HTTP transport is
//! modelled here: `initialize`, `tools/list`, `tools/call` and `ping`. PLAN.md section 6 kept the
//! option of `rmcp` open, and this is the point where that was weighed: the crate would bring a
//! tokio runtime and an axum dependency for four method names, while the endpoint has to answer
//! the same four questions either way. Hand-writing them keeps the binary small and the grammar
//! visible; a client that asks for anything else is told so rather than silently ignored.
//!
//! The tool results use the MCP content shape (`content` plus `isError`) rather than a bare JSON
//! value, because that is what a model reads, and because it lets a refused write carry its reason
//! as text instead of as a transport-level failure.

use serde::{Deserialize, Serialize};

/// How the protocol version of a client is answered when it does not match ours.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// One request from a client.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Present but unused: a request without it is rejected by [`parse`], which is where the
    /// version is checked rather than trusted.
    #[serde(default)]
    pub jsonrpc: String,
    /// Absent for a notification, which is why the id is optional.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

impl Request {
    /// A notification carries no id, so its answer has nothing to address.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// The object the arguments of a call live in.
    ///
    /// A `tools/call` nests them under `arguments`, while a call that is its own method carries
    /// them directly in `params`. Accepting both means a client can use the shortest form it
    /// likes, which is what an agent tends to do.
    fn args(&self) -> Option<&serde_json::Map<String, serde_json::Value>> {
        let outer = self.params.as_ref()?.as_object()?;

        match outer.get("arguments").and_then(|value| value.as_object()) {
            Some(inner) if !inner.is_empty() => Some(inner),
            _ => Some(outer),
        }
    }

    /// One argument of the call, read by name.
    pub fn arg(&self, name: &str) -> Option<serde_json::Value> {
        self.args().and_then(|map| map.get(name)).cloned()
    }

    /// One string argument of a tool, which is how every argument of this endpoint arrives.
    pub fn string_arg(&self, name: &str) -> Option<String> {
        self.arg(name)
            .and_then(|value| value.as_str().map(str::to_owned))
    }

    /// The tool a call names.
    ///
    /// Only a `tools/call` carries a tool name, and there the name lives in `params` rather than
    /// among the arguments: a direct method call such as `rules.deny` may well pass a rule name of
    /// its own, and that is not the tool.
    pub fn tool_name(&self) -> String {
        if self.method != "tools/call" {
            return self.method.clone();
        }

        self.params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|map| map.get("name"))
            .and_then(|value| value.as_str())
            .unwrap_or("status")
            .to_owned()
    }
}

/// The answer to one request.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    /// A response to a notification carries neither id nor result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

/// The error object of a failed call.
#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

/// `Method not found`, which is also the answer to a tool name this endpoint does not know.
pub const METHOD_NOT_FOUND: i32 = -32601;

/// `Invalid request`, used for a body that is not a JSON-RPC 2.0 call at all.
pub const INVALID_REQUEST: i32 = -32600;

/// `Invalid params`, used when a tool is called with an argument it cannot use.
pub const INVALID_PARAMS: i32 = -32602;

/// The code an MCP client should read as "the endpoint refused to act". It is in the range the
/// specification leaves for implementations, so a client does not mistake a policy refusal for a
/// protocol error.
pub const REFUSED: i32 = -32000;

impl Response {
    /// The result of a call that went through.
    pub fn result(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    /// The answer to a notification: nothing but the protocol version.
    pub fn acknowledged(id: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(serde_json::json!({})),
            error: None,
        }
    }

    /// A failed call. `id` is kept, because a client matches replies to requests by it.
    pub fn error(id: Option<serde_json::Value>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(Error {
                code,
                message: message.into(),
            }),
        }
    }
}

/// The result body of a `tools/call`: text a model can read, plus whether the tool refused.
///
/// A refusal is reported as a result with `isError` rather than as a JSON-RPC error, which is what
/// the MCP specification asks for and what lets the client read the reason instead of only the
/// fact that something went wrong.
pub fn tool_text(text: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "content": [{ "type": "text", "text": text.into() }],
        "isError": false,
    })
}

/// The result body of a tool that answers with data rather than with a sentence.
///
/// The data is given twice on purpose: as text for the model, which reads `content`, and as
/// `structuredContent` for a client that would rather not parse a string it was given as JSON.
pub fn tool_json(value: serde_json::Value) -> serde_json::Value {
    let text = value.to_string();

    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "isError": false,
        "structuredContent": value,
    })
}

/// The result body of a tool that declined to act.
pub fn tool_refusal(text: impl Into<String>) -> serde_json::Value {
    let text = text.into();
    serde_json::json!({
        "content": [{ "type": "text", "text": text.clone() }],
        "isError": true,
        // The refusal is also structured, so a client does not have to parse prose to learn that
        // the policy rather than the firewall was the obstacle.
        "structuredContent": { "refused": true, "reason": text },
    })
}

/// Read the body of a request, rejecting the versions of the protocol this endpoint does not speak.
///
/// `jsonrpc` is required by the specification but clients have been known to omit it, so a missing
/// field is treated as version 2.0 while a wrong one is a hard refusal.
pub fn parse(body: &[u8]) -> std::result::Result<Request, Response> {
    let request: Request = serde_json::from_slice(body)
        .map_err(|error| Response::error(None, INVALID_REQUEST, error.to_string()))?;

    if !request.jsonrpc.is_empty() && request.jsonrpc != "2.0" {
        return Err(Response::error(
            request.id.clone(),
            INVALID_REQUEST,
            format!("this endpoint speaks JSON-RPC 2.0, not {}", request.jsonrpc),
        ));
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_notification_has_nothing_to_address() {
        let notification: Request =
            serde_json::from_slice(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .expect("parse");

        assert!(notification.is_notification());
        assert_eq!(notification.tool_name(), "notifications/initialized");
    }

    #[test]
    fn a_tool_call_reads_its_arguments() {
        let call: Request = serde_json::from_slice(
            br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rules.deny","arguments":{"app":"C:\\temp\\x.exe","name":"agent"}}}"#
        )
        .expect("parse");

        assert!(!call.is_notification());
        assert_eq!(call.tool_name(), "rules.deny");
        assert_eq!(
            call.string_arg("app").as_deref(),
            Some("C:\\temp\\x.exe"),
            "the arguments of a tools/call are nested under `arguments`"
        );
        assert_eq!(call.string_arg("name").as_deref(), Some("agent"));
    }

    #[test]
    fn an_index_is_read_from_the_nested_arguments() {
        let call: Request = serde_json::from_slice(
            br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rules.share","arguments":{"index":2}}}"#
        )
        .expect("parse");

        assert_eq!(call.arg("index").and_then(|value| value.as_u64()), Some(2));
    }

    #[test]
    fn a_method_that_carries_its_arguments_in_params_is_understood_too() {
        let call: Request = serde_json::from_slice(
            br#"{"jsonrpc":"2.0","id":4,"method":"rules.share","params":{"index":1}}"#,
        )
        .expect("parse");

        assert_eq!(call.tool_name(), "rules.share");
        assert_eq!(call.arg("index").and_then(|value| value.as_u64()), Some(1));
    }

    #[test]
    fn a_wrong_protocol_version_is_refused() {
        let error = parse(br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
            .err()
            .expect("refused");

        assert_eq!(error.error.expect("error").code, INVALID_REQUEST);
        assert_eq!(error.id, Some(serde_json::json!(1)));
    }

    #[test]
    fn an_absent_version_is_taken_as_2_0() {
        let request = parse(br#"{"id":1,"method":"ping"}"#).expect("accepted");

        assert_eq!(request.method, "ping");
    }

    #[test]
    fn a_refusal_is_a_result_rather_than_a_transport_error() {
        let refusal = tool_refusal("mcp_writes is none");
        let response = Response::result(Some(serde_json::json!(1)), refusal);

        assert!(
            response.error.is_none(),
            "a refusal must not look like a protocol error"
        );
        assert_eq!(
            response
                .result
                .expect("result")
                .get("isError")
                .and_then(|value| value.as_bool()),
            Some(true)
        );
    }

    #[test]
    fn an_empty_result_omits_the_fields_it_has_not() {
        let acknowledged = serde_json::to_string(&Response::acknowledged(None)).expect("serialize");

        assert_eq!(acknowledged, r#"{"jsonrpc":"2.0","result":{}}"#);
    }
}
