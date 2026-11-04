//! The `/mcp` endpoint: JSON-RPC 2.0 in, tool answers out. Every tool here reads, so the endpoint
//! never touches a file or the store on its own behalf.

use anyhow::Result;

use crate::export;
use crate::mcp;

use super::STATE_EVENTS;
use super::http::{Request, Response};
use super::state::AppState;
use super::worker::{StoreWork, WfpWorker};

/// The method behind a `tools/call`, with the code and message of a protocol error.
type ToolError = (i32, String);

/// Answer one JSON-RPC 2.0 call for an MCP client.
///
/// Everything the endpoint knows is in `state`, so the transport stays thin: it decodes the call,
/// asks the same core the web UI asks, and puts the answer into the shape MCP clients read. A
/// failure to speak JSON-RPC is still answered with HTTP 200, because in JSON-RPC the failure is
/// part of the conversation rather than a delivery problem.
pub(super) fn mcp_endpoint(
    state: &AppState,
    worker: &WfpWorker,
    request: &Request,
) -> Result<Response> {
    let call = match mcp::parse(&request.body) {
        Ok(call) => call,
        Err(reply) => return Response::json(200, &reply),
    };

    let id = call.id.clone();

    // A notification wants no answer, but HTTP needs a body, so it gets an empty result. Both the
    // missing id and the `notifications/` prefix mean the same thing here.
    if call.is_notification() || call.method.starts_with("notifications/") {
        return Response::json(200, &mcp::Response::acknowledged(id));
    }

    let reply = match call.method.as_str() {
        "initialize" => serde_json::json!({
            "protocolVersion": mcp::PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": env!("CARGO_PKG_NAME"),
                "version": env!("CARGO_PKG_VERSION"),
            },
        }),
        "ping" => serde_json::json!({}),
        "tools/list" => serde_json::json!({ "tools": tool_list() }),
        "tools/call" => match mcp_tool(state, worker, &call) {
            Err(error) => {
                return Response::json(200, &mcp::Response::error(id, error.0, error.1));
            }
            Ok(value) => value,
        },
        // A tool may also be called by its own name, which is the shortest form an agent can
        // choose, so it is answered here rather than sent to the "unknown method" branch.
        other if is_tool(other) => match mcp_tool(state, worker, &call) {
            Err(error) => {
                return Response::json(200, &mcp::Response::error(id, error.0, error.1));
            }
            Ok(value) => value,
        },
        other => {
            return Response::json(
                200,
                &mcp::Response::error(id, mcp::METHOD_NOT_FOUND, format!("unknown method {other}")),
            );
        }
    };

    Response::json(200, &mcp::Response::result(id, reply))
}

/// Whether a method name is one of the tools, which makes it callable without `tools/call`.
fn is_tool(name: &str) -> bool {
    tool_list()
        .iter()
        .any(|tool| tool["name"].as_str() == Some(name))
}

/// The tools the endpoint offers, in the shape `tools/list` wants.
///
/// Every one of them reads (plan section 10). A tool that would change a file or the store is
/// not offered at all rather than refused at call time, so an agent cannot be tempted to write
/// something it has no business writing, and the page keeps the editing to itself.
/// The six tools the endpoint offers, and nothing else. Every one of them reads. Writing was
/// removed with `0.36.0`: an agent that can write can hand itself a rule, and a rule is the way
/// out to the network, so a tool that reaches the internet could open its own gate.
fn tool_list() -> Vec<serde_json::Value> {
    /// The schema of a tool that takes no arguments at all.
    fn no_arguments() -> serde_json::Value {
        serde_json::json!({ "type": "object", "properties": {} })
    }

    let index = serde_json::json!({
        "type": "object",
        "properties": {
            "index": { "type": "integer", "description": "the rule `rules.share` should encode, counted as rules.list orders them" }
        }
    });

    let tools = [
        (
            "status",
            "settings, the rule count, the store, and the monitor",
            no_arguments(),
        ),
        (
            "rules.list",
            "every rule, in the order the firewall reads it",
            no_arguments(),
        ),
        (
            "rules.share",
            "one rule as a Base64 string; takes an index",
            index,
        ),
        (
            "detected.list",
            "the applications learning mode collected, newest first",
            no_arguments(),
        ),
        (
            "events.list",
            "the connections the firewall reported recently, with their destination",
            no_arguments(),
        ),
        (
            "profiles.list",
            "the active profile and the names of the stored profiles",
            no_arguments(),
        ),
    ];

    tools
        .into_iter()
        .map(|(name, description, schema)| {
            serde_json::json!({ "name": name, "description": description, "inputSchema": schema })
        })
        .collect()
}

/// Run one MCP tool.
///
/// Every tool here reads. What a client cannot find is no longer a tool that refused a write but a
/// tool that never existed: an endpoint that offers only questions cannot grant itself a firewall
/// change it then has to explain (plan section 10).
fn mcp_tool(
    state: &AppState,
    worker: &WfpWorker,
    call: &mcp::Request,
) -> std::result::Result<serde_json::Value, ToolError> {
    match call.tool_name().as_str() {
        "status" => {
            let outcome = worker
                .ask(StoreWork::Inventory)
                .map_err(|error| (mcp::REFUSED, format!("{error:#}")))?;
            let rules = state.rules.lock().expect("rules lock poisoned").rule.len();
            let detected = state.detector.snapshot().len();

            Ok(mcp::tool_json(serde_json::json!({
                "port": state.settings.port,
                "learn_mode": state.learn_mode(),
                "protection": state.protection(),
                "default_policy": state.settings.default_policy.name(),
                "theme": state.live.theme().name(),
                "profile": state.active_name(),
                "rules": rules,
                "detected": detected,
                "store": {
                    "readable": outcome.ok,
                    "providers": outcome.inventory.providers,
                    "sublayers": outcome.inventory.sublayers,
                    "filters": outcome.inventory.filters,
                    "reason": outcome.reason,
                },
                "monitor": state.monitor(),
                "startup": state.startup.clone(),
            })))
        }
        "rules.list" => {
            let rules = state.rules.lock().expect("rules lock poisoned").clone();

            Ok(mcp::tool_json(
                serde_json::to_value(rules).map_err(|error| (mcp::REFUSED, error.to_string()))?,
            ))
        }
        "rules.share" => {
            let index = call
                .arg("index")
                .and_then(|value| value.as_u64())
                .ok_or((mcp::INVALID_PARAMS, "rules.share needs an index".to_owned()))?
                as usize;
            let rules = state.rules.lock().expect("rules lock poisoned").clone();

            match rules.rule.get(index) {
                Some(rule) => Ok(mcp::tool_text(
                    export::encode(rule).map_err(|error| (mcp::REFUSED, format!("{error:#}")))?,
                )),
                None => Err((
                    mcp::INVALID_PARAMS,
                    format!("there is no rule at index {index}"),
                )),
            }
        }
        "detected.list" => Ok(mcp::tool_json(
            serde_json::to_value(state.detector.snapshot())
                .map_err(|error| (mcp::REFUSED, error.to_string()))?,
        )),
        "events.list" => {
            let mut events = state.events.snapshot();

            events.reverse();
            events.truncate(STATE_EVENTS);

            Ok(mcp::tool_json(
                serde_json::to_value(events).map_err(|error| (mcp::REFUSED, error.to_string()))?,
            ))
        }
        "profiles.list" => Ok(mcp::tool_json(serde_json::json!({
            "active": state.active_name(),
            "names": crate::rules::list_names(&state.paths.profiles),
        }))),
        other => Err((
            mcp::METHOD_NOT_FOUND,
            format!("this endpoint has no tool named {other}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;
    use crate::server::testsupport::state;

    /// The writing tools are gone from the endpoint, so a client that still calls one hears
    /// `method not found` rather than watching a file change behind its back.
    #[test]
    fn calling_a_removed_tool_is_a_method_not_found() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();
        let rules_path = server_state.rules_path();

        let before = std::fs::read_to_string(&rules_path).ok();

        let response = Server::route(
                &server_state,
                &worker,
                &Request::new(
                    "POST",
                    "/mcp",
                    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rules.allow","arguments":{"app":"notepad.exe"}}}"#.to_vec(),
                ),
            )
            .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            body.contains("-32601"),
            "a removed tool is not a tool any more: {body}",
        );
        assert_eq!(
            std::fs::read_to_string(&rules_path).ok(),
            before,
            "an MCP call must not write a rule file",
        );
    }

    /// `tools/list` is what an agent reads before it acts, so the list *is* the surface: a writing
    /// tool that is not listed cannot be called, and `shutdown` is proof that it is really gone.
    #[test]
    fn the_tool_list_offers_only_reading_tools() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
            ),
        )
        .expect("route");

        let body = String::from_utf8_lossy(&response.body).into_owned();

        for name in [
            "status",
            "rules.list",
            "rules.share",
            "detected.list",
            "events.list",
            "profiles.list",
        ] {
            assert!(
                body.contains(&format!(r#""name":"{name}""#)),
                "{name} is a tool an agent can discover: {body}",
            );
        }

        for name in ["shutdown", "settings.set", "rules.allow", "rules.decode"] {
            assert!(
                !body.contains(&format!(r#""name":"{name}""#)),
                "{name} wrote to a file or the store, so it is not offered any more: {body}",
            );
        }
    }

    /// An agent may name a tool directly rather than wrapping it in `tools/call`, which is the
    /// shortest form it can send and therefore the one it is most likely to guess.
    #[test]
    fn a_tool_can_be_called_by_its_own_name() {
        let server_state = state();
        let worker = WfpWorker::start_enforcing();

        let response = Server::route(
            &server_state,
            &worker,
            &Request::new(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"profiles.list"}"#.to_vec(),
            ),
        )
        .expect("route");

        assert_eq!(response.status, 200);

        let body = String::from_utf8_lossy(&response.body).into_owned();

        assert!(
            !body.contains("unknown method"),
            "a tool name is a method too: {body}"
        );
        assert!(
            body.contains("structuredContent"),
            "the tool itself answered: {body}",
        );
    }
}
