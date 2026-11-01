# 6. The MCP endpoint

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

`POST /mcp` speaks JSON-RPC 2.0 and needs no session: every request is answered on its own, so
curl is a valid client. `initialize`, `ping`, `tools/list` and `tools/call` are implemented, and a
tool name may be used as the method directly, which is the shortest form an agent can send.

Only the part of the protocol a client actually sends on a stateless HTTP transport is modelled. A
client that asks for anything else is told so rather than silently ignored.

## Tools

Six tools, and every one of them reads.

| Tool | Purpose |
|---|---|
| `status` | settings, rule count, store health, the state of the event feed, what the rebuild at startup found |
| `rules.list` | every rule, in file order |
| `rules.share` | one rule as a Base64 string (takes `index`) |
| `detected.list` | what learning mode collected |
| `events.list` | recent connection events, each naming both endpoints, whether the traffic left the machine, and the deciding filter id and rule |
| `profiles.list` | the active profile and the stored profile names |

`rules.share` is the readable half of a rule: an agent can hand the string to a human, and the
human can put it in the browser, which is how a rule travels between machines without anyone
editing a file over a share.

Since **0.37.0** `events.list` answers with connections that left the machine. A loopback connection
is dropped in the monitor before it reaches the log, so an agent cannot see its own traffic in the
feed, and a destination on the local segment is reported with `local_network` set rather than
dropped ([WFP internals](07-wfp-internals.md#what-the-callback-keeps)).

### What happened to the writing tools

Until `0.36.0` the endpoint also offered `rules.allow`, `rules.deny`, `rules.remove`,
`rules.import`, `rules.decode`, `settings.set`, `profile.use`, `shutdown` and `export`. They are
gone from the code rather than switched off by configuration, and the reason is circular
permission: a tool that can write can hand itself a firewall rule, and a firewall rule is the way
out to the network. An agent that runs a program which reaches the internet could therefore open
its own gate, which is not a question about the firewall but a change to it.

A client that calls one of the removed tools hears `-32601` (`METHOD_NOT_FOUND`), the same answer
it would get for a name that never existed. What the endpoint cannot do is the protocol's business,
not a policy decision, so it is not reported as a tool that ran and declined.

The consequence worth stating plainly: **an MCP client cannot stop this tool.** `shutdown` was a
writing tool, so stopping the process means the browser, the tray, or a `POST /api/shutdown` with
the session token.

## Reads and the token

The MCP endpoint is deliberately outside the session token described in
[the security model](10-security-model.md). An agent is configured with a URL, and a URL it has to
be told about is a URL that can be copied into another process on this machine. Because the endpoint
only reads, the worst that an uninvited reader does is learn what the rules are.

The writing half of that argument belongs to the HTTP API in
[chapter 5](05-web-ui.md): the browser holds the token, and only the browser may write.

## Why hand-written

The `rmcp` crate was weighed and rejected here: it would bring a tokio runtime and an axum
dependency for four method names, while the endpoint has to answer the same four questions either
way. Hand-writing them keeps the binary small and the grammar visible.

---

Previous: [5. The web UI](05-web-ui.md) · Next: [7. WFP internals](07-wfp-internals.md)
