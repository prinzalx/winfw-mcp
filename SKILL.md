---
name: winfw-mcp
description: Use when an agent needs to query or reason about the winfw-mcp Windows firewall on this machine, over MCP or the local HTTP API - what each side may read, what only the browser may change, and which effects to expect from a rule.
---

# winfw-mcp for agents

winfw-mcp is a portable Windows firewall tool (`winfw-mcp.exe --serve`, elevated, WFP-based) with
a local web UI and an embedded HTTP server on `127.0.0.1` (default port 8788). One process,
no service, no installer.

## MCP: read-only, by construction

The MCP endpoint is `POST /mcp` (JSON-RPC 2.0). Every tool it offers **reads**; there is no write
tool any more, and one is not coming back over MCP. An agent can ask questions; only the person
behind the browser page changes the firewall.

Tools an agent can call:

| Tool | Answer |
|---|---|
| `status` | protection, policy, learning, store counts, elevation |
| `rules.list` | the whole rule list (name, action, pattern, narrowing fields) |
| `rules.share` | one rule as a Base64 string, for copy and paste |
| `detected.list` | applications no rule speaks about yet (learning mode collects them) |
| `events.list` | recent connections; loopback traffic is already filtered out |
| `profiles.list` | the active profile and the names of the stored profiles |

What MCP is **not** allowed to do: add, remove or import rules, change settings, switch profiles,
export, import, shutdown. An MCP request never carries the session token and must not touch a
writing route.

## HTTP API: reads are open to loopback, writes need the browser

Reads (`GET`, plus `HEAD`) are answered to anyone on loopback after a Host-header check (DNS
rebinding guard). They need no token - `GET /api/state` and `GET /api/reverse?ip=<address>`.

Writes (`POST`) are guarded on three fronts, and the session token is the browser's private key:

- **Token**: a 128-bit random value minted at start, living only in process memory. It leaves the
  server exactly once, as the URL fragment of the page the tray icon opens
  (`http://127.0.0.1:8788/#token=<value>`). A fragment is never sent to a server, so no other
  local process can read it off a socket. It lives only in the page's memory: a reload, a
  bookmark or an old window loses it, and that tab then reads but cannot write.
- **Host header**: must name `127.0.0.1:<port>` or `localhost:<port>` - checked on every request,
  reading ones included.
- **Origin header**: required on writes (CSRF guard). `GET`, `HEAD` and `POST /mcp` are exempt
  from token, origin and content type.
- Writing requests must carry `Content-Type: application/json`.

A process that is not the browser (curl, an agent, a script) can read everything on loopback but
cannot write: it never saw the token, and the state body deliberately does not carry it.

## What the firewall decides

- `default_policy = "deny"`: while protection is on, a program with no ALLOW rule cannot connect,
  outgoing and incoming. Exceptions stay reachable: loopback and the IPv6 base functions.
- Programs are recognised by their image path alone. DNS, DHCP and time sync live inside
  `svchost.exe`; since 1.4.4 a rule's `service` field narrows it to named hosted services,
  and a rule without one speaks about the whole program.
- Wildcards `*` and `?` work in application patterns; a pattern beyond the cap (32 installed
  filters) is cut and says so.
- Every rule change is written to `rules.toml` and pushed to the WFP store immediately.

## Rules of engagement for an agent

1. Query over MCP or `GET /api/state`; do not POST a change unless you were told the token.
2. A blocked connection appears in `detected.list`; a permitted one follows a rule.
3. Local (loopback) traffic is invisible on purpose - it never left the machine.
4. The tool is one instance: a second start exits silently, non-zero.
