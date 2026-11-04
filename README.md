# winfw-mcp

**A portable, web-driven Windows Firewall (WFP) controller with an MCP interface.**

Instead of a native GUI it runs a small web server: start it, a balloon names the address next to
the tray icon, a click on that icon opens the browser, and the same core answers an MCP client over
JSON-RPC, which is where a local agent reads the firewall.

- Target platform: **Windows only**, no cross-platform abstraction layer
- Runs **portable**: no service, no installer, no registry state
- All settings, rules and logs live in `%APPDATA%\winfw-mcp`
- Everything in the repo is English: code, identifiers, UI strings, docs

## Starting it

Double-click the executable. That is the whole procedure: the tool asks for administrator rights,
puts an icon in the notification area, and the icon opens the page. A second start while one is
running ends quietly, and `Quit and remove rules` in the tray menu takes the tool's filters out of
the store so the machine is as it was before it ran.

From a shell, in a release build the console closes with the process, so start it in the background:

```
winfw-mcp.exe                    # serve, and that is all a start needs
winfw-mcp.exe --help             # every parameter, and nothing else
```

## Building it

```
cargo build --release
cargo test -- --test-threads=1
```

The tests touch the live WFP store, so run them serially and not while an instance is serving.

## The handbook

The documentation is split into chapters, so that each question has one place to be answered.

| Chapter | Answers questions about |
|---|---|
| [1. Getting started](docs/01-getting-started.md) | what the tool is, requirements, building, the commands |
| [2. Data and configuration](docs/02-data-and-configuration.md) | the data directory, `config.toml`, log level, atomic writes |
| [3. Rules and profiles](docs/03-rules-and-profiles.md) | rule order, deny over allow, wildcards, device paths, profiles |
| [4. Learning mode](docs/04-learning-mode.md) | the Detected list and how an application becomes a rule |
| [5. The web UI](docs/05-web-ui.md) | the page, what is on it, which connections it shows, and every HTTP route |
| [6. The MCP endpoint](docs/06-mcp-endpoint.md) | JSON-RPC methods, the tool list, why the endpoint only reads |
| [7. WFP internals](docs/07-wfp-internals.md) | elevation, our filters, applying, the event stream and what it keeps, filter attribution, threading |
| [8. Lifecycle and tray](docs/08-lifecycle.md) | starting, the tray icon, stopping, what stays behind |
| [9. Development](docs/09-development.md) | source layout, tests, the release process |
| [10. Security model](docs/10-security-model.md) | the session token, Host and Origin checks, what is protected, what an agent can see and what is not |

Working documents next to this index: [CHANGELOG.md](CHANGELOG.md) is the release-by-release history
and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) the brief for an outside review of the request path.
The plan that started the tool, the diary of the release rounds that produced it and the list of
open points are working files kept off this repository, so they are named in prose rather than
linked. The release process, including how a patch on an ignored file is released, is in
[chapter 9](docs/09-development.md).

## Status

The tool owns its data directory, reads its config and rules, reads the live WFP store, translates
`rules.toml` into persistent WFP filters with deny ranked above allow, and serves a web UI that
edits those rules. It follows live connections over SSE — only the ones that leave the machine —
and learning mode collects every application no rule speaks about yet in a Detected list, where each
entry can be allowed, denied or dismissed from the browser. In a release build it runs without a
console window and lives as a tray icon. Any area can be copied into `export\` on demand, one rule
travels as a Base64 string, and an MCP agent talks JSON-RPC to `POST /mcp`. Rules are organised
into named profiles, and protection can be paused from the page or from the tray menu.

A rule matches an application path with `*` and `?`, a remote address, network, range or list, a
local address, a port or list of ports, a protocol number, and a direction. `default_policy` is
`deny`, so an application no ALLOW rule mentions does not connect.

The MCP endpoint reads only, on purpose: an agent that could write a rule could open its own gate,
and that is the one thing a firewall in front of an agent should not allow.

Every release since **0.1.0** is listed with what changed in the
[changelog](CHANGELOG.md). What is known to be missing or fragile is kept in a working backlog that
is not published here, because an open point in a firewall is a finding a reader could work with.
