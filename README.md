# winfw-mcp

**A portable, web-driven Windows Firewall (WFP) controller with an MCP interface.**

A rewrite of [simplewall](https://github.com/henrypp/simplewall) in Rust. The C original is the
functional specification, not a code base to port line by line. Instead of a native GUI it runs a
small web server: start it, click the tray icon, the browser opens the UI. The same core answers an
MCP client, so an agent can allow or deny a connection too.

- Target platform: **Windows only**, no cross-platform abstraction layer
- Runs **portable**: no service, no installer, no registry state
- All settings, rules and logs live in `%APPDATA%\winfw-mcp`
- Everything in the repo is English: code, identifiers, UI strings, docs

```
cargo build
cargo test -- --test-threads=1
cargo run -- --serve
```

## The handbook

The documentation is split into chapters, so that each question has one place to be answered.

| Chapter | Answers questions about |
|---|---|
| [1. Getting started](docs/01-getting-started.md) | what the tool is, requirements, building, the three commands |
| [2. Data and configuration](docs/02-data-and-configuration.md) | the data directory, `config.toml`, log level, atomic writes |
| [3. Rules and profiles](docs/03-rules-and-profiles.md) | rule order, deny over allow, wildcards, device paths, profiles |
| [4. Learning mode](docs/04-learning-mode.md) | the Detected list and how an application becomes a rule |
| [5. The web UI](docs/05-web-ui.md) | the page, what is on it, and every HTTP route |
| [6. The MCP endpoint](docs/06-mcp-endpoint.md) | JSON-RPC methods, the tool list, who may write |
| [7. WFP internals](docs/07-wfp-internals.md) | elevation, our filters, applying, the event stream, threading |
| [8. Lifecycle and tray](docs/08-lifecycle.md) | starting, the tray icon, stopping, what stays behind |
| [9. Development](docs/09-development.md) | source layout, tests, the release process, version history |

Working documents next to this index: [PLAN.md](PLAN.md) is the plan and its rationale,
[BACKLOG.md](BACKLOG.md) the collected follow-ups and audit findings.

## Status

Milestones 0 to 10 are all done, and each of them is released. The tool owns its data directory,
reads its config and rules, reads the live WFP store, translates `rules.toml` into persistent WFP
filters with deny ranked above allow, and serves a web UI that edits those rules. It follows live
connections over SSE, and learning mode collects every application no rule speaks about yet in a
Detected list where each entry can be allowed, denied or dismissed from the browser. In a release
build it runs without a console window and lives as a tray icon. Any area can be copied into
`export\` on demand, one rule travels as a Base64 string, and an MCP agent talks JSON-RPC to
`POST /mcp`. Rules are organised into named profiles, and stopping the tool — from the page, from
the tray or over MCP — leaves the filters in place.

| # | Milestone | State |
|---|---|---|
| 0 | Toolchain: Rust builds an `.exe` | done |
| 1 | Data directory, config and rules load, atomic writes | done |
| 2 | WFP read path: open the engine, enumerate providers, sublayers, filters | done |
| 3 | Rules model and write path: `rules.toml` ↔ WFP | done |
| 4 | HTTP server and web UI shell | done |
| 5 | Live connection events over SSE | done |
| 6 | Learning mode: Detected list, Allow / Deny / Edit | done |
| 7 | Tray icon and start popup | done |
| 8 | Export and Base64 Share | done |
| 9 | MCP endpoint | done |
| 10 | Named profiles | done |

The current release is **0.11.1**. What is known to be missing or fragile is listed in the
[backlog](BACKLOG.md), ranked in its last section.
