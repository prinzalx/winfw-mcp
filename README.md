# winfw-mcp

**A portable, web-driven Windows Firewall (WFP) controller with an MCP interface.**

A rewrite of [simplewall](https://github.com/henrypp/simplewall) in Rust. The C original is the
functional specification, not a code base to port line by line. Instead of a native GUI it runs a
small web server: start it, a balloon names the address next to the tray icon, a click on that icon
opens the browser, and the same core answers an MCP client over JSON-RPC, which is where a local
agent reads the firewall.

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
| [5. The web UI](docs/05-web-ui.md) | the page, what is on it, which connections it shows, and every HTTP route |
| [6. The MCP endpoint](docs/06-mcp-endpoint.md) | JSON-RPC methods, the tool list, why the endpoint only reads |
| [7. WFP internals](docs/07-wfp-internals.md) | elevation, our filters, applying, the event stream and what it keeps, filter attribution, threading |
| [8. Lifecycle and tray](docs/08-lifecycle.md) | starting, the tray icon, stopping, what stays behind |
| [9. Development](docs/09-development.md) | source layout, tests, the release process |
| [10. Security model](docs/10-security-model.md) | the session token, Host and Origin checks, what is protected, what an agent can see and what is not |

Working documents next to this index: [PLAN.md](PLAN.md) is the plan and its rationale,
[BACKLOG.md](BACKLOG.md) the collected follow-ups and audit findings,
[CHANGELOG.md](CHANGELOG.md) the release-by-release history,
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) the brief for an outside review of the request path.

## Status

Milestones 0 to 10 are all done, and each of them is released. The tool owns its data directory,
reads its config and rules, reads the live WFP store, translates `rules.toml` into persistent WFP
filters with deny ranked above allow, and serves a web UI that edits those rules. It follows live
connections over SSE — only the ones that leave the machine — and learning mode collects every
application no rule speaks about yet in a Detected list, where each entry can be allowed, denied or
dismissed from the browser. In a release build it runs without a console window and lives as a tray
icon. Any area can be copied into `export\` on demand, one rule travels as a Base64 string, and an
MCP agent talks JSON-RPC to `POST /mcp`. Rules are organised into named profiles, and stopping the
tool — from the page, from the tray or over MCP — leaves the filters in place.

The MCP endpoint reads only, on purpose: an agent that could write a rule could open its own gate,
and that is the one thing a firewall in front of an agent should not allow.

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
| 8 | Export, Base64 Share and whole-file Restore | done |
| 9 | MCP endpoint | done |
| 10 | Named profiles | done |

## Releases

The current release is **0.41.0**. Starting the tool now says so: the tray icon arrives with a
balloon naming the address, which is the start popup PLAN.md section 1 promised. The handbook reads
like an operating manual rather than a development diary: version numbers are gone from the chapters
and the release history has its own file, [CHANGELOG.md](CHANGELOG.md).
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) is a brief for an outside reviewer of the request
path; the security chapter it reviews is
[the security model](docs/10-security-model.md#the-guard).

Every release since **0.1.0** is listed with what changed in the
[changelog](CHANGELOG.md). What is known to be missing or fragile is collected in the
[backlog](BACKLOG.md), ranked in its last section.
