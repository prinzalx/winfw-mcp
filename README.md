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
MCP agent talks JSON-RPC to `POST /mcp`. Rules are organised into named profiles, protection can be
paused from the page or from the tray menu, and stopping the tool — from either — leaves the filters
in place. A rule file written by the C original can be read in with `--import <file>`.

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

The current release is **0.61.0**: the tool now starts as a firewall. `default_policy` defaults to
`deny`, so an application no ALLOW rule mentions cannot connect, outbound or inbound, and the policy
is stated in the page header instead of hiding in the settings — *Programs without a rule are
blocked*. Loopback and the IPv6 base functions stay reachable, and Pause protection remains the
not-a-firewall switch for anyone who locks themselves out. Before it,
**0.59.0** ended a second start quietly: no browser, no token exchange, one warning in the log and a
non-zero status. Before it, **0.58.0** moved the session token out of `/api/state` and into the URL
fragment the tray opens, so a local process can no longer read the right to write off the state body
with `curl`. Before those, **0.57.0** made a profile written by the C original readable: `--import
<file>` takes the XML simplewall exports and replaces the rule file of the active profile with
them; nothing reaches the live store, so the result is looked at on the page first. **0.56.0**
let a rule name a span of addresses — `remote` took one address or one network, and a network
cannot cover nine hosts without also covering the fifteen around them, so `10.0.0.1-10.0.0.9` is
now written, stored, shown and installed as a range condition. Before it, **0.55.0** made the
Detected list follow the profile: an entry is a question about the rules that are live, so each
profile keeps its own list, while the set of applications a wildcard expands against stays shared,
because that is a fact about the machine. Before it, **0.54.0** named and tested the decision that
tells the tool whether the shell granted an elevated restart. Earlier changes of behaviour: a rule learned to
name any transport (`protocol` takes a number from 1 to 255, which is how a rule about GRE (47) or
ESP (50) is written, 0.51.0), a drive mounted after the tool started became findable (a lookup that
misses re-asks the system for the drive-to-device table and retries, 0.50.0), an unelevated run
learned to raise itself (`POST /api/relaunch` shows the UAC dialog and stops this process when the
shell grants it, 0.49.0), two pages open on the same rules list stopped overwriting each other
silently (the state reports a `generation`, and a whole-list write that names a stale one is
answered `409`), the rules table learned to be reordered, and the connection feed learned to say
when it last spoke — `running, 128 events, last event 42s ago`. The startup diff names the rules
added, removed or flipped while the tool was closed. An export names the profile its rules came
from, the firewall can be paused from the page or the tray, and a rule can carry a `comment`. The
handbook reads like an operating manual rather than a development diary, and the release history
has its own file, [CHANGELOG.md](CHANGELOG.md).
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) is a brief for an outside reviewer of the request
path; the security chapter it reviews is
[the security model](docs/10-security-model.md#the-guard).

Every release since **0.1.0** is listed with what changed in the
[changelog](CHANGELOG.md). What is known to be missing or fragile is collected in the
[backlog](BACKLOG.md), ranked in its last section.
