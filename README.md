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
[JOURNAL.md](JOURNAL.md) the diary of the release rounds that produced the tool,
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
paused from the page or from the tray menu. `Quit` takes the tool's filters out of the store with it,
so the machine is as it was before it ran; `POST /api/shutdown` is the stop that leaves them in
place. A rule file written by the C original can be read in with `--import <file>`, and a run without
parameters only prints what it understands.

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

The current release is **0.73.1**: the expanded connection row shows the protocol its heading had
been promising, and the page's script is now checked for brackets that do not match. That second
part closes the long-standing question of how to notice a page that no longer *parses* without
putting a JavaScript parser and a build step into a tool that has neither.

Before it, **0.73.0** let a rule name the address this machine talks from. `local` takes the same
three text shapes `remote` has always taken (`10.0.0.5`, `10.0.0.0/24`, `10.0.0.1-10.0.0.9`) and is a
rule's fifth narrowing dimension, so a rule about one network interface no longer has to be a rule
about everything.

Before it, **0.72.0** named the account behind a connection. WFP hands the user of a
connection to the event callback as a security identifier, and the tool now resolves it, so a row
says `waterfox.exe` *run as* `CORP\alice` rather than the program alone. The lookup is cached, runs
after the loopback drop, and falls back to the SID text when it fails. It reaches the page, the
state endpoint and the MCP's `events.list`.

Before it, **0.71.0**: the Detected list reaches the page whole. `/api/state` answered
the newest twenty entries while the list on disk holds a hundred, so forty-seven open questions were
decided from twenty and the rest had no way to reach a decision at all. The answer now carries the
same cap the list is kept to, so the two numbers cannot drift apart again, and `detected_total`
still counts everything for the badge.

Before it, **0.70.0**: the last piece of the reference's file format arrived. `rules.toml` carries a
checksum of its own body, so a file edited by hand or torn by a bad write says so in the log and in
the UI rather than being taken over quietly.

Before that, **0.69.0**: the three things a manual start asked for. Without parameters the
tool now prints its parameters and the shortest start instead of rewriting the live store, an
unelevated start asks for administrator rights rather than limping along with an unreadable store,
and `Quit` takes our filters out of the store so the machine ends as it was found. The stop that
keeps the installed rules is still there as `POST /api/shutdown`.

Before it, **0.68.0**: a backlog finding closed by reading the code, not by changing it.
The note claimed that tests write into the running tool's data directory because `DataPaths::resolve()`
knows only `%APPDATA%\winfw-mcp`. It does, and `main` is its only caller — every test that touches a
file works in a scratch directory already, so nothing had to be fixed and the `WINFW_DATA` override
this note asked for was not added.

Before it, **0.67.0**: a rules file that cannot be parsed says so in the log. The
fallback to the previous generation has been warned about since 0.24.0, but the rule file was read
before the log subscriber existed, so the warning was dropped and the page showed the backup's rules
while the file on disk held something else.

Before it, **0.66.0**: the page is checked against its own markup. Nothing noticed for
twelve releases that the page's script had stopped parsing, because the static HTML keeps rendering
whether or not the script runs. A test now collects every element id the embedded script asks for and
asserts the markup declares each of them, and renaming one id was verified to fail it.

Before it, **0.65.0**: the Detected list answers the questions asked most recently. The
tab listed the twenty entries that were *collected* first, and an entry a repeat connection merely
refreshes keeps its place, so a program running for a week had its newest question at the bottom of
the list and never reached the page — blocked and undetected at the same time. The list is now
ordered by the time it was last seen before it is cut, and `detected_total` counts every open entry,
so a badge can read `47+` rather than a number that is quietly too small.

Before it, **0.64.1**: the tray icon says what it is doing. Hovering now reads
`winfw-mcp — protection on, learning on — http://127.0.0.1:8788/` and is refreshed every two
seconds, every event the shell reports is logged so that "clicking does nothing" can be decided
after the fact, and the right-button menu is tracked so it cannot close before it is read. Before
it, **0.64.0**: the page reads like an operating manual. Presentation only — no
route, field, status code or behaviour moved. One row of header with three chips (protection, policy,
learning) replaced the header sentence, the four areas became tabs, and the page opens on Detected
whenever an entry is waiting there. Connections are grouped by program with the verdict and Allow/Deny
per program, the rules table is edited in a dialog, the Detected cards put Allow and Deny first, and
Settings hold the switches plus a Tools group where Clear and Quit ask first. The policy chip says
*Block unknown* in green under `deny` and *Allow unknown* in yellow under `allow`, with the loopback and
IPv6 exceptions in its tooltip, and responses carry a `Content-Security-Policy` of `default-src 'self'`.
Before it, **0.63.0** made a click on the tray icon do what it says: the shell reports the icon event in
the low word of the callback and the icon id in the high word, but the window procedure read only the
high word, so a click matched the icon id against a mouse message and did nothing; both words are read
now, the icon declares version 4 so the shell sends `NIN_SELECT` and `WM_CONTEXTMENU` at all. Before
that, **0.62.0** made one application one Detected
entry, comparing paths without regard to case, so `C:\Test\Tool.exe` and `c:\test\tool.exe` collect
into one entry, one dismiss and one decision. Before that, **0.61.0** made the tool start as a
firewall: `default_policy` defaults to `deny`, so an application no ALLOW rule mentions cannot
connect, outbound or inbound, and the policy is stated in the page header instead of hiding in the
settings. Before that, **0.60.0** made a wildcard pattern that exceeds the cap of 32 say so in the
log, in `/api/state` and under the pattern box, and **0.59.0** ended a second start quietly: no
browser, no token exchange, one warning in the log and a non-zero status. Before those,
**0.58.0** moved the session token out of `/api/state` and into the URL fragment the tray opens, so
a local process can no longer read the right to write off the state body with `curl`, and
**0.57.0** made a profile written by the C original readable through `--import <file>`. **0.56.0**
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
