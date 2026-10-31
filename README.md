# winfw-mcp

**A portable, web-driven Windows Firewall (WFP) controller with an MCP interface.**

A rewrite of [simplewall](https://github.com/henrypp/simplewall) in Rust. The C original is the
functional specification, not a code base to port line by line. Instead of a native GUI it runs a
small web server: start it, click the tray icon, the browser opens the UI. The same core is later
exposed over MCP, so an agent can allow or deny a connection too.

- Target platform: **Windows only**, no cross-platform abstraction layer
- Runs **portable**: no service, no installer, no registry state
- All settings, rules and logs live in `%APPDATA%\winfw-mcp`
- Everything in the repo is English: code, identifiers, UI strings, docs
- Plan and rationale: [PLAN.md](PLAN.md)
- Collected follow-ups: [BACKLOG.md](BACKLOG.md)

## Status

Milestone 10 of 10, all of them done. The tool owns its data directory, reads its config and rules, reads the live
WFP store, translates `rules.toml` into persistent WFP filters with deny ranked above allow, and
serves a web UI that edits those rules. It follows live connections over SSE, and learning mode
collects every application no rule speaks about yet in a Detected list where each entry can be
allowed, denied or dismissed from the browser. In a release build it runs without a console window
and lives as a tray icon: left click opens the browser, right click offers `Quit`. Any area can be
copied into `export\` on demand, and one rule travels as a Base64 string you can paste anywhere.
The same core answers a second client: an MCP agent talks JSON-RPC to `POST /mcp`. Rules are
organised into named profiles; switching one moves the live rule set to another file and rebuilds
the store, and the choice survives a restart.

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

## Build and run

Requires the `x86_64-pc-windows-msvc` toolchain and an MSVC linker (Visual Studio Build Tools are
enough; Visual Studio itself is not).

```
cargo build
cargo test
cargo run
```

Run the tests one at a time (`cargo test -- --test-threads=1`) and elevated. One test drives the
real store through `WfpWorker`, and an unelevated process is refused there, so that test fails
without administrator rights for reasons that have nothing to do with the code.

### Commands

```
winfw-mcp            load rules.toml and install it in the live store, then exit
winfw-mcp --serve    run the web server until stopped
winfw-mcp --clear    remove our filters from the live store
```

An apply needs elevation: without it the store reports access denied and the rules are not
installed.

In a release build the binary is a Windows program rather than a console one, so starting it shows
no terminal window at all: `--serve` puts an icon in the notification area, a left click on it opens
the browser on the UI, and the right button offers `Quit`. Debug builds keep the console, because
that is where the log goes while the tool is being developed.

Applying is a full rebuild, not a diff: our filters are removed and re-added in rule order inside
one transaction, so the order in `rules.toml` is exactly the order WFP evaluates. Because the
filters are persistent, `--clear` is the clean way to take the tool out again.

Re-applying is the normal case, not an error. The provider and sublayer stay in the store after
`--clear`, and both `Fwpm*Add0` calls answer `FWP_E_ALREADY_EXISTS` when they are added again, which
the write path accepts.

### Identifying our filters

Every filter we install belongs to a fixed provider GUID, so a later run can find its own objects
again without a state file. Enumerating them through a `FWPM_FILTER_ENUM_TEMPLATE0` was rejected by
the engine with `FWPM_E_INVALID_ENUM_TYPE`, so the filter list is read whole and the provider key is
compared in code. A filter with no provider key was not added by us.

On the first run the binary creates its data directory and the two files inside it:

```
%APPDATA%\winfw-mcp\
    config.toml          settings, written with defaults on first run
    rules.toml           user rules, order significant: the first match wins
    profiles\            named profiles, one file each
    learn.json           collected Detected entries (learning mode)
    logs\                rotating log files
    export\              destination for on-demand exports
```

`RUST_LOG` overrides `log_level` from `config.toml` for a single run. Logging goes to stderr,
because stdout belongs to the MCP stdio transport.

### Web UI

`--serve` binds `127.0.0.1` on the `port` from `config.toml` (8788 by default) and serves a single
page with no build step, embedded in the binary. Open it, edit a rule, and the change is written to
`rules.toml` and pushed to the store immediately.

| Route | Purpose |
|---|---|
| `GET /` | the page itself |
| `GET /api/state` | settings, rules and what the store reported |
| `POST /api/rules` | replace the rule list: write the file, then rebuild the filters |
| `POST /api/detected` | turn one detected application into a rule and rebuild the store |
| `POST /api/detected/dismiss` | drop a detected application without deciding |
| `POST /api/clear` | remove our filters from the store |
| `POST /api/export` | copy the rules, the config and the Detected list into `export\` |
| `POST /api/rules/share` | one rule as a Base64 string, for copy and paste |
| `POST /api/rules/import` | append the rule a Base64 string carries |
| `GET /api/profiles` | the active profile and the names of the stored profiles |
| `POST /api/profiles/switch` | make another profile live (an empty name selects `rules.toml`) |
| `GET /api/events` | the connection feed as a server-sent event stream |
| `GET /api/health` | liveness, for a supervisor or the MCP transport |
| `POST /mcp` | the Model Context Protocol endpoint (JSON-RPC 2.0) |

### MCP endpoint

`POST /mcp` speaks JSON-RPC 2.0 and needs no session: every request is answered on its own, so
curl is a valid client. `initialize`, `ping`, `tools/list` and `tools/call` are implemented, and a
tool name may be used as the method directly.

| Tool | Purpose | Writes? |
|---|---|---|
| `status` | settings, rule count, store health, how much the endpoint may write | no |
| `rules.list` | every rule, in file order | no |
| `rules.share` | one rule as a Base64 string (takes `index`) | no |
| `rules.allow` | add an allow rule (takes `app`, optional `name`) | yes |
| `rules.deny` | add a deny rule (takes `app`, optional `name`) | yes |
| `detected.list` | what learning mode collected | no |
| `events.list` | recent connection events | no |
| `export` | copy an area (`rules`, `config`, `detected`, `all`) into `export\` | yes |
| `profiles.list` | the active profile and the stored profile names | no |
| `profile.use` | switch the live profile (takes `name`) | yes |

Reads are always allowed. Writes go through `mcp_writes` in `config.toml`, which is `none` by
default: an agent should be able to ask questions before anyone allows it to answer them. A
refused write is not a transport error; it comes back as a normal tool result with `isError` set,
which is what the MCP spec says about a tool that ran and declined. Deny outranks allow, always,
so an agent can loosen a hole but cannot talk its way past a deny.

The Detected list is the learning mode. Every application that connects while no enabled rule
covers it is collected there, with its hit count and whether the firewall allowed or blocked it, and
the newest decision waits at the top. Each row can be allowed, denied or dismissed, and the path in
the row is editable before that, because widening `C:\Program Files\Nodejs\node.exe` to
`C:\Program Files\*\*.exe` is the usual wish. A decided row becomes an ordinary rule in
`rules.toml`, so nothing downstream has to know where a rule came from.

Application paths reach the firewall in device form (`\device\harddiskvolume3\...`), which nobody
reads comfortably, so the UI shows the drive form and a rule written in either form is accepted.

Live connections come from WFP's own event stream (`FwpmNetEventSubscribe4`) on a session of the
monitor's own. Two engine options have to be set on that session first, and both were found the
hard way: without `FWPM_ENGINE_COLLECT_NET_EVENTS` the subscription is accepted but never fires, and
without the classifier keyword in `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS` only blocked
connections are collected at all, so the allowed ones a learning mode needs would be missing. The
options are per session, so the monitor configures its own and leaves the machine alone.

The server is `std` only: one thread per connection, no async runtime. Every request that matters
ends in a blocking WFP call anyway, and a long-lived connection is what SSE needs.
Because a WFP transaction belongs to a thread rather than to a handle, exactly one worker thread
owns the engine handle; request threads hand their work to it over a channel and wait.

### Reading the store needs elevation

Measured on Windows 11: an unelevated process opens the WFP engine without problem, but every read
answers access denied and every write is refused. So `cargo run` in a plain shell logs a warning per
store class, prints no filters and reports `WFP write refused`, while an elevated run lists the
store and installs the rules. That is a supported degraded state, not a failure: `/api/state`
answers `store.ok` with the reason, and the web UI shows a banner instead of an empty list.

## Data model decisions

- **A profile is a file, not a table.** The active profile is a name in `config.toml`; its rules are
  one file in `profiles\`. The unnamed default profile keeps using `rules.toml`, so a config from an
  earlier version needs no migration. Switching writes the current rules back to the file they came
  from before the new one is read, so no rule is ever only in memory.
- **Load once, write immediately.** All settings are read at startup; every change made in the web
  UI is written straight back to disk. No save button, no dirty state.
- **Deny always beats allow.** A deny filter is installed one weight above an allow filter, so a
  matching deny wins even when an allow rule comes earlier in `rules.toml`. Between rules of the
  same action the earlier one still wins, because equal weights are resolved in creation order and
  filters are installed in file order.
- **Atomic writes.** Files are written to `*.tmp` and renamed, so a crash never leaves a half
  written config behind. This matters because the WFP filters we install are persistent and
  outlive the process.
- **Unknown config keys are an error,** not a warning. A typo in `config.toml` fails loudly instead
  of quietly keeping the default.
- **Store classes are reported separately.** WFP grants read access per class, so providers,
  sublayers and filters each carry their own result. A refused provider store is not a reason to
  throw away the filters we did read.
- **Wildcards are ours, not the kernel's.** Rules match on `*` and `?`; the translation to WFP is
  done by this program, in one place. WFP itself compares an application path exactly, so a pattern
  with a wildcard is expanded into the applications learning mode has actually seen, and each of
  them gets its own filter (up to a fixed cap). A pattern nothing was seen for yet is installed as
  it stands, so the rule stays visible even before it can match.
- **Learning mode collects applications, not connections.** One executable that makes a hundred
  connections is one decision. An application an enabled rule already covers is not collected at
  all, because a rule that blocks it is a decision that was already made.

## Releases

Every milestone is released: version bumped here, `README.md` updated, tagged, pushed. The version
in `Cargo.toml` is the source of truth. A fix to a released milestone is a patch release of its
own, which is why some versions have no milestone of their own.

| Version | Milestone |
|---|---|
| 0.1.0 | Data directory, config and rules load, atomic writes |
| 0.2.0 | WFP read path: engine handle, enumeration of the live store, degraded when unelevated |
| 0.2.1 | Fix heap corruption while releasing an enumerated store |
| 0.3.0 | Rules model and write path: `rules.toml` ↔ WFP, full rebuild in one transaction |
| 0.3.1 | Fix the write path: find our filters without a template, accept `FWP_E_ALREADY_EXISTS` |
| 0.3.2 | Deny outranks allow by filter weight, whatever the order in `rules.toml` is |
| 0.4.0 | HTTP server and web UI shell: rules page, JSON API, degraded-store banner |
| 0.4.1 | Show the address the page was served from instead of a hardcoded localhost |
| 0.5.0 | Live connection events: WFP event stream forwarded to the browser over SSE, plus a page markup fix (the script had been outside its element) |
| 0.6.0 | Learning mode: Detected list in the UI, wildcard patterns, device path ↔ drive path translation |
| 0.7.0 | Tray icon without a console window: left click opens the browser, right click offers `Quit` |
| 0.8.0 | Export of any area into `export\`, plus Share and Import of a single rule as Base64 |
| 0.9.0 | MCP endpoint: JSON-RPC 2.0 over `POST /mcp`, read-only by default, gated writes |
| 0.10.0 | Named profiles: `profiles\<name>.toml`, switchable from the UI and over MCP |
