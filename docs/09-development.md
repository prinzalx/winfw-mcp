# 9. Development

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

## Layout

```
src/main.rs       argument parsing, startup, the one-shot store commands
src/config.rs     settings
src/paths.rs      the data directory and every path inside it
src/rules.rs      rules.toml, the profile files, and the stamp that records who wrote them last
src/store.rs      atomic file writes
src/device.rs     device path <-> drive path
src/learn.rs      the Detected list
src/log.rs        the bounded log file, rolled at a megabyte
src/monitor.rs    the net-event subscription and the event log
src/server.rs     HTTP transport, the request guard, routes, the accept loop, the WFP worker
src/mcp.rs        the JSON-RPC grammar of the MCP endpoint
src/export.rs     export, Base64 share and import
src/tray.rs       the notification-area icon and its message window
src/wfp.rs        every Fwpm* call
web/index.html    the single page, embedded in the binary
assets/           the icon: `winfw-mcp.ico` and the script that generates it
build.rs          the Windows resource: the icon and the version information
```

`src/server.rs` is a transport by rule: it reads and writes the files and forwards store work to the
WFP worker, but it decides nothing about the firewall.

## Tests

```
cargo test -- --test-threads=1
```

Exactly one test process at a time, because the store tests share one live WFP store: see
[getting started](01-getting-started.md#build-test-run). Elevation is not needed for a green run — a
store that answers `0x80070005` is a result the tests understand, and the Detected-list tests assert
what follows from it rather than failing over it. It is needed to see the store itself: on an
elevated runner `cargo build --all-targets` and `cargo test` read and write real entries, and an
elevated `--serve` is the only way the event subscription fires at all.

`cargo fmt --check` is expected to be clean. Clippy is not part of CI, and has a handful of
pre-existing warnings; new code is expected to add none.

## The icon and the version information

A portable executable has no installer to give it a logo, so `build.rs` compiles one in:
`assets\winfw-mcp.ico` becomes the executable's icon resource and the version fields `propsheet`
reads, with the numbers taken from `Cargo.toml`. The same file is served to the browser as
`/favicon.ico`, so tray, shell and browser tab all show one logo from one source.

The icon is generated rather than drawn by hand — `python assets/make_icon.py` rewrites it. A disc
with a brick pattern, because a firewall is a wall and 16 pixels do not reward imagination.

`build.rs` needs a resource compiler (`rc.exe` from the Windows SDK, or `windres`). Both CI and a
developer machine with the MSVC toolchain have one. Without either, `winresource` panics with a
message naming the missing tool rather than producing an exe with no icon at all.

## Releases

Every milestone is released: version bumped in `Cargo.toml`, `README.md` updated, tagged, pushed,
and a GitHub release written. The version in `Cargo.toml` is the source of truth. A fix to a
released milestone is a patch release of its own, which is why some versions have no milestone of
their own.

## Version history

| Version | Milestone |
|---|---|
| 0.37.0 | Only traffic that left the machine is shown (§12, chapters 5 and 7). A connection over a loopback address is dropped in the monitor's callback before the log, the seen list and the Detected list are touched, so the connection panel, the event counter, learning mode and MCP cannot disagree about it; an event with no remote address is kept, because an unfilled destination is not evidence of a local connection. A destination on the local segment is kept and marked `local network` with a checkbox on the page to hide those rows, and `debug_show_loopback` in `config.toml` keeps the loopback events for a diagnosis run |
| 0.36.0 | The MCP endpoint is read-only and the HTTP API is guarded (§3.6, chapter 10). The nine writing MCP tools are gone from the code rather than gated: `mcp_writes` in `config.toml` retired with them, still accepted so an older file loads. Every route now checks `Host`, and every writing route additionally checks `Origin`, `content-type: application/json` and a session token that lives only in memory; `/mcp` gets no token and can reach no writing route. `rules.toml.stamp` records the fingerprint of the file the tool wrote last, so a hand edit made while the tool was closed is announced in a banner instead of adopted silently, and the same comparison while it runs notices an edit between two page loads |
| 0.35.0 | The engine open waits for the Base Filtering Engine now (§3.5). PLAN.md §5 asked for the retry and the worker thread made exactly one attempt for the life of the process, so a run started before the service was ready served its whole session with a "store unavailable" banner. Five attempts over 3.7 seconds now, in `Engine::open_retrying`; the retry loop is generic over the attempt and over its sleep, so the wait policy is under test without an engine, and the comment claiming a retry was pointless "until there are writes to protect" — untrue since milestone 3 — is gone |
| 0.34.0 | A body the server cannot read is the client's fault now (§3.2). An unreadable theme, a misspelled field or a JSON syntax error in a POST answered `500 Internal Server Error`, which told the user the server had broken; the body-parsing half of every route answers `400 Bad Request` now, and the refusal text carries the parse error along. A failure that is not about the body — a refused store, a rule index past the end — stays `500`, because the mapping now runs through one helper instead of one call site per shape of failure |
| 0.33.0 | Export got its second half (§3.3). `POST /api/rules/replace` and the MCP `rules.import` tool take the text of a whole rules file and replace the live list with it, read by the same reader that reads `rules.toml` at startup, so a version, a field name or a pattern this build cannot read is refused before the file on disk is touched, and the generation that is replaced is kept as the backup. The page gained a `Restore` button with a file chooser and a confirmation, because this is the one action that can take rules away rather than only fail to add them |
| 0.32.0 | The theme reaches the page (§3.2). `theme` was written to `config.toml`, reported in the state and used by nothing; it is now an enumerated setting of `light`, `dark` or `auto` rather than a free string, the header cycles the three with a click, and `auto` follows the operating system. The choice applies in the same request and survives a reload, `GET /api/state` and MCP `status` report it, and a name neither endpoint can read is refused rather than stored unseen. `port` and `log_level` are the settings that remain file-only |
| 0.31.0 | The rebuild at startup reports itself (§3.1). Its counts were already there and only ever reached the log; they are kept now, so `GET /api/state` and MCP `status` carry what the store held against what the rules describe, and the page says so under the store banner. It keeps quiet on an unchanged restart, and a refused store stays the banner's business rather than getting a second, emptier notice |
| 0.30.0 | Export covers the stored profiles (§3.3). `export` takes a `profiles` area, and the default `all` area now walks into `export\profiles\`, because a set of equal files flattened next to `rules.toml` cannot be told apart in a backup afterwards. An empty profiles directory exports nothing and leaves no directory behind, and the names come from the same sorted list the Profiles area reads |
| 0.29.0 | The MCP endpoint can edit the rule list (§3.6). `rules.remove` takes the rule at an index out of the file and rebuilds the store, so an agent has a way to clean up; `rules.decode` is the read direction of a share string and appends the rule only when told to with `add`; and `rules.allow` and `rules.deny` now dismiss the Detected entry they decided, which the browser had always done and the endpoint had not. An index past the end is refused by name, because an agent that counted from an older `rules.list` needs to hear its picture was stale |
| 0.28.0 | Profiles became manageable from the browser (§3.4). `New` copies the live rules into a new profile and switches to it, `Rename` moves the file and its backup, `Delete` takes both out and falls back to `rules.toml` when the deleted profile was the live one; a name already in use is refused rather than overwritten, and the unnamed default is refused for rename and delete because `rules.toml` is what the tool falls back to |
| 0.27.0 | The event feed reports itself (§3.1). The monitor publishes what subscribing did — `starting`, `running`, `refused` with the code that refused it, `stopped` — together with how many events the log took in, so the page says `no feed: 0x00000005` next to an empty connection list instead of leaving it a mystery, and the MCP `status` tool answers with the same value from the same helper |
| 0.26.0 | The log rotates (§3.2). Lines go to `logs\winfw-mcp.log` and to the console; past a megabyte the live file moves to `winfw-mcp.log.1` and writing starts over, so a run that nobody watches leaves at most two files behind. A log that will not open is reported on the console rather than refused as a startup failure, which is what the startup lines the old ad-hoc helper wrote are now part of |
| 0.25.0 | The connection table is complete. An event now also carries the local endpoint and a `loopback` marker: each endpoint is read only when the header says it filled it, so an end the event did not name is empty rather than the `0.0.0.0` a zeroed union would otherwise report, and the loopback marker comes from the classify arm that names the deciding filter. The page shows `local -> remote`, marks a connection that never left the machine, and drops an endpoint it has nothing about |
| 0.24.0 | Storage hardened (§4.4). A rule file names the version that wrote it (`version = 1`; an older file without the line still reads, a newer one is refused with both versions named), every rule-file write keeps the generation before it as `<name>.bak`, and a rule file that cannot be parsed at startup falls back to that backup with a warning rather than failing to start. A pattern is checked on the way in — an absolute path, no control character and none of `" < > |` — on the page, on the HTTP API, over MCP and on import, so a typo is a refusal rather than a rule that matches nothing |
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
| 0.11.0 | Stopping the tool: `POST /api/shutdown`, a `Quit` button, and a `Quit` on the tray that ends the process rather than only its tray thread |
| 0.11.1 | Documentation split into chapters under `docs/`; the README is the index rather than every answer |
| 0.11.2 | `learn_mode` is honoured: with it off the Detected list stays empty while the connection log keeps filling, and the page says learning is off |
| 0.11.3 | A busy port no longer ends the app: the server falls forward to the next free port and the tray opens the port it actually got |
| 0.11.4 | Wildcard rules are rebuilt when a new application turns up, learned or not, and the store is rebuilt from the rules at startup |
| 0.12.0 | `default_policy` in `config.toml`: `deny` installs the base block plus the loopback, 6to4 and ICMPv6 permits, so an application no rule mentions is denied |
| 0.13.0 | Settings became writable: `POST /api/settings` and the MCP tool `settings.set` change `learn_mode` and `default_policy` on a running process, write `config.toml`, and rebuild the store; the page header shows both as clickable toggles, and an unknown field is refused rather than ignored. CI runs the tests single-threaded, which is what the two live-store tests always needed |
| 0.14.0 | Rules gained three optional dimensions: `protocol` (`tcp`/`udp`), `direction` (`in`/`out`) and `port` (a single port or a range such as `1024-2048`). They are real conditions rather than labels — direction picks the layers a rule is installed on, protocol and port become WFP filter conditions — and they travel through the file, the page, the HTTP API, Share/Import and MCP. A value the server cannot read is refused instead of quietly meaning "any" |
| 0.15.0 | Rules gained the fourth dimension, `remote`: an address or network such as `10.0.0.5` or `192.168.1.0/24`, in either family. Host bits are dropped while it is read, so the file holds the network the filter matches, and it narrows the layers to its own address family on top of what `direction` picked. It is a real `FWPM_CONDITION_IP_REMOTE_ADDRESS` condition with an address-and-mask, and it travels through the file, the page, the HTTP API, Share/Import and MCP like the other three |
| 0.16.0 | Only one serving instance at a time. The first `--serve` claims a private named mutex for the session and writes the port it listens on to `server.port` in the data directory; a second start sees the claim, reads that port, asks the shell for a browser on the running UI and exits successfully rather than binding a socket nobody asked for. The mutex is released and the file removed when the server stops, and a stale file left by a hard kill is simply ignored |
| 0.17.0 | The tool has a face. `assets\winfw-mcp.ico` is generated by `assets/make_icon.py` and compiled into the executable by a new `build.rs`, which also writes the version information `propsheet` reads, with the numbers taken from `Cargo.toml`. The tray loads that resource instead of the system's default icon, and the same bytes answer `GET /favicon.ico`, so tray, shell and browser tab show one logo from one file |
| 0.23.0 | The process answers `--help` and `--version` (`-h`, `-V`). Both print and exit successfully before any argument parsing that could fail, so the version of an installed binary can be read without elevation and without touching the store. An unknown flag now points at `--help` in its error text |
| 0.22.0 | `volatile_filters` arrived. A server run with the setting on takes our filters out of the store when it stops, so the tool is a firewall only while it runs; the persistent default is untouched, and a killed volatile run is cleaned up by the next start's startup cleanup. The dynamic-session variant was tried first and rejected: a session handle refuses persistent providers and sublayers, which is exactly what our store layout is built on |
| 0.21.0 | The tray menu grew. The right button now offers `Open`, `Pause learning` and `Quit`; the pause flips the running `learn_mode` flag without writing `config.toml`, so it lasts for this run only and the menu label is read from the flag every time the menu opens |
| 0.20.0 | Learning mode notices a destination. An application an enabled rule covers is collected again when it reaches an address none of its own rules reaches: the Detected entry carries a `remote`, allow and deny turn it into a rule that names that destination, and the entry identity is application plus destination. `Cidr::contains` answers the question, with both sides left-aligned into a `u128` so a v4 prefix masks the same bits as a v6 one |
| 0.19.0 | A connection event names where it went. The remote address is read out of the union arm `ipVersion` selects — one `u32` for v4, sixteen bytes for v6 — and reported as `remote_addr` in the log, the API, the stream and `events.list`, so two connections from one application to two networks are told apart. The page shows it as `address:port` |
| 0.18.0 | An event says which rule decided it. Every filter `apply` installs is recorded against the rule it came from, the WFP worker republishes that table on every rebuild, and the monitor reads an event's `filterId` back through it. A connection line now carries `filter_id` and, for one of our filters, the rule name, so "blocked by rule X" is honest; a non-zero id we do not know reports "by other" rather than guessing |

---

Previous: [8. Lifecycle and tray](08-lifecycle.md) · Next: [10. Security model](10-security-model.md)
