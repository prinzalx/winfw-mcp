# 9. Development

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

## Layout

```
src/main.rs       argument parsing, startup, the one-shot store commands
src/config.rs     settings, `mcp_writes`
src/paths.rs      the data directory and every path inside it
src/rules.rs      rules.toml and the profile files
src/store.rs      atomic file writes
src/device.rs     device path <-> drive path
src/learn.rs      the Detected list
src/monitor.rs    the net-event subscription and the event log
src/server.rs     HTTP transport, routes, the accept loop, the WFP worker
src/mcp.rs        the JSON-RPC grammar of the MCP endpoint
src/export.rs     export, Base64 share and import
src/tray.rs       the notification-area icon and its message window
src/wfp.rs        every Fwpm* call
web/index.html    the single page, embedded in the binary
```

`src/server.rs` is a transport by rule: it reads and writes the files and forwards store work to the
WFP worker, but it decides nothing about the firewall.

## Tests

```
cargo test -- --test-threads=1
```

Exactly one test process at a time, and elevated. Both halves of that sentence matter: see
[getting started](01-getting-started.md#build-test-run). CI runs a plain `cargo build --all-targets`
and `cargo test` on a Windows runner, which is elevated, so the store test reads real entries there
instead of reporting access denied.

`cargo fmt --check` is expected to be clean. Clippy is not part of CI, and has a handful of
pre-existing warnings; new code is expected to add none.

## Releases

Every milestone is released: version bumped in `Cargo.toml`, `README.md` updated, tagged, pushed,
and a GitHub release written. The version in `Cargo.toml` is the source of truth. A fix to a
released milestone is a patch release of its own, which is why some versions have no milestone of
their own.

## Version history

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
| 0.11.0 | Stopping the tool: `POST /api/shutdown`, a `Quit` button, and a `Quit` on the tray that ends the process rather than only its tray thread |
| 0.11.1 | Documentation split into chapters under `docs/`; the README is the index rather than every answer |
| 0.11.2 | `learn_mode` is honoured: with it off the Detected list stays empty while the connection log keeps filling, and the page says learning is off |
| 0.11.3 | A busy port no longer ends the app: the server falls forward to the next free port and the tray opens the port it actually got |
| 0.11.4 | Wildcard rules are rebuilt when a new application turns up, learned or not, and the store is rebuilt from the rules at startup |
| 0.12.0 | `default_policy` in `config.toml`: `deny` installs the base block plus the loopback, 6to4 and ICMPv6 permits, so an application no rule mentions is denied |

---

Previous: [8. Lifecycle and tray](08-lifecycle.md) · Back to the [index](../README.md)
