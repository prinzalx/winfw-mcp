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

## Status

Milestone 3 of 10. The tool owns its data directory, reads its config and rules, reads the live
WFP store, and translates `rules.toml` into persistent WFP filters. It has no UI yet.

| # | Milestone | State |
|---|---|---|
| 0 | Toolchain: Rust builds an `.exe` | done |
| 1 | Data directory, config and rules load, atomic writes | done |
| 2 | WFP read path: open the engine, enumerate providers, sublayers, filters | done |
| 3 | Rules model and write path: `rules.toml` ↔ WFP | done |
| 4 | HTTP server and web UI shell | next |
| 5 | Live connection events over SSE | planned |
| 6 | Learning mode: Detected list, Allow / Deny / Edit | planned |
| 7 | Tray icon and start popup | planned |
| 8 | Export and Base64 Share | planned |
| 9 | MCP endpoint | planned |
| 10 | Named profiles | planned |

## Build and run

Requires the `x86_64-pc-windows-msvc` toolchain and an MSVC linker (Visual Studio Build Tools are
enough; Visual Studio itself is not).

```
cargo build
cargo test
cargo run
```

### Commands

Until milestone 4 puts the web server in front of it, the two store operations are command line
flags. Both are the operations the web UI will expose first as well. An apply needs elevation:
without it the store reports access denied and the rules are not installed.

```
winfw-mcp            load rules.toml and install it in the live store
winfw-mcp --clear    remove our filters from the live store
```

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
    learn.bin            collected Detected entries (learning mode)
    logs\                rotating log files
    export\              destination for on-demand exports
```

`RUST_LOG` overrides `log_level` from `config.toml` for a single run. Logging goes to stderr,
because stdout belongs to the MCP stdio transport.

### Reading the store needs elevation

Measured on Windows 11: an unelevated process opens the WFP engine without problem, but every read
answers access denied and every write is refused. So `cargo run` in a plain shell logs a warning per
store class, prints no filters and reports `WFP write refused`, while an elevated run lists the
store and installs the rules. That is a supported degraded state, not a failure, and the web UI will
say so on a banner instead of showing an empty list.

## Data model decisions

- **Load once, write immediately.** All settings are read at startup; every change made in the web
  UI is written straight back to disk. No save button, no dirty state.
- **Atomic writes.** Files are written to `*.tmp` and renamed, so a crash never leaves a half
  written config behind. This matters because the WFP filters we install are persistent and
  outlive the process.
- **Unknown config keys are an error,** not a warning. A typo in `config.toml` fails loudly instead
  of quietly keeping the default.
- **Store classes are reported separately.** WFP grants read access per class, so providers,
  sublayers and filters each carry their own result. A refused provider store is not a reason to
  throw away the filters we did read.
- **Wildcards are ours, not the kernel's.** Rules match on `*` and `?`; the translation to WFP is
  done by this program, in one place.

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
