# 9. Development

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

## Layout

```
src/main.rs              argument parsing, startup, the one-shot store commands
src/config.rs            settings
src/paths.rs             the data directory and every path inside it
src/rules.rs             rules.toml, the profile files, and the stamp that records who wrote them last
src/simplewall.rs        reading the XML profile the C original writes
src/store.rs             atomic file writes
src/device.rs            device path <-> drive path
src/learn.rs             the Detected list
src/log.rs               the bounded log file, rolled at a megabyte
src/monitor.rs           the net-event subscription and the event log
src/instance.rs          one instance at a time, and the port file it publishes
src/elevated.rs          whether this process is elevated, and the ask for an elevated restart
src/export.rs            export, Base64 share and import
src/mcp.rs               the JSON-RPC grammar of the MCP endpoint
src/server/mod.rs        the accept loop, the connection handling, the SSE stream
src/server/http.rs       request, response, headers, body parsing
src/server/guard.rs      the session token and the Host, Origin and content-type checks
src/server/state.rs      the shared state a request thread reads
src/server/worker.rs     the WFP worker: the one thread that owns the engine handle
src/server/routes.rs     the dispatcher and every route's handler
src/server/profiles.rs   create, delete, rename and switch a profile
src/server/settings.rs   a settings change written to `config.toml`
src/server/mcp_tools.rs  the read-only MCP dispatcher over that state
src/tray.rs              the notification-area icon, its start balloon and its message window
src/wfp.rs               every Fwpm* call
src/testutil.rs          a scratch directory for the tests
web/index.html           the single page, embedded in the binary
assets/                  the icon: `winfw-mcp.ico` and the script that generates it
build.rs                 the Windows resource: the icon and the version information
```

The `server` directory is a transport by rule: it reads and writes the files and forwards store work
to the WFP worker, but it decides nothing about the firewall. The split exists so that the two
files worth reviewing on their own are small: `guard.rs`, which is the whole answer to *who may
write*, and `mcp_tools.rs`, which holds no write access to rules, settings, profiles or the store at
all. Nothing outside the directory names more than `crate::server::` re-exports.

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

Test code lives in the same files as the code it checks and ships nowhere: `serve_once`, the
`testutil` scratch directory, `server::testsupport` and every `mod tests` are `#[cfg(test)]`,
so the release executable carries none of it and a separate test crate would buy nothing.

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

The history of every release lives in the [changelog](../CHANGELOG.md), newest first. This
chapter answers how development works; the changelog answers what it produced.

Previous: [8. Lifecycle and tray](08-lifecycle.md) · Next: [10. Security model](10-security-model.md)
