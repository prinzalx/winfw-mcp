# 1. Getting started

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

winfw-mcp is a rewrite of [simplewall](https://github.com/henrypp/simplewall) in Rust. The C
original is the functional specification, not a code base to port line by line. Instead of a native
GUI it runs a small web server: start it, click the tray icon, and the browser opens the UI. The
same core answers an MCP client, so an agent can allow or deny a connection too.

## What it is, and what it is not

- **Windows only.** No cross-platform abstraction layer; nothing here is written for a second
  operating system.
- **Portable.** No service, no installer, no registry state. One executable.
- **Self-contained.** All settings, rules and logs live in `%APPDATA%\winfw-mcp`.
- **English only.** Code, identifiers, UI strings and documentation.

## Requirements

The `x86_64-pc-windows-msvc` toolchain and an MSVC linker. Visual Studio Build Tools are enough;
Visual Studio itself is not needed.

## Build, test, run

```
cargo build
cargo test
cargo run
```

Run the tests one at a time and elevated:

```
cargo test -- --test-threads=1
```

One test drives the real store through `WfpWorker`, and an unelevated process is refused there, so
that test fails without administrator rights for reasons that have nothing to do with the code.
Several test processes at once are worse than useless: they all write to the same live store, and
the result then depends on which of them finished last.

## Commands

```
winfw-mcp            load rules.toml and install it in the live store, then exit
winfw-mcp --serve    run the web server until stopped
winfw-mcp --clear    remove our filters from the live store
winfw-mcp --help     print the usage text (`-h`)
winfw-mcp --version  print the version (`-V`)
```

An unknown flag is an error rather than a shrug, so a mistyped option cannot silently install
filters nobody asked for. Only one `--serve` may run at a time: a second start finds the first,
opens the browser on it, and exits. See [the lifecycle chapter](08-lifecycle.md#only-one-at-a-time).

## Elevation

An apply needs elevation: without it the store reports access denied and the rules are not
installed. [The WFP internals](07-wfp-internals.md#reading-the-store-needs-elevation) describe what
that degraded state looks like and why the UI shows a banner instead of an empty list.

---

Next: [2. Data and configuration](02-data-and-configuration.md)
