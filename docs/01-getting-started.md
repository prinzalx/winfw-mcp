# 1. Getting started

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

winfw-mcp is a Windows firewall controller written in Rust. Instead of a native GUI it runs a small
web server: start it, a balloon names the address next to the tray icon, and a click on that icon
opens the browser on the UI. The same core answers an MCP client, which is how a local agent reads
the firewall.

## What it is, and what it is not

- **Windows only.** No cross-platform abstraction layer; nothing here is written for a second
  operating system.
- **Portable.** No service, no installer, no registry state. One executable.
- **Self-contained.** All settings, rules and logs live in `%APPDATA%\winfw-mcp`.
- **English only.** Code, identifiers, UI strings and documentation.
- **Distrustful from the first run.** The default policy is `deny`: a program no ALLOW rule mentions
  cannot connect, so a fresh install looks like an empty rules table and a blocked internet until the
  first entry of the Detected list is allowed. Loopback stays reachable, which is why the page still
  loads. `allow` remains one click in the header away for anyone who prefers to watch first.

## Requirements

The `x86_64-pc-windows-msvc` toolchain and an MSVC linker. Visual Studio Build Tools are enough;
Visual Studio itself is not needed.

## Build, test, run

```
cargo build
cargo test
cargo run
```

Run the tests one at a time:

```
cargo test -- --test-threads=1
```

A few tests drive the real store through `WfpWorker`, and an unelevated process is refused there.
That is a result the tests understand rather than one they fail over, so the suite is green either
way — but elevation is what lets them touch the store, and an elevated run is the only one that
proves the store path works. Several test processes at once are worse than useless: they all write
to the same live store, and the result then depends on which of them finished last.

## Commands

```
winfw-mcp                   serve: what a double-click starts, and the same as --serve
winfw-mcp --apply           load rules.toml and install it in the live store, then exit
winfw-mcp --serve           run the web server until stopped
winfw-mcp --takeover        the same, but wait briefly for an instance that is stopping; a
                            relaunch starts its elevated copy this way
winfw-mcp --clear           remove our filters from the live store
winfw-mcp --import <file>   read an exported profile into the active rule file, replacing it
winfw-mcp --help            print the usage text (`-h`)
winfw-mcp --version         print the version (`-V`)
```

`--import` needs no elevation: it reads the XML of an exported profile, writes the
rules it understands into the rule file of the active profile, and stops there. Nothing reaches the
live store, because the point of the import is to look at the result on the page before deciding
whether it is worth installing. What the shape of a profile does not fit is written into the comment
of the rule it came from, or reported as a note in the log when no rule came from it at all.

No flag means a double-click, and a double-click serves. That was not always so: for a long time a
run without parameters printed its usage and touched nothing, which in a release build — no console
window — looked exactly like a program that was broken. `--apply` is the one-shot that installs the
rules and exits, for anyone who wants that instead of a tool that keeps running.

An unknown flag is an error rather than a shrug, so a mistyped option cannot silently install
filters nobody asked for. Only one `--serve` may run at a time: a second start finds the name
taken, logs one line, and ends with a non-zero status without opening anything. See
[the lifecycle chapter](08-lifecycle.md#only-one-at-a-time).

## Elevation

Reading and writing the store needs elevation. An unelevated start therefore asks, in a dialog, for
an elevated start of the same command; the dialog says what staying means, which is that no rule is
installed and the page shows a store it cannot confirm. Answering no is a supported answer and the
run continues, and a refused UAC dialog is treated the same way. An import is not asked about,
because it only reads and writes files.

The elevated copy of a serving run is started with `--takeover`, waits a few seconds for the
instance name the asking process still holds, and brings its own token and its own tray. A token is
never handed from one process to the other.

[The WFP internals](07-wfp-internals.md#reading-the-store-needs-elevation) describe what a refused
store looks like and why the UI shows a banner instead of an empty list.

---

Next: [2. Data and configuration](02-data-and-configuration.md)
