# 2. Data and configuration

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

Everything the tool owns lives under one directory, resolved before anything else reads or writes a
file. Nothing is stored in the registry, and nothing is installed anywhere else.

## The data directory

On the first run the binary creates its data directory and the files inside it:

```
%APPDATA%\winfw-mcp\
    config.toml          settings, written with defaults on first run
    rules.toml           user rules, order significant: the first match wins
    rules.toml.bak       the previous generation of the rules, kept from the second save on
    rules.toml.stamp     the fingerprint of the file the tool wrote last, so an outside edit is noticed
    server.port          written while a serving instance runs, removed when it stops
    profiles\            named profiles, one file each
    learn.json           collected Detected entries (learning mode)
    logs\                rotating log files
    export\              destination for on-demand exports
```

## The log file

Everything `tracing` reports goes to `logs\winfw-mcp.log` and to the console. A release build runs
without a window, so the file is the only place its lines survive, which is why it is bounded:
past one megabyte the live file moves to `winfw-mcp.log.1` -- replacing whatever generation was
there before it -- and writing starts over. The newest lines are always the ones that are kept, and
the result is never more than two files.

| File                     | Contents                                              |
| ----------------------- | ----------------------------------------------------- |
| `logs\winfw-mcp.log`    | the current generation, newest lines at the bottom    |
| `logs\winfw-mcp.log.1`  | the generation before it, until the next roll         |

## Settings

| Key | Meaning |
|---|---|
| `port` | the loopback port the web server binds (8788 by default); if it is busy the server takes the next free one of the following eight instead of failing |
| `log_level` | default tracing level; `RUST_LOG` overrides it for a single run, and a change over the API takes effect at once |
| `debug_show_loopback` | `false` by default. Connections that never left the machine are dropped from the event feed; `true` keeps them for a diagnosis. Read at startup, so changing it takes a restart (see [WFP internals](07-wfp-internals.md#the-event-stream)) |
| `learn_mode` | whether learning mode collects applications; off means the Detected list stays empty while the connection log keeps filling |
| `default_policy` | `allow` (default) or `deny`. `deny` puts an unconditional block at the bottom of the four authorization layers, so an application no rule mentions is denied rather than allowed; see [WFP internals](07-wfp-internals.md#the-default-deny-base) |
| `volatile_filters` | `false` by default. `true` makes the server take our filters out of the store when it stops, so the tool is a firewall only while it runs; `false` keeps them installed after a quit (see [lifecycle](08-lifecycle.md#stopping)). Read at startup, so changing it takes a restart |
| `theme` | `light`, `dark` or `auto`, where `auto` follows the operating system; the page applies it live |
| `mcp_writes` | accepted but without effect: the MCP endpoint is read-only. An older `config.toml` still loads, and the next save drops the key |
| `active_profile` | the live profile name; empty selects `rules.toml` itself |

`RUST_LOG` overrides `log_level` from `config.toml` for a single run. Logging goes to stderr,
because stdout belongs to the MCP stdio transport.

A key the file does not mention is read as its default, and that has one consequence worth knowing:
a config written before a key existed never gains it. The file is written on the first run and on a
settings change, not at every start, so `debug_show_loopback` and `volatile_filters` — neither of
which the page can write — are only in the file if a version that knew them wrote it. On an install
that predates them, someone has to type the line to turn the switch on.

## Rules worth knowing

- **Unknown keys are an error,** not a warning, in both files. A typo in `config.toml` fails loudly
  instead of quietly keeping the default. An exception is made for config keys added by a later
  version, so upgrading does not fail on a config a newer binary wrote. The same holds for a rule:
  an unknown field, or a `protocol`/`direction`/`port`/`remote` value the server cannot read, is
  refused.
- **A rule field that is absent is absent, not empty.** `protocol`, `direction`, `port` and
  `remote` are optional on a rule, and a rule written without them is about every protocol, both
  directions, every port and every address. They are left out of the file when they are not used,
  so a rule from an earlier version reads and writes exactly as it did.
  [Rules and profiles](03-rules-and-profiles.md#narrowing-a-rule)
- **Atomic writes, with the previous generation kept.** Files are written to `*.tmp` and renamed, so
  a crash never leaves a half written config behind. This matters because the WFP filters this tool
  installs are persistent and outlive the process. Rule files — `rules.toml` and every profile — are
  also copied to `<name>.bak` before each write, and a rule file that cannot be read at startup falls
  back to that backup with a warning in the log rather than a failed start.
- **A rule file says which version wrote it.** `rules.toml` starts with `version = 1`. A file from an
  earlier version has no line and is read as this version; a file from a newer one is refused, and the
  message names both versions. Since an unknown field is an error, the version is what turns "this
  binary is too old" into a sentence that says so.
- **Load once, write immediately.** All settings are read at startup; every change made in the web
  UI is written straight back to disk. No save button, no dirty state.

## Changing a setting

`learn_mode` and `default_policy` may be changed while the server runs, and both take effect
immediately:

```
curl -X POST http://127.0.0.1:8788/api/settings \
     -H 'Content-Type: application/json' \
     -d '{"default_policy": "deny"}'
```

Every field is optional, and a field that is absent keeps its value, so a client flips one thing
without having to know the rest. All four take effect at once, `log_level` included: the running
filter is swapped rather than reinstalled, and a level the filter cannot read is refused rather
than written and then silently ignored. A process started with `RUST_LOG` in the environment loses
that override to the first settings change that names the level, because the new level replaces the
filter the environment produced. The answer is the same body `GET /api/state` returns, so a client
sees what the server actually settled on.

Note what the endpoint does **not** accept: `port`, because the socket is already bound, and
`active_profile`, which has its own route (`POST /api/profiles/switch`) because switching a profile
also rewrites the rules.

---

Previous: [1. Getting started](01-getting-started.md) · Next: [3. Rules and profiles](03-rules-and-profiles.md)
