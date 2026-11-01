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
    profiles\            named profiles, one file each
    learn.json           collected Detected entries (learning mode)
    logs\                rotating log files
    export\              destination for on-demand exports
```

## Settings

| Key | Meaning |
|---|---|
| `port` | the loopback port the web server binds (8788 by default); if it is busy the server takes the next free one of the following eight instead of failing |
| `log_level` | default tracing level; `RUST_LOG` overrides it for a single run |
| `learn_mode` | whether learning mode collects applications; off means the Detected list stays empty while the connection log keeps filling, and changing it takes a restart |
| `default_policy` | `allow` (default) or `deny`. `deny` puts an unconditional block at the bottom of the four authorization layers, so an application no rule mentions is denied rather than allowed; see [WFP internals](07-wfp-internals.md#the-default-deny-base). Changing it takes a restart |
| `theme` | presentation preference carried by the page |
| `mcp_writes` | how much the MCP endpoint may write: `none`, `rules` or `all` |
| `active_profile` | the live profile name; empty selects `rules.toml` itself |

`RUST_LOG` overrides `log_level` from `config.toml` for a single run. Logging goes to stderr,
because stdout belongs to the MCP stdio transport.

## Three rules worth knowing

- **Unknown config keys are an error,** not a warning. A typo in `config.toml` fails loudly instead
  of quietly keeping the default. An exception is made for keys added by a later version, so
  upgrading does not fail on a config a newer binary wrote.
- **Atomic writes.** Files are written to `*.tmp` and renamed, so a crash never leaves a half
  written config behind. This matters because the WFP filters this tool installs are persistent and
  outlive the process.
- **Load once, write immediately.** All settings are read at startup; every change made in the web
  UI is written straight back to disk. No save button, no dirty state.

---

Previous: [1. Getting started](01-getting-started.md) · Next: [3. Rules and profiles](03-rules-and-profiles.md)
