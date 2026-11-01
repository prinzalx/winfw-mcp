# 5. The web UI

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

`--serve` binds `127.0.0.1` on the `port` from `config.toml` (8788 by default) and serves a single
page with no build step, embedded in the binary. Open it, edit a rule, and the change is written to
`rules.toml` and pushed to the store immediately.

A port that is already taken does not end the app: the server takes the next free one of the
following eight, warns about it in the log, and the tray icon opens the browser at the port it
actually got.

The page is served from the binary and so is its icon: `GET /favicon.ico` answers with the same
file the tray and the shell use, so a browser tab shows the logo without a single file on disk.

## What is on the page

- **Profile** selector, which switches the live rule file.
- **Header** line: address, learning mode, default policy. Learning mode and the default policy are
  underlined because they are clickable — clicking one asks the server to switch it to the other
  value, which writes `config.toml` and rebuilds the store in the same request.
- **Rules** table: enabled flag, name, action, pattern, protocol, direction, port, remote address,
  remove, share. Every field is edited in place and saved on change. Protocol and direction are
  dropdowns whose first entry is `any`, which is sent as no value at all; the port box takes `443`
  or `1024-2048` and the remote box `10.0.0.5` or `192.168.1.0/24`, both left empty for anything
  goes. A value the server cannot read bounces back as an error and the row is redrawn from what
  the server has.
- **Detected** table: the learning mode, with `allow`, `deny` and `dismiss` per row.
- **Recent connections**: fed over SSE, newest first.
- **Actions**: Add rule, Apply to WFP, Clear our filters, Export, Import, Quit.
- **Banner**: what the store reported. A refused store is shown as a banner with its reason rather
  than as an empty list.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | the page itself |
| `GET /api/state` | settings, rules and what the store reported |
| `POST /api/rules` | replace the rule list: write the file, then rebuild the filters |
| `POST /api/detected` | turn one detected application into a rule and rebuild the store |
| `POST /api/settings` | change `learn_mode` or `default_policy` at runtime; `theme` and `log_level` are written for the next run |
| `POST /api/detected/dismiss` | drop a detected application without deciding |
| `POST /api/clear` | remove our filters from the store |
| `POST /api/shutdown` | stop the server, which ends the process; the filters stay installed |
| `POST /api/export` | copy the rules, the config and the Detected list into `export\` |
| `POST /api/rules/share` | one rule as a Base64 string, for copy and paste |
| `POST /api/rules/import` | append the rule a Base64 string carries |
| `GET /api/profiles` | the active profile and the names of the stored profiles |
| `POST /api/profiles/switch` | make another profile live (an empty name selects `rules.toml`) |
| `GET /api/events` | the connection feed as a server-sent event stream |
| `GET /api/health` | liveness, for a supervisor or the MCP transport |
| `POST /mcp` | the Model Context Protocol endpoint (JSON-RPC 2.0) |

## Export, import, share

Export answers which files it copied and where, which is the manual backup path: every area can be
copied into `export\` on demand. Import is deliberately narrow — it appends the one rule a share
string carries, rather than replacing anything, so pasting a string cannot silently discard a rule
set.

## Stopping the page's server

The `Quit` button posts `/api/shutdown`. That ends the process, not merely the request, so the page
reports what happened instead of reloading a server that is no longer there. The filters stay in
the firewall; `--clear` is what removes them. See [lifecycle](08-lifecycle.md#stopping).

---

Previous: [4. Learning mode](04-learning-mode.md) · Next: [6. The MCP endpoint](06-mcp-endpoint.md)
