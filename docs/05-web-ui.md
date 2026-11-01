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

- **Profile** selector, which switches the live rule file, with `New`, `Rename` and `Delete` beside
  it. `New` copies the rules on screen into a new profile and switches to it; `Rename` and
  `Delete` work on the profile the selector holds, and `Delete` asks first because it takes the
  rules file with it. Renaming or deleting the unnamed `default` is refused: it is `rules.toml`
  itself rather than a file in `profiles\`.
- **Header** line: address, learning mode, default policy, theme. Learning mode and the default
  policy are underlined because they are clickable — clicking one asks the server to switch it to
  the other value, which writes `config.toml` and rebuilds the store in the same request. The theme
  is clickable too and cycles `light -> dark -> auto`, where `auto` follows the operating system.
  Since **0.32.0** this is not decoration: the choice is applied to the page in the same request and
  survives a reload, so a bright terminal and a dark browser stop fighting each other.
- **Rules** table: enabled flag, name, action, pattern, protocol, direction, port, remote address,
  remove, share. Every field is edited in place and saved on change. Protocol and direction are
  dropdowns whose first entry is `any`, which is sent as no value at all; the port box takes `443`
  or `1024-2048` and the remote box `10.0.0.5` or `192.168.1.0/24`, both left empty for anything
  goes. A value the server cannot read bounces back as an error and the row is redrawn from what
  the server has.
- **Detected** table: the learning mode, with `allow`, `deny` and `dismiss` per row. An entry for a
  destination a covered application reached is marked `to <address>` and decides that destination
  alone.
- **Recent connections**: fed over SSE, newest first, as `local -> remote`. Each line names the
  destination it went to and the rule the firewall blamed for its verdict — `by browser` for one of
  ours, `by other` for a filter another firewall owns. A connection that never left the machine is
  marked `loopback`. An endpoint the event named no address for is left out of the line; an address
  with no port still shows the port.
- **The feed's state**, next to that heading: `running, 128 events`, `no feed: 0x00000005`,
  `starting` or `stopped`. It is the answer to "is this list empty because nothing happened or
  because nothing was delivered?", which an unelevated run can only answer the second way.
- **Actions**: Add rule, Apply to WFP, Clear our filters, Export, Import, Restore, Quit.
  Restore is the file half of an export: a file chooser takes a rules file back in, and the
  interface asks first, because replacing the list is the one action on the page that can lose
  rules rather than only fail to add them.
- **Banner**: what the store reported. A refused store is shown as a banner with its reason rather
  than as an empty list. Under it, since **0.31.0**, what the rebuild at startup found: a line naming
  the filters the store held and the filters the rules describe, shown only when the two differ. An
  unchanged restart says nothing, and a refused store needs no second notice because the banner above
  already names it.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | the page itself |
| `GET /api/state` | settings, rules, what the store reported, the state of the event feed and what the rebuild at startup found |
| `POST /api/rules` | replace the rule list: write the file, then rebuild the filters |
| `POST /api/detected` | turn one detected application (or destination, when the entry carries a `remote`) into a rule and rebuild the store |
| `POST /api/settings` | change `learn_mode`, `default_policy` or `theme` at runtime; only `log_level` is written for the next run |
| `POST /api/detected/dismiss` | drop a detected application or destination without deciding |
| `POST /api/clear` | remove our filters from the store |
| `POST /api/shutdown` | stop the server, which ends the process; the filters stay installed |
| `POST /api/export` | copy the rules, the config, the Detected list and the profiles into `export\` |
| `POST /api/rules/share` | one rule as a Base64 string, for copy and paste |
| `POST /api/rules/import` | append the rule a Base64 string carries |
| `POST /api/rules/replace` | replace the whole rule list with the text of a rules file: the restore half of an export |
| `GET /api/profiles` | the active profile and the names of the stored profiles |
| `POST /api/profiles/switch` | make another profile live (an empty name selects `rules.toml`) |
| `POST /api/profiles/create` | copy the live rules into a new profile and make it live; a name already taken is refused |
| `POST /api/profiles/rename` | give a profile another name, taking its backup along; the live profile stays live |
| `POST /api/profiles/delete` | remove a profile and its backup, falling back to `rules.toml` when it was the live one |
| `GET /api/events` | the connection feed as a server-sent event stream |
| `GET /api/health` | liveness, for a supervisor or the MCP transport |
| `POST /mcp` | the Model Context Protocol endpoint (JSON-RPC 2.0) |

## Export, import, share

Export answers which files it copied and where, which is the manual backup path: every area can be
copied into `export\` on demand. Since **0.30.0** the profiles come along too, into
`export\profiles\` rather than next to `rules.toml`, because a set of equal files is impossible to
tell apart in a flat listing; a profiles directory that is still empty exports nothing and leaves no
directory behind. Import has two directions since **0.33.0**. A share string still appends the one
rule it carries rather than replacing anything, so pasting cannot silently discard a rule set. A
whole file replaces the list: `Restore` on the page reads the chosen file in the browser and posts
its text, and the MCP `rules.import` tool takes the same text. What comes back is read by the same
reader that reads `rules.toml` at startup, so a version this build does not know, a field name it
does not recognise or a pattern it cannot hold is refused before the file on disk is touched — and
the generation it replaces is kept as the backup either way. `rules.decode` remains the read
direction for a single rule, and appends it only when asked to with `add`.

## Stopping the page's server

The `Quit` button posts `/api/shutdown`. That ends the process, not merely the request, so the page
reports what happened instead of reloading a server that is no longer there. The filters stay in
the firewall; `--clear` is what removes them. See [lifecycle](08-lifecycle.md#stopping).

---

Previous: [4. Learning mode](04-learning-mode.md) · Next: [6. The MCP endpoint](06-mcp-endpoint.md)
