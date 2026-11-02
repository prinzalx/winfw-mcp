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
  This is not decoration: the choice is applied to the page in the same request and
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
  ours, `by other` for a filter another firewall owns. A destination on the local segment is marked
  `local network` and can be hidden with the checkbox under the heading. An endpoint the event named
  no address for is left out of the line; an address with no port still shows the port.
- **The feed's state**, next to that heading: `running, 128 events`, `no feed: 0x00000005`,
  `starting` or `stopped`. It is the answer to "is this list empty because nothing happened or
  because nothing was delivered?", which an unelevated run can only answer the second way.
- **Actions**: Add rule, Apply to WFP, Clear our filters, Export, Import, Restore, Quit.
  Restore is the file half of an export: a file chooser takes a rules file back in, and the
  interface asks first, because replacing the list is the one action on the page that can lose
  rules rather than only fail to add them.
- **Banner**: what the store reported. A refused store is shown as a banner with its reason rather
  than as an empty list. Under it, what the rebuild at startup found: a line naming
  the filters the store held and the filters the rules describe, shown only when the two differ. An
  unchanged restart says nothing, and a refused store needs no second notice because the banner above
  already names it. A third notice appears when `rules.toml` on disk is not the file
  the tool itself wrote: someone edited it, restored a backup over it, or deleted it, and the rules
  the page shows are the ones in memory rather than the ones in the file. Saving a rule makes the
  file ours again and the notice goes away.

## Connections worth showing

The list answers one question: what reached out. A connection that never left the
machine is not on it at all. That is decided in the monitor rather than in the page, because the
log, the counter next to the heading, the Detected list and everything an MCP client reads are fed
from that one point — and because the log holds two hundred entries, a local agent talking to this
tool's own web server would otherwise crowd the connections a user could act on out of the list.

A destination on the local segment does leave the machine, so it is shown rather than dropped, but
it is marked `local network`: the private ranges, link-local and unique local addresses. The
checkbox under the heading hides exactly those rows, for someone who only wants the Internet. The
filter is presentation only and is not remembered across reloads.

None of this touches the rules. In particular the loopback permits of the default-deny policy are
still installed, which is what keeps the tool reachable while it blocks everything else
([WFP internals](07-wfp-internals.md#the-default-deny-base)).

## Routes

| Route | Purpose |
|---|---|
| `GET /` | the page itself |
| `GET /api/state` | settings, rules, what the store reported, the state of the event feed, what the rebuild at startup found, the session token and whether `rules.toml` changed outside the tool |
| `POST /api/rules` | replace the rule list: write the file, then rebuild the filters |
| `POST /api/detected` | turn one detected application (or destination, when the entry carries a `remote`) into a rule and rebuild the store |
| `POST /api/settings` | change `learn_mode`, `default_policy`, `theme` or `log_level` at runtime; all four take effect at once |
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
| `GET /api/events` | the connection feed as a server-sent event stream: the connections that left the machine |
| `GET /api/health` | liveness, for a supervisor or the MCP transport |
| `GET /favicon.ico` | the icon in the browser's tab, served from the binary so a request for it does not answer 404 |
| `POST /mcp` | the Model Context Protocol endpoint (JSON-RPC 2.0) |

## Who may write

Every request passes a guard before it reaches a route, and the guard distinguishes
reading from writing.

| Check | Applies to | Answer | Why |
|---|---|---|---|
| `Host` names `127.0.0.1`, `localhost` or another loopback address | every route, reads included | **403** | DNS rebinding: a page on another domain can be made to resolve to `127.0.0.1` after it loaded, and then only the `Host` header says which name was used |
| `Origin`, when present, is a loopback origin | writing routes | **403** | the same page on another port is not this page; this is the CSRF case |
| `Content-Type: application/json` | writing routes | **415** | a form or a `text/plain` body is what a cross-site request is allowed to send without asking first |
| `x-winfw-token` equals the token issued at startup | writing routes | **401** | the browser holds the token; a process that never saw it may not write |

The token is sixteen random bytes rendered as hex, made when the process starts, held in memory only,
and never written to a file or to the log. It reaches the browser in the URL the tray opens
(`http://127.0.0.1:8788/?token=…`); a tab whose address was typed by hand has no token and takes it
from the first `/api/state` body, which is read before any button can be pressed.

`GET`, `HEAD` and `POST /mcp` are exempt from the token, the origin and the content type: a read
cannot change anything, and the MCP endpoint is configured with a URL rather than with a session. The
`Host` check is not exempt, because that is exactly the check a read needs too. What this buys and
what it does not is the subject of [the security model](10-security-model.md).

A request body the server cannot read answers **400 Bad Request**, and only a
body: a JSON syntax error, a field of the wrong type, a name outside an enum like a theme that is
not `light`, `dark` or `auto`, a field the route does not know. Anything else that can fail — a
store that refused the change, a file that would not write, an index past the end of the rule list
— stays **500**, because then the refusal is about the state and not about what the client sent.

## Export, import, share

Export answers which files it copied and where, which is the manual backup path: every area can be
copied into `export\` on demand. The profiles come along too, into
`export\profiles\` rather than next to `rules.toml`, because a set of equal files is impossible to
tell apart in a flat listing; a profiles directory that is still empty exports nothing and leaves no
directory behind. Import has two directions. A share string still appends the one
rule it carries rather than replacing anything, so pasting cannot silently discard a rule set. A
whole file replaces the list: `Restore` on the page reads the chosen file in the browser and posts
its text. The MCP endpoint once offered the same thing as `rules.import`, which is gone
like the other writing tools. What comes back is read by the same reader that reads `rules.toml` at
startup, so a version this build does not know, a field name it
does not recognise or a pattern it cannot hold is refused before the file on disk is touched — and
the generation it replaces is kept as the backup either way. The read direction for a single rule is
`POST /api/rules/share`, which answers with the Base64 string alone rather than with JSON; the MCP
endpoint offers the same string as `rules.share`.

## Stopping the page's server

The `Quit` button posts `/api/shutdown`. That ends the process, not merely the request, so the page
reports what happened instead of reloading a server that is no longer there. The filters stay in
the firewall; `--clear` is what removes them. See [lifecycle](08-lifecycle.md#stopping).

---

Previous: [4. Learning mode](04-learning-mode.md) · Next: [6. The MCP endpoint](06-mcp-endpoint.md)
