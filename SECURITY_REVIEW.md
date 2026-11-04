# Security review brief

A brief for a reviewer who has not seen the code. It describes the process, the request path and
the questions; it does not describe the answer. Written in English, because the repository is
English throughout. Current as of 0.77.8.

## What runs

One process, `winfw-mcp.exe`, Windows only, elevated or not. It owns the machine's WFP firewall
rules and it owns a small HTTP server on `127.0.0.1` (default port 8788; it walks forward to the
next free port when that one is busy). There is no service, no installer and no registry state;
everything lives under `%APPDATA%\winfw-mcp`.

A person uses the server through a browser page. The tray icon opens the page at
`http://127.0.0.1:<port>/#token=<token>`, and the page takes the token out of the address again the
moment it has read it. An agent uses the same server through one endpoint, `POST /mcp`, which
speaks JSON-RPC 2.0 and is read-only **in the code**: the reading tools it offers (`status`,
`rules.list`, `rules.share`, `detected.list`, `events.list`, `profiles.list`) touch neither a file
nor the live store, and there is no writing tool to call. The writing tools were removed from the
code rather than switched off, so an agent cannot reach a write even by naming one.

## The request path

Every connection to the socket goes through the same handler. Nothing bypasses it.

1. **Bind.** The socket is bound to `127.0.0.1`. Nothing on another machine reaches it.
2. **One instance.** A private named mutex means exactly one serving process exists. A second start
   exits quietly with a non-zero status: no browser, no token exchange. An elevated relaunch waits a
   few seconds for that mutex precisely so it is not mistaken for a second start.
3. **Parse.** The HTTP request line and headers are parsed. The fields `guard` reads are collected
   on the way in; a request that cannot be parsed is refused before the guard.
4. **Guard.** The guard in `src/server/guard.rs` answers `403`/`415`/`401` and the route never runs.
   It distinguishes reading from writing:
   - `GET` and `HEAD` need only the `Host` check;
   - `POST /mcp` needs only the `Host` check, by path, because that endpoint carries no token;
   - every other method needs `Host`, `Origin`, `content-type: application/json` and the token.
5. **Route.** Writing routes post work to one WFP worker thread and wait for its answer. Reading
   routes answer from the shared state.

The guard is the whole answer to *who may write*:

| Check | Applies to | Answer | Against |
|---|---|---|---|
| `Host` is a loopback name | every request | 403 | DNS rebinding |
| `Origin`, when present, is a loopback origin | writes | 403 | cross-site request forgery |
| `content-type: application/json` | writes | 415 | a form post, or a cross-origin `fetch` |
| `x-winfw-token` matches | writes | 401 | a process that never opened the page |

## The token

The token is sixteen random bytes from `getrandom` (128 bits, hex), made once at process start. It
lives in memory only: never in `config.toml`, never in a file beside it, never in the log, and —
since 0.58.0 — **not in any response body**. It reaches the browser in the URL *fragment* the tray
opens, and a fragment is never sent to a server, so the page is the only place it exists after that.

A tab opened without the fragment (an address typed by hand, a page reloaded) can read everything
and cannot write; the page says so rather than failing a click in silence. There is no session
storage, no cookie and no localStorage: a reload loses the right to write, which is accepted.

If the operating system hands out no randomness, the server continues with a fixed, well-known value
and logs a warning.

## What the default policy adds

`default_policy` defaults to `deny`: an application no ALLOW rule mentions cannot connect, outbound
or inbound, and `deny` outranks `allow` always. That is a WFP semantic rather than a transport
check, and it bounds what a permitted application can do. Three limits of it are documented and not
solved: applications are matched by path alone, so DNS, DHCP and time sync all live in
`svchost.exe`; a rule for an interpreter (`python.exe`, `node.exe`, `powershell.exe`) permits every
script that runs through it; and loopback is permitted by the base filters, not by a rule.

## What is deliberately not protected

A process running as the same user can read the port file and call `GET /api/state`, and since
0.58.0 that no longer tells it the token, so plain `curl` can read but cannot write. It is the
convenience path that is closed, not every path: the same user can still examine the browser
process or its command line, and can edit `rules.toml` directly, which the fingerprint notices but
does not prevent. A cross-origin page cannot read responses (no `Access-Control-Allow-Origin` header
is sent at all), and a `fetch` that sets `content-type` on another origin is preflighted, which the
server answers `404` because it implements no `OPTIONS` route.

## The questions

Review the path above against the code and answer these. Each one should be a short yes/no with a
file and line as evidence.

1. Can a caller other than the page reach a **writing** route with a token that is not its own?
   Consider: the token travels in a URL fragment and lives only in the page's memory; could a local
   process read the browser's command line, its memory, or a request body and learn it?
2. Does the guard's `/mcp` exemption open anything beyond reading? `/mcp` skips `Origin`,
   `content-type` and the token. Is there a route reachable under `/mcp` that writes?
3. Is the `Host` check hard to get wrong? It accepts `localhost`, any `127.0.0.0/8` address and
   `::1`. The port is not compared. Should the port be compared?
4. Is the missing-`Host` exemption a hole? HTTP/1.1 requires a `Host` header on every request to
   this server, but the guard lets a request with no `Host` through.
5. The token comparison is a plain string compare. Is timing a concern for a local secret that a
   local adversary can already read another way?
6. The guard runs before the route table and before the `/api/events` stream is opened. Is there a
   path from the socket to a route that does not pass it?
7. Is anything the model relies on *not* in the guard? (The `deny`-outranks-`allow` rule is a WFP
   semantic, not a transport check; it is documented separately.)

## Evidence

- `src/server/guard.rs` — the guard, the Host/Origin helpers, the token maker, eight tests.
- `src/server/mod.rs` — the accept loop; `guard` runs before the route and before the event stream.
- `src/server/mcp_tools.rs` — the reading tools; no `save`, no store work, no rule write, and no
  write is reachable under `/mcp`.
- `docs/10-security-model.md` — the chapter that mirrors this brief, including the limits of
  default deny.
- `CHANGELOG.md` rows 0.36.0, 0.37.0, 0.58.0 and 0.61.0 — the read-only endpoint, the dropped
  loopback traffic, the token out of the state body, and default deny as the default.
