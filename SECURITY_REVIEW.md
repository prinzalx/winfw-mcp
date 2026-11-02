# Security review brief

A brief for a reviewer who has not seen the code. It describes the process, the request path and
the questions; it does not describe the answer. Written in English, because the repository is
English throughout.

## What runs

One process, `winfw-mcp.exe`, Windows only, elevated or not. It owns the machine's WFP firewall
rules and it owns a small HTTP server on `127.0.0.1` (default port 8788; it walks forward to the
next free port when that one is busy). There is no service, no installer and no registry state;
everything lives under `%APPDATA%\winfw-mcp`.

A person uses the server through a browser page. The tray icon opens the page at
`http://127.0.0.1:<port>/?token=<token>`. An agent uses the same server through one endpoint,
`POST /mcp`, which speaks JSON-RPC 2.0 and is read-only in the code: there is no MCP tool that
changes a file or the live store.

## The request path

Every connection to the socket goes through the same handler. Nothing bypasses it.

1. **Bind.** The socket is bound to `127.0.0.1`. Nothing on another machine reaches it.
2. **One instance.** A private named mutex means exactly one serving process exists. A second
   start opens a browser on the first one and exits.
3. **Parse.** The HTTP request line and headers are parsed. The fields `guard` reads are collected
   on the way in; a request that cannot be parsed is refused before the guard.
4. **Guard.** The guard in `src/server/guard.rs` answers `403`/`415`/`401` and the route never
   runs. It distinguishes reading from writing:
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

The token is sixteen random bytes from `getrandom` (128 bits, hex), made once at process start. It
lives in memory only: never in `config.toml`, never in a file beside it, never in the log. The
browser learns it from the URL the tray opens. If the operating system hands out no randomness, the
server continues with a fixed, well-known value and logs a warning.

## What is deliberately not protected

A process running as the same user can read the port file, call `GET /api/state`, read the token
out of the body, and write whatever it likes. Same-user is not an adversary this model defeats;
the fingerprint of `rules.toml` notices a hand edit but does not prevent it. A cross-origin page
cannot read responses (no `Access-Control-Allow-Origin` header is sent at all), and a `fetch` that
sets `content-type` on another origin is preflighted, which the server answers `404` because it
implements no `OPTIONS` route.

## The questions

Review the path above against the code and answer these. Each one should be a short yes/no with a
file and line as evidence.

1. Can a caller other than the page reach a **writing** route with a token that is not its own?
   Consider: the token is handed to the browser in a URL query; could a local process read the
   command line, the environment, or the body of an earlier request and learn it?
2. Does the guard's `/mcp` exemption open anything beyond reading? `/mcp` skips `Origin`,
   `content-type` and the token. Is there a route reachable under `/mcp` that writes?
3. Is the `Host` check hard to get wrong? It accepts `localhost`, any `127.0.0.0/8` address and
   `::1`. The port is not compared. Should the port be compared?
4. Is the missing-`Host` exemption a hole? HTTP/1.1 requires a `Host` header on every request to
   this server, but the guard lets a request with no `Host` through.
5. The token comparison is a plain string compare. Is timing a concern for a local secret that a
   local adversary can already read another way?
6. Is anything the model relies on *not* in the guard? (The `deny`-outranks-`allow` rule is a WFP
   semantic, not a transport check; it is documented separately.)

## Evidence

- `src/server/guard.rs` — the guard, the Host/Origin helpers, the token maker, eight tests.
- `src/server/mod.rs` — the accept loop; `guard` runs before the route; `x-winfw-token` header.
- `docs/10-security-model.md` — the chapter that mirrors this brief.
- `CHANGELOG.md` rows 0.36.0 and 0.37.0 — why the endpoint is read-only and why loopback traffic
  is dropped in the monitor.
