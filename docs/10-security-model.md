# 10. Security model

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

The question this chapter answers is a narrow one, and it is worth stating before anything else:
**who is prevented from doing what?** The answer is not "an attacker with the user's password". It is
this — a local agent, or a web page sitting in the same browser, must not be able to hand itself
firewall freedom. A tool that reaches out to the internet and then writes its own allow rule has
answered its own question, and the firewall stops being a policy somebody decided.

That is enforced in two places: the MCP endpoint reads only, and the HTTP routes
that write carry a session token.

## The two surfaces

| Surface | Reached by | May write? | Proven by |
|---|---|---|---|
| `POST /mcp` | any process on this machine that knows the port | no | the writing tools are gone from the code; a call to one is `-32601` |
| writing HTTP routes | the page the tray opened | yes | `x-winfw-token`, plus `Host`, `Origin` and `Content-Type` checks |
| reading HTTP routes | anything on this machine | — | `Host` only |

The endpoint is deliberately given no token. An agent is configured with a URL, and a URL is easier
to hand out than a secret that has to be copied into the right process at the right time. That is
only acceptable because the endpoint cannot write: the worst an uninvited MCP client does is learn
what the rules are, and it cannot stop the process either, because `shutdown` was a writing tool.

## The session token

Sixteen random bytes as hex, from `getrandom`, made when the process starts. It lives in memory and
nowhere else: not in `config.toml`, not in a file beside it, not in the log, and — since 0.58.0 —
in no answer body either. The tray opens the browser on `http://127.0.0.1:8788/#token=…`, and a
fragment is never sent over the wire: the document request the server answers is plain `GET /`, the
secret appears in no request line, and no response carries it back.

A tab that has no fragment — an address typed by hand, or a reload after the page took the fragment
out of the address bar again — can still read everything but cannot write. The page says so, keeps
the write controls disabled, and points at the tray icon. A reload therefore loses the write right,
which is a decision rather than an oversight: the token lives in one variable in the page and in no
storage, no cookie and no file.

A note on the fallback. If the operating system refuses to hand out randomness at all, the server
continues with a fixed, well-known token and logs a warning. In that situation the token has stopped
being a secret and become a formality; the Host and Origin checks are still in place.

## The guard

Every request passes the guard in `src/server/guard.rs` before a route sees it.

| Check | Applies to | Answer | Against |
|---|---|---|---|
| `Host` is a loopback name | everything, reads included | **403** | DNS rebinding |
| `Origin`, when present, is a loopback origin | writes | **403** | cross-site request forgery |
| `Content-Type: application/json` | writes | **415** | a form post, or the body a cross-origin request may send without asking |
| `x-winfw-token` matches | writes | **401** | a process that never opened the page |

DNS rebinding deserves the explanation, because it is the reason a read is checked too. A page on
another domain is loaded while `example.com` still resolves to a public address; every request after
that resolves `example.com` to `127.0.0.1`, arrives at our socket, and carries a `Host` header naming
the other domain. Without that check such a page could read the whole state of the firewall.

A missing `Host` header is let through. HTTP/1.1 asks every request for one and a browser always
sends it, so the check can only ever catch a name that is wrong rather than a command line client
that omitted it. The port is not compared: a request only reaches the process on the port it
listens on, so a page with the wrong port never arrived in the first place.

The guard sees every request, `/mcp` included: `crate::server::guard` runs on the parsed request
before `Server::route` is called, and the answer of a refused request is written and the connection
closed without the route ever running. There is no second door — the accept loop has one handler —
so "what is protected" has one answer:

1. **Bind.** The socket is bound to `127.0.0.1`, so nothing on another machine reaches it at all;
   `netstat` shows a loopback listener, not `0.0.0.0`.
2. **One instance.** The mutex of [lifecycle](08-lifecycle.md#only-one-at-a-time) means there is
   exactly one process answering, so no second server can be quietly started on the same port with
   weaker checks.
3. **Reads** — including `/mcp` and `/favicon.ico` — need only the loopback `Host`. A DNS-rebinding
   page learns names and counts, nothing secret.
4. **Writes** need `Host`, `Origin`, `content-type: application/json` and the token. A non-browser
   process that never opened the page has no token; a page on another origin fails `Origin` or,
   with a form post, `content-type`.
5. **`/mcp` carries no token** and has no writing route to reach: it is read-only in the code, so
   the one endpoint without a secret is the one that cannot change a file.

## What the fingerprint catches

`rules.toml` is a file the user can edit, and the tool is not the only writer in the world. At
startup the tool compares the file with the fingerprint of the last state *it* wrote, kept in
`rules.toml.stamp`; a difference is shown on the page as a banner rather than adopted quietly, and a
change noticed while running raises the same banner. Saving a rule re-fingerprints the file, so the
notice disappears when the file is ours again. A file that has gone away counts as changed: the rules
on the page are the ones in memory, and the file that describes them is missing.

The stamp follows the *active* rules file, so switching profiles changes what is compared, and a
profile with no stamp of its own is compared against the file as it was found.

## What is not protected

Being honest here matters more than sounding secure.

- **A process running as the same user is not an adversary this model defeats.** It can read the
  port, call `/api/state` and see everything the page shows. Since 0.58.0 it can no longer *learn*
  the token that way — the state body does not carry it — so `curl` cannot write, and cannot even
  shut the tool down, without being told the token out of band. A determined process of the same
  user can still read the browser's memory or its command line. And anyone of that user can edit
  `rules.toml` directly, which the fingerprint notices but does not prevent.
- **The token is not a secret from the machine, only from another origin.** The page that holds it is
  the page we opened. A cross-site page cannot read our responses — no `Access-Control-Allow-Origin`
  header is sent at all — and a `fetch` that sets `content-type: application/json` on another origin
  is preflighted, which our server answers with `404` because it implements no `OPTIONS` route.
- **The guard does not know what a rule means.** It refuses a write from a page that is not ours; it
  does not refuse a rule that happens to open the whole internet. Deny outranks allow, always, and
  that is the semantic protection rather than this transport one.
- **Two writers are told, not ordered.** A whole-list write may name the generation it read, and a
  stale name is answered `409` with the current state rather than applied; see
  [the web UI chapter](05-web-ui.md#two-pages-one-list). A client that names no generation still
  wins silently, so the protection covers the page and any client that chooses to use it, not the
  raw API.
- **The tray is a client, not a privileged process.** It holds the URL the server gave it and sends
  the same token in the same header, so pausing protection or learning from the menu is checked by
  the guard exactly like a click on the page. Nothing reaches a route through a side door, which is
  the point worth stating: the guard has one caller and the tray has no direct line to the store.
- **Elevation is a separate question.** The HTTP server runs with the process's rights; the difference
  between an elevated and an unelevated run is about the live store, and it is described in
  [WFP internals](07-wfp-internals.md#reading-the-store-needs-elevation).

## What default deny leaves open

Since 0.61.0 the tool starts with `default_policy = "deny"`, which is what makes it a firewall rather
than a logger: an application no ALLOW rule mentions cannot connect. Three limits of that belong
here, because each of them has surprised someone.

- **Applications are matched by path alone.** There is no service match and no package match, so
  everything hosted by `svchost.exe` is one application to the firewall. DNS, DHCP and time sync run
  there, and without a permit for `svchost.exe` no name resolves at all: the connection a blocked
  client reports is a timeout, not a refusal. The price of the permit is the other direction: with
  `svchost.exe` allowed, every service may use it.
- **An interpreter is one application.** A rule for `python.exe`, `node.exe` or `powershell.exe`
  permits every script that runs through it, whatever the script reaches for. The manual recommends
  narrowing such a rule with a remote address or a port.
- **Loopback is permitted by the base filters, not by a rule.** A connection that never left the
  machine is allowed under deny, which is why the page still loads while everything external is
  blocked.

Getting out of a deny that is too tight does not need a rule edit: **Pause protection** in the tray or
on the page takes our filters out of the store, which restores connectivity, and putting them back
re-applies the policy.

## Where an agent can still get out

An agent that talks MCP can read the rules, the detected list, the recent connections and the share
string of a rule. To change anything it must ask the human, who uses the page. That is the whole
design: the read side is automatable, and the write side keeps a person in it until there is a reason
to say otherwise about a specific group of services and targets.

One consequence of the connection filter belongs here, because it is a fact about what an
agent can see rather than about what it may do. The connection feed holds only traffic that left
the machine, so an agent
looking for itself in `events.list` will not find its own requests to this tool's web server: they
were loopback, and they are gone before the log. The agent's connections are the ones it does not
have to explain to the firewall.

---

Previous: [9. Development](09-development.md) · Back to the [index](../README.md)
