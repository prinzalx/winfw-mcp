# 6. The MCP endpoint

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

`POST /mcp` speaks JSON-RPC 2.0 and needs no session: every request is answered on its own, so
curl is a valid client. `initialize`, `ping`, `tools/list` and `tools/call` are implemented, and a
tool name may be used as the method directly, which is the shortest form an agent can send.

Only the part of the protocol a client actually sends on a stateless HTTP transport is modelled. A
client that asks for anything else is told so rather than silently ignored.

## Tools

| Tool | Purpose | Writes? |
|---|---|---|
| `status` | settings, rule count, store health, the state of the event feed, what the rebuild at startup found, how much the endpoint may write | no |
| `rules.list` | every rule, in file order | no |
| `rules.share` | one rule as a Base64 string (takes `index`) | no |
| `rules.decode` | read a Base64 share string back (takes `share`; with `add` the rule is appended) | no, yes with `add` |
| `rules.import` | replace the whole rule list with the text of a rules file (takes `text`) | yes |
| `rules.allow` | add an allow rule (takes `app`, optional `pattern`, `name`, `protocol`, `direction`, `port`, `remote`), and dismiss the Detected entry it decides | yes |
| `rules.deny` | add a deny rule, dismissing the Detected entry it decides (same arguments) | yes |
| `rules.remove` | remove the rule at an index, write the file, rebuild the store (takes `index`) | yes |
| `detected.list` | what learning mode collected | no |
| `events.list` | recent connection events, each naming both endpoints, whether the traffic left the machine, and the deciding filter id and rule | no |
| `export` | copy an area (`rules`, `config`, `detected`, `profiles`, `all`) into `export\` | yes |
| `profiles.list` | the active profile and the stored profile names | no |
| `profile.use` | switch the live profile (takes `name`) | yes |
| `settings.set` | change `learn_mode`, `default_policy` or `theme` (all optional) | yes |
| `shutdown` | stop the process; the filters stay in the firewall | yes |

`rules.share` and `rules.decode` are the two directions of one string, which is how a rule travels
between machines without the browser: `share` on one host, `decode` with `add` on the other. Without
`add` a decode writes nothing, so it stays usable under the default `mcp_writes = none`, and the
pattern it carries is validated before anything is written — a share string is Base64 around JSON a
human may have edited.

`rules.allow` and `rules.deny` take an application an agent read from `detected.list` and take it
off that list once the store accepted the rule, which is what the browser has always done. An entry
the store refused stays visible, so a decision nothing acted on is not lost silently.

## Who may write

Reads are always allowed. Writes go through `mcp_writes` in `config.toml`, which is `none` by
default: an agent should be able to ask questions before anyone allows it to answer them.

`rules` permits the tools that touch the rule list. `all` additionally permits the ones that rewrite
the settings as well, which today means `profile.use` and `settings.set`.

A refused write is not a transport error; it comes back as a normal tool result with `isError` set
and the reason both as text and as structured content. That is what the MCP spec says about a tool
that ran and declined. Deny outranks allow, always, so an agent can widen a hole but cannot talk
its way past a deny.

An argument the tool cannot use is a protocol error instead, `-32602` (`INVALID_PARAMS`). A pattern
that is not an absolute path is refused this way, so an agent that hands over `not-a-path` is told
so rather than left with a rule that matches nothing (`status` will not look wrong, but nothing will
match).

## Why hand-written

The `rmcp` crate was weighed and rejected here: it would bring a tokio runtime and an axum
dependency for four method names, while the endpoint has to answer the same four questions either
way. Hand-writing them keeps the binary small and the grammar visible.

---

Previous: [5. The web UI](05-web-ui.md) · Next: [7. WFP internals](07-wfp-internals.md)
