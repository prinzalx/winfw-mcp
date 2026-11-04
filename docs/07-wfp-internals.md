# 7. WFP internals

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

## Reading the store needs elevation

Measured on Windows 11: an unelevated process opens the WFP engine without problem, but every read
answers access denied and every write is refused. So `cargo run` in a plain shell logs a warning per
store class, prints no filters and reports `WFP write refused`, while an elevated run lists the
store and installs the rules.

That is a supported degraded state, not a failure: `/api/state` answers `store.ok` with the reason,
and the web UI shows a banner instead of an empty list.

WFP grants read access **per class**, so providers, sublayers and filters each carry their own
result. A refused provider store is not a reason to throw away the filters we did read.

## Opening the engine waits for the service

Every long-running caller opens the engine through a retry: five attempts over
3.7 seconds, with the waits ascending between them. The Base Filtering Engine can be briefly
unavailable during boot, and the worker thread of the server opens the engine once and keeps the
handle for its whole life — a run that started before the service was ready and gave up on the
first answer would have served its entire session with the banner "store unavailable", whatever
the service did afterwards. The C reference retries at the same place for the same reason.

The waits are the whole policy, so they are the thing under test: the retry loop is generic over
the attempt and over its sleep, and the tests hand it a fake both ways — an attempt that fails
twice and recovers, and one that never does. A machine whose firewall service is disabled should
be slow to start, not started slowly.

## Identifying our filters

Every filter we install belongs to a fixed provider GUID, so a later run can find its own objects
again without a state file. Enumerating them through a `FWPM_FILTER_ENUM_TEMPLATE0` was rejected by
the engine with `FWPM_E_INVALID_ENUM_TYPE`, so the filter list is read whole and the provider key is
compared in code. A filter with no provider key was not added by us.

A filter key is derived from the rule name **plus its index**, so the UI's repeated default name
`new rule` cannot collide.

## Applying

Applying is a full rebuild, not a diff: our filters are removed and re-added in rule order inside
one transaction. Because the filters are persistent, `--clear` is the clean way to take the tool out
again.

Re-applying is the normal case, not an error. The provider and sublayer stay in the store after
`--clear`, and both `Fwpm*Add0` calls answer `FWP_E_ALREADY_EXISTS` when they are added again, which
the write path accepts.

## The layers a rule is installed on

One rule becomes one filter per application it matches, per layer it applies to. Which layers that
are depends on the direction of the rule, and an address narrows them further, because an IPv4
address can never match on an IPv6 layer:

| `direction` | Layers |
|---|---|
| absent | all four: connect and recv-accept, for both address families |
| `"out"` | `ALE_AUTH_CONNECT_V4` and `ALE_AUTH_CONNECT_V6` |
| `"in"` | `ALE_AUTH_RECV_ACCEPT_V4` and `ALE_AUTH_RECV_ACCEPT_V6` |

| `remote`, `local` | Of those, only |
|---|---|
| absent | all of them |
| an IPv4 address, network or span | the two `..._V4` layers |
| an IPv6 address, network or span | the two `..._V6` layers |

Each address narrows the layers on its own, and the two of them have to agree on a family: a rule
that names a v4 destination behind a v6 local address is left on no layer at all, because no
connection has ends of both families.

Each filter carries the application condition (`FWPM_CONDITION_ALE_APP_ID`) and, when the rule
narrows, a protocol condition (`FWPM_CONDITION_IP_PROTOCOL`, `FWP_UINT8`), a port condition and an
address condition per end the rule names. The port condition is `FWPM_CONDITION_IP_REMOTE_PORT` on
a connect layer and `FWPM_CONDITION_IP_LOCAL_PORT` on a recv-accept layer, because that is the port
the connection is about in each direction. The address condition is
`FWPM_CONDITION_IP_REMOTE_ADDRESS` for the destination and `FWPM_CONDITION_IP_LOCAL_ADDRESS` for
the local end, each with `FWP_V4_ADDR_MASK` (an address and a mask) or
`FWP_V6_ADDR_MASK` (an address and a prefix length) depending on the family. A span of addresses is
the same field matched with `FWP_MATCH_RANGE` and `FWP_RANGE_TYPE`: the bounds are a `FWP_UINT32`
pair for a v4 span and a `FWP_BYTE_ARRAY16_TYPE` pair for a v6 one, which is what the reference
fills for the same case.

A single port is matched with `FWP_UINT16` and `FWP_MATCH_EQUAL`; a range with `FWP_RANGE_TYPE` and
`FWP_MATCH_RANGE`. The range is one of the conditions WFP keeps a **pointer** to rather than a copy, so
the `FWP_RANGE0` has to outlive the call. The four address conditions are pointer conditions too, for
the same reason, and a v6 span adds a pointer of its own inside each bound.

> Getting that pointer wrong is easy and the failure is not obvious. Handing WFP the address of an
> `Option<FWP_RANGE0>` instead of the address of the `FWP_RANGE0` inside it installs a filter whose
> range is read out of the wrong bytes, and WFP answers `FWP_E_INVALID_ENUMERATOR`. The same trap
> waits for every condition that is a pointer, which is why the address value is built as an enum of
> the four shapes rather than an `Option` of each, and why the bounds of a span are held next to the
> `FWP_RANGE0` that points at them instead of inside it.

## The application condition

A rule about one application is installed as a `FWP_BYTE_BLOB` condition obtained from
`FwpmGetAppIdFromFileName0`, which resolves a file that exists into the device path WFP matches on.
A pattern that names no existing file is handed over as it stands, and the match becomes exact.

Measured on a live store: a rule written `C:\WINDOWS\system32\CURL.EXE` allowed a program whose
path the firewall reports as `C:\Windows\System32\curl.exe`. The resolution does not care about
case, so the path is stored exactly as it was typed rather than lowercased the way the C original
does (`wfp.c:2176`). What this tool compares case-insensitively itself is the Detected list and the
seen pool, where a second spelling would otherwise mean a second entry
([learning mode](04-learning-mode.md)).

## The default-deny base

`default_policy = "deny"` in `config.toml` installs thirteen base filters next to the rule filters:

| Filters | Action | Weight | Purpose |
|---|---|---|---|
| 4, one per authorization layer | permit | `0x0F` | loopback, so the browser can still reach this tool's own web server |
| 1 on `ALE_AUTH_RECV_ACCEPT_V4` | permit | `0x0F` | protocol 41 (6to4) |
| 4 on `ALE_AUTH_RECV_ACCEPT_V6` | permit | `0x0F` | ICMPv6 types 133 to 136, the router and neighbour messages the IPv6 stack needs |
| 4, one per authorization layer | block | `0x01` | the unconditional bottom, so anything no rule allows is denied |

They live in our own sublayer at `FWW_SUBLAYER` and carry our provider key, so `--clear` takes them
out exactly like a rule filter.

### The weight ladder

Filters inside a sublayer are ordered by weight, highest first:

| Weight | Used for |
|---|---|
| `0x0F` | base permits of the default-deny policy |
| `0x0E` | a deny rule |
| `0x0D` | an allow rule |
| `0x01` | the unconditional base block |

Deny has to sit above allow, or the outcome would depend on where a rule happens to sit in
`rules.toml`. This is what makes a deny override an allow without the two being compared as a pair.

Two pitfalls were measured rather than read: WFP answers `FWP_E_INVALID_WEIGHT` (`0x80320025`) for a
weight of `0`, and it answers the same for `0x10`. The usable window for a `FWP_UINT8` weight ends at
`0x0F`, which is exactly where the reference's `FWW_IMPORTANT` stops.

## The event stream

Live connections come from WFP's own event stream (`FwpmNetEventSubscribe4`) on a session of the
monitor's own. Two engine options have to be set on that session first, and both were found the hard
way:

- without `FWPM_ENGINE_COLLECT_NET_EVENTS` the subscription is accepted but never fires;
- without the classifier keyword in `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS` only blocked
  connections are collected at all, so the allowed ones a learning mode needs would be missing.

The options are per session, so the monitor configures its own and leaves the machine alone.

The thread reports what subscribing did, because a refused subscription is a supported state and an
empty connection list needs a reason. It publishes `starting`, `running`, `refused` with the code
that refused it, or `stopped` on the way out, and both reports read that together with how many
events the log took in and when the last of them arrived. An unelevated run therefore says
`no feed: 0x00000005` rather than looking like a machine about to happen. The count and the stamp
together answer a question neither answers alone: the count says whether the feed ever worked, the
stamp says when it last did, which is what tells a quiet machine from a subscription that stopped
delivering while it stayed open. Note what the count means: it counts what the callback handed
over, and the callback drops a connection that stayed on the machine before it hands anything
over.

## What the callback keeps

The callback is where an event is either dropped or copied out, and dropping is
part of its job. A connection that never left the machine does not reach the log at all, which is
the only way to keep it out of the log's bound, out of its counter, out of the seen list and out of
the Detected list at the same time; filtering in the page would have left three of those four wrong.

WFP's own `isLoopback` marker is believed when the event carries one. Without a marker the remote
address decides: `127.0.0.0/8` and `::1` cannot have left. An event that names no remote address is
kept, because a field the header did not fill is not evidence the traffic stayed home — treating an
empty destination as local would quietly drop real connections.

A destination on the local segment leaves the machine and is therefore kept: the private ranges,
`169.254.0.0/16`, `fe80::/10` and `fc00::/7`. It is reported as `local_network` so the page can
offer a filter for it. `debug_show_loopback` in `config.toml` turns the drop off for a diagnosis
run; like `log_level` it is read once at startup.

The filters are not involved in any of this. The loopback permits of the default-deny policy are
installed whatever the feed decides to show, and the tool's own web server answers on `127.0.0.1`
while the log shows nothing about it.

## Reading the endpoints of an event

Each end of the connection lives in a union of its own in the event header — `Anonymous1` for the
local address, `Anonymous2` for the remote one — and `ipVersion` selects which arm of it to read:
one `u32` for v4, sixteen bytes for v6. The v4 arm is converted the same way the store writes a
filter condition's address, so the address in the log and the address a rule matches are the same
number read the same way.

Whether either end exists at all is a separate marker in the header's `flags`, and that marker is
what is believed. An arm nobody wrote still holds whatever the zeroed event put in it, and a zeroed
v4 arm is `0.0.0.0` — a plausible-looking address that would be wrong to report. The same marker
guards the two ports. A version of `FWP_IP_VERSION_NONE` names no address family at all, which is
what a connectionless event looks like.

The loopback marker is not in the header. It is `isLoopback` on the classify arms — the same
pointers the deciding `filterId` is read from — so an event of another type has no marker to report
and reads `false` rather than "unknown".

## Naming the filter that decided an event

An event names the filter behind its verdict by a number and nothing else: `filterId` in the
classify arm of the event union. The number is not derived from content and it is not stable — it is
an index into the store, handed out when the filter goes in — so reading it back needs a table this
process built itself.

`apply` fills that table. Every filter it installs is recorded under the id WFP reports, against the
rule name it came from, and the finished table rides out on `Applied::owners`. The WFP worker owns
the live copy and republishes it after every successful rebuild, so the table always describes the
store that is in there right now; a `Clear` empties it. The monitor's callbacks look an event's id up
in that table under a lock.

Two answers are deliberately distinguished in the API. `"rule": "browser"` means one of our filters
decided it, and `"rule": null` beside a non-zero `filter_id` means the store blamed a filter we do not
know — another firewall on the machine, or one of ours that a later rebuild replaced. `filter_id: 0`
is the sentinel for "the event named no filter at all", and because WFP never hands out id 0 it can
never collide with a real filter.

This is the piece the reference gets from comparing the dropping filter's provider key against its
own; we get the same answer from a table we own, which also covers the permit side of a verdict.

## Reading the destination an event went to

The address is not in the event's own fields but in a union selected by `ipVersion`: the v4 arm is a
single `u32`, the v6 arm sixteen bytes. Reading the arm the version does *not* select yields garbage
rather than an error, so the version decides and nothing else.

The v4 number is read the same way the store writes an address condition (`u32::from_be_bytes` of the
octets), which keeps the address in the log and the address a rule matches the same value read the
same way. A connectionless event carries no version and reports no address.

The event log carries the local endpoint and a marker for connections that never left the machine;
the user name is still only in the
event and not in the log.

## Threading

The server is `std` only: one thread per connection, no async runtime. Every request that matters
ends in a blocking WFP call anyway, and a long-lived connection is what SSE needs.

Because a WFP transaction belongs to a thread rather than to a handle, exactly one worker thread
owns the engine handle; request threads hand their work to it over a channel and wait.

## What the reference does that we do not

The C original always runs default-deny: base filters at the bottom of the store, plus explicit
permits for loopback and ICMPv6 neighbour discovery so the machine stays reachable. Since 0.61.0
ours runs the same shape out of the box: `default_policy` defaults to `deny`, so an application no
rule mentions cannot connect until the human allows it from the Detected list. `allow` remains
selectable in `config.toml` and on the page, where traffic no rule mentions is left to the rest of
the machine.

That gap, and the other differences found while comparing, are collected in the
[backlog](../BACKLOG.md).

---

Previous: [6. The MCP endpoint](06-mcp-endpoint.md) · Next: [8. Lifecycle and tray](08-lifecycle.md)
