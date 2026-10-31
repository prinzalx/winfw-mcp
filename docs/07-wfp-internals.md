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

## The event stream

Live connections come from WFP's own event stream (`FwpmNetEventSubscribe4`) on a session of the
monitor's own. Two engine options have to be set on that session first, and both were found the hard
way:

- without `FWPM_ENGINE_COLLECT_NET_EVENTS` the subscription is accepted but never fires;
- without the classifier keyword in `FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS` only blocked
  connections are collected at all, so the allowed ones a learning mode needs would be missing.

The options are per session, so the monitor configures its own and leaves the machine alone.

## Threading

The server is `std` only: one thread per connection, no async runtime. Every request that matters
ends in a blocking WFP call anyway, and a long-lived connection is what SSE needs.

Because a WFP transaction belongs to a thread rather than to a handle, exactly one worker thread
owns the engine handle; request threads hand their work to it over a channel and wait.

## What the reference does that we do not

The C original installs base filters at `FWW_LOWEST` (`simplewall/src/wfp.c`) that make the store
default-deny, and then needs explicit permits for loopback and for ICMPv6 neighbour discovery so the
machine stays reachable. Our rules decide the applications a rule mentions; traffic no rule mentions
is not enforced the same way while no such base filter exists.

That gap, and the other differences found while comparing (remote destination, protocol, direction
and address family in a rule; provider attribution on events), is collected in the
[backlog](../BACKLOG.md).

---

Previous: [6. The MCP endpoint](06-mcp-endpoint.md) · Next: [8. Lifecycle and tray](08-lifecycle.md)
