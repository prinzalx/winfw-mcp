# ADR 0006: Default deny with visible exceptions

## Status

Accepted (retroactively recorded 2026-11-22).

## Context

A fresh firewall for one machine can start permissive (everything the rules do
not mention goes out) or restrictive (nothing goes out that no rule allows).
The owner's whole Detected-list workflow depends on what happens to an
unmentioned program.

## Decision

The default policy is `deny`: an unconditional block sits at the bottom of the
authorization layers, loopback and the IPv6 base functions stay reachable
through default rules, and anything else surfaces in the Detected list until
the owner decides. `allow` remains a switchable policy for a machine that
should not be guarded this strictly.

## Consequences

An empty rules table on first start is a closed firewall, not an open one -
which is what the owner asked for. The red `PAUSED` chip and the `Allow
unknown` naming tell the state at a glance. The price is the Detected queue's
volume after a fresh install, answered by the live filter and the decision
dialog.

## Alternatives

Default allow with a blocklist was rejected: it hides unknown programs until
they misbehave, and the tool exists to make the unknown visible.
