# ADR 0001: Talk to WFP directly through the windows crate

## Status

Accepted (retroactively recorded 2026-11-22; the choice predates the ADR).

## Context

The tool must install and remove filters in the live Windows Filtering
Platform store, watch connection events, and read the store inventory.
`wf.msc` is too heavy, `netsh advfirewall` cannot express WFP filters the way
the tool needs, and the FirewallControl COM API hides WFP behind its own
rule model.

## Decision

The tool calls the WFP C API directly through the `windows` crate: engine
handles, filter enumeration, `FwpmFilterAdd0` and its siblings, and the ALE
layer condition ids.

## Consequences

Everything WFP can express is reachable, including the security-descriptor
conditions behind the service narrowing. The marshalling traps are ours to
know: pointer conditions must point at the value, a
`FWP_SECURITY_DESCRIPTOR_TYPE` condition needs its `FWP_BYTE_BLOB` framing,
and an unelevated write answers `FWPM_E_ACCESS_DENIED_ELEVATED_USER`
(`0x80320009`). Live-store tests are the only honest verification, so they
run serially and elevation is a run-time fact.

## Alternatives

`netsh advfirewall` was rejected for its coarser model and text parsing; the
FirewallControl COM API for the impedance between its rule objects and our
filters; a cross-platform firewall abstraction for costing more than it saves
on a Windows-only tool.
