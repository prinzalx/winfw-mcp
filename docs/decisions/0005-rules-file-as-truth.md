# ADR 0005: rules.toml is the source of truth

## Status

Accepted (retroactively recorded 2026-11-22).

## Context

WFP holds the installed filters, but the tool needs a form a person can edit,
keep in Git and understand: the store is engine state, not a document.

## Decision

`rules.toml` (or the active profile file) is the single source of truth; the
store is rebuilt from it. The file carries a checksum of its own body so a
hand edit that breaks it is read anyway but said so out loud.

## Consequences

A restart, a rebuild and a store repair are the same operation, and the
`Quit and remove rules` story is honest: the filters go out with the process,
the file stays. A hand edit outside the tool costs a checksum warning until
the next write, which is accepted - the warning is the point. Learning
collects decisions into the file, the file never invents state.

## Alternatives

Treating the store as truth was rejected: WFP holds thousands of filters from
every engine on the machine, and a per-filter edit loop cannot express rule
order or names the way a file can.
