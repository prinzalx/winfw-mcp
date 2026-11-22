# ADR 0003: The MCP endpoint is read-only

## Status

Accepted (retroactively recorded 2026-11-22).

## Context

An agent that reads the firewall over MCP could also be allowed to write a
rule. A write tool lets an agent decide its own traffic.

## Decision

The MCP endpoint answers reads only (`status`, `rules.list`, `events.list`,
`detected.list`, ...); writing rules is the browser's job.

## Consequences

An agent cannot open its own gate: the firewall in front of an agent stays in
front. The owner decided against the agent-side self-un-sandbox, and the
`mcp_writes` setting was retired accordingly - an old `config.toml` key is
accepted, never read, and dropped by the next save.

## Alternatives

A whitelisted write tool (for example `rules.add`) was weighed and refused on
principle, not on effort: a write from the agent side would need the same
guard conversation all over again.
