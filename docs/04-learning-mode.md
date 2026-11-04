# 4. Learning mode

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

The Detected list is the learning mode. Every application that connects while no enabled rule
covers it is collected there, with its hit count and whether the firewall allowed or blocked it, and
the newest decision waits at the top.

Each profile has its own list. An entry is a question about the rules that are live, so the list
follows the profile: switching profiles switches the list, and an entry collected under one profile
is back the moment that profile is live again. The set of seen applications a wildcard expands
against is the one part of `learn.json` that every profile shares, because it is a fact about the
machine rather than about a rule set.

## Applications, and the destinations they reach

Learning mode collects applications, not connections. One executable that makes a hundred
connections to the same place is one decision. An application an enabled rule already covers is not
collected at all, because a rule that blocks it is a decision that was already made.

A covered application is still noticed when it reaches a destination its own rules do
not cover. An `allow` for `tool.exe` on `site1.com` no longer hides the first connection to
`site2.com`: that appears as a second Detected entry, marked with `to <address>`, and its identity
is the pair of application *and* destination. What counts as covered is decided per application, and
an application with a rule that names no destination covers every address, so nothing new is ever
reported for it.

A connection that never left the machine is not collected either. It is dropped in
the monitor before learning mode is asked about it, so an agent talking to this tool's own local web
server does not add entries anyone has to dismiss
([WFP internals](07-wfp-internals.md#the-event-stream)).

**The application is compared without regard to case.** Windows paths are case-insensitive, and the
firewall reports a device path in lower case while a person types what the shell shows them, so
`C:\Test\Tool.exe` and `c:\test\tool.exe` are one application, one Detected entry and one decision.
The entry keeps the spelling it was first collected under, which is the one already on the screen,
and a dismiss reaches it under any spelling. A `learn.json` written before 0.62.0 can hold both
spellings of one application; loading folds them together, adds the hit counters, and loses nothing.
The seen list that a wildcard pattern is expanded against is folded the same way, so one
application becomes one filter rather than one filter per spelling.

## Deciding

Each row can be allowed, denied or dismissed:

- **allow / deny** turns the entry into an ordinary rule in `rules.toml` and rebuilds the store, so
  nothing downstream has to know where a rule came from. A destination entry becomes a rule that
  names that destination, which is what stops the next destination from being allowed by accident.
- **dismiss** drops the entry without deciding, which is what a row is for when the application is
  uninteresting or was started by accident.

A dismissed entry is only removed after the store accepted the write. A refused write leaves the
entry on the list so the user can try again, which is why an unelevated run appears to ignore a
decision rather than reporting it as broken.

An agent decides nothing at all: it reads `detected.list`, and the decision is made on the page.
The writing tools that once existed dismissed the entry only after they had turned it into a rule
and the store had taken the rule.

## Edit before deciding

The path in the row is editable on purpose: widening `C:\Program Files\Nodejs\node.exe` to
`C:\Program Files\*\*.exe` before allowing it is the usual wish, and an ordinary rule is created
either way. A new application shows up in the list without a reload, but only this one list is
refreshed from the event stream, so what the user is typing in the rules table is not thrown away.

## The switch

Collection is controlled by `learn_mode` in `config.toml`. While it is off, nothing new reaches the
Detected list, but the connection log keeps filling, so the connections panel is unaffected. The set of
seen applications that wildcard rules are expanded against grows either way; see
[the wildcards](03-rules-and-profiles.md#wildcards). The setting
is read when the process starts, which means changing it takes a restart; a way to flip it from the
web page is on the backlog, which is a working file and not published here. With learning off the
Detected list says so instead of
claiming that nothing is waiting for a decision.

## What learning mode is not

It is not a log of every connection. The connections panel is fed separately; see
[the web UI](05-web-ui.md) and [the WFP internals](07-wfp-internals.md#the-event-stream). Whether a
blocked connection that no rule mentions should also be remembered as its own entry is an open
question, tracked in the backlog.

---

Previous: [3. Rules and profiles](03-rules-and-profiles.md) · Next: [5. The web UI](05-web-ui.md)
