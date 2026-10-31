# 4. Learning mode

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

The Detected list is the learning mode. Every application that connects while no enabled rule
covers it is collected there, with its hit count and whether the firewall allowed or blocked it, and
the newest decision waits at the top.

## Applications, not connections

Learning mode collects applications, not connections. One executable that makes a hundred
connections is one decision. An application an enabled rule already covers is not collected at all,
because a rule that blocks it is a decision that was already made.

## Deciding

Each row can be allowed, denied or dismissed:

- **allow / deny** turns the entry into an ordinary rule in `rules.toml` and rebuilds the store, so
  nothing downstream has to know where a rule came from.
- **dismiss** drops the entry without deciding, which is what a row is for when the application is
  uninteresting or was started by accident.

A dismissed entry is only removed after the store accepted the write. A refused write leaves the
entry on the list so the user can try again, which is why an unelevated run appears to ignore a
decision rather than reporting it as broken.

## Edit before deciding

The path in the row is editable on purpose: widening `C:\Program Files\Nodejs\node.exe` to
`C:\Program Files\*\*.exe` before allowing it is the usual wish, and an ordinary rule is created
either way. A new application shows up in the list without a reload, but only this one list is
refreshed from the event stream, so what the user is typing in the rules table is not thrown away.

## What learning mode is not

It is not a log of blocked traffic. The event panel is fed separately; see
[the web UI](05-web-ui.md) and [the WFP internals](07-wfp-internals.md#the-event-stream). Whether a
blocked connection that no rule mentions should also be remembered as its own entry is an open
question, tracked in the [backlog](../BACKLOG.md).

---

Previous: [3. Rules and profiles](03-rules-and-profiles.md) · Next: [5. The web UI](05-web-ui.md)
