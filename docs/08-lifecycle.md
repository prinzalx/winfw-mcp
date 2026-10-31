# 8. Lifecycle and tray

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

## Starting

A portable tool is started by double-click, and a console window belonging to a tray icon is in the
way. In a release build the binary is therefore a Windows program rather than a console one:
starting it shows no terminal window at all. Debug builds keep the console, because that is where
the log goes while the tool is being developed.

`--serve` puts an icon in the notification area. A machine where the icon cannot be added is not a
failure of the tool: the server answers anyway and the user types the address, so a refused icon is
only logged. Because the release binary has no console, the startup lines and the outcome of adding
the icon are appended to the log file in the data directory as well.

A tray icon is not a widget: `Shell_NotifyIconW` binds an icon to a *window* and delivers its clicks
as messages to that window's procedure. So the tray owns a message-only window and the thread that
pumps its messages, which is also why the tray cannot live on one of the server's request threads.

## Clicking

- **Left click** opens the browser on the UI. The URL is handed to the shell, which means the
  browser is the user's, not ours.
- **Right click** offers `Quit`.

## Stopping

Both routes end the process rather than only the tray thread:

- the page's `Quit` button posts `POST /api/shutdown`;
- the tray's `Quit` clears the same flag.

The flag is `AppState::running`. The accept loop waits on it, and after it is cleared the loop waits
a short grace period so the client that asked for the stop receives its reply before the process
ends. The MCP endpoint offers the same action as the `shutdown` tool, gated by `mcp_writes`.

**Stopping keeps the rules.** The filters we install are persistent and outlive the process, so the
firewall still enforces what `rules.toml` says after the tool is gone. `--clear` is what takes our
filters out of the live store again.

## Not implemented on purpose

There is no service, no autostart and no single-instance check yet. The last of those means starting
the tool twice currently gives you two processes; it is tracked in the
[backlog](../BACKLOG.md).

---

Previous: [7. WFP internals](07-wfp-internals.md) · Next: [9. Development](09-development.md)
