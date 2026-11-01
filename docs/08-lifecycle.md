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

Before the listener is bound, the server rebuilds the store from the rules it just read. Our filters
are persistent, so without that step the store would keep whatever the previous run left in it, and
a rule edited while the tool was closed would not be enforced until the next write. Since **0.31.0**
the answer of that rebuild is kept rather than only logged: `GET /api/state` and the MCP `status`
tool carry a `startup` object with the filters the store held, the filters the rules describe, and a
`differs` flag for the two having disagreed. The page shows a line about it under the store banner,
and stays quiet when nothing disagrees — an unchanged restart and a store the tool refused both have
nothing to report there, because a refusal has no counts to compare and is already named by the
banner itself.

The logo in the notification area is our own, and it comes out of the executable rather than from a
file beside it: `build.rs` puts `assets\winfw-mcp.ico` in the binary's resources and the tray loads
it from there, which is what keeps a single `.exe` portable. If the resource is missing — a build
without a resource compiler — the tray falls back to the system's default application icon and the
tool still works.

A tray icon is not a widget: `Shell_NotifyIconW` binds an icon to a *window* and delivers its clicks
as messages to that window's procedure. So the tray owns a message-only window and the thread that
pumps its messages, which is also why the tray cannot live on one of the server's request threads.

## Only one at a time

A second `--serve` does not start a second server. The name `Local\winfw-mcp.serve` is claimed with
a mutex before anything is bound or rebuilt, and whoever loses it opens the browser on the instance
that is already running and exits successfully:

```
INFO winfw_mcp: another instance is serving url=http://127.0.0.1:8788/
```

That is the answer to a double double-click, and exit code `0` says so: the tool is running, which is
what the second start was asking for.

Two details make this work rather than look like it works:

- **The URL opened is the running instance's.** A busy port makes a server fall forward to the next
  free port, so the configured port is not necessarily the served one. The running instance records
  the port it got in `server.port` in the data directory, and the second process reads that file.
  An instance that stops takes the file with it.
- **Only `--serve` is guarded.** A one-shot apply or clear is over in a moment, and the live store
  serialises two overlapping transactions on its own, so there is nothing to protect there.

`Local\` scopes the name to the terminal-services session, which fits a per-user tool: two accounts
on one machine may each run the tool, and each owns the rules in its own `%APPDATA%`.

## Clicking

- **Left click** opens the browser on the UI. The URL is handed to the shell, which means the
  browser is the user's, not ours.
- **Right click** opens a menu with `Open`, `Pause learning` and `Quit`. `Open` does what a left
  click does. `Pause` and `Resume` flip the running `learn_mode` flag and write no file, so a pause
  lasts for this run only: a restart reads `config.toml` again. The menu is built when it opens, so
  the label always reflects the flag the monitor reads; a settings change made in the web in between
  is picked up the next time the menu opens. `Quit` is the same stop as below.

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

The exception is `volatile_filters = true`: the server then sends itself one last clear on the way
out, and the rules go with the process. A *killed* process never reaches that last step; the
leftovers are found by the next run's startup cleanup, which removes every filter carrying our
provider key before installing the new ones.

## Not implemented on purpose

There is no service and no autostart. Adding either is tracked in the [backlog](../BACKLOG.md), and
each has to live with the fact that a portable tool is run by the user, not by a manager that could
start it again.

---

Previous: [7. WFP internals](07-wfp-internals.md) · Next: [9. Development](09-development.md)
