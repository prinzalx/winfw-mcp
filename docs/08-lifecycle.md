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
a rule edited while the tool was closed would not be enforced until the next write. Today
the answer of that rebuild is kept rather than only logged: `GET /api/state` and the MCP `status`
tool carry a `startup` object with the filters the store held, the filters the rules describe, and a
`differs` flag for the two having disagreed. The page shows a line about it under the store banner,
and stays quiet when nothing disagrees — an unchanged restart and a store the tool refused both have
nothing to report there, because a refusal has no counts to compare and is already named by the
banner itself.

A tool started by a boot rule can outrun the Base Filtering Engine, and it waits
rather than misses: the engine open retries five times over 3.7 seconds before the store is
reported unavailable ([WFP internals](07-wfp-internals.md#opening-the-engine-waits-for-the-service)).

The logo in the notification area is our own, and it comes out of the executable rather than from a
file beside it: `build.rs` puts `assets\winfw-mcp.ico` in the binary's resources and the tray loads
it from there, which is what keeps a single `.exe` portable. If the resource is missing — a build
without a resource compiler — the tray falls back to the system's default application icon and the
tool still works.

Once the icon is in place it is modified a second time, and that second call is the start popup of
PLAN.md section 1: a balloon whose title is the tool's name and whose text is the address the server
listens on. It answers the only question a double-click raises — where is the page? — without opening
a window, without waiting for anybody, and without asking the shell for anything the tray is not
already asking for. The text is the address alone; the session token the tray opens the browser with
is thirty characters the user did not ask for and cannot type, and the page reads its token from its
own first response anyway. A balloon the shell refuses is a debug line rather than a failure,
because the icon is in the notification area either way, and a startup that shows nothing at all is
what PLAN.md section 1 was written against.

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
- **Right click** opens a menu with `Open`, `Pause learning`, `Pause protection` and `Quit`.
  `Open` does what a left click does. `Pause learning` and `Pause protection` flip a running flag
  and write no file, so each pause lasts for this run only: a restart reads `config.toml` again and
  the labels read `Pause` again. The menu is built when it opens, so a label always reflects the
  flag the monitor or the worker reads; a change made in the web in between is picked up the next
  time the menu opens. Both entries are the same request the page sends, so the tray is a client of
  the API rather than a second way in. `Quit` is the same stop as below.
- **A click on the start balloon only dismisses it.** Reporting that click needs the icon to be
  registered with a shell version, and the version also moves where the mouse events sit in the
  callback message. Keeping the click path where it is costs less than the balloon is worth, so the
  balloon is read rather than used, and the icon is what opens the page.

## Pausing protection

A firewall that is in the way is normally switched off rather than reconfigured, and that is what
the header switch and `Pause protection` in the tray menu are for. Protection is a flag the worker
holds, not a setting in `config.toml`: it starts **on**, and a restart enforces again.

What pauses is our filters, not Windows. The switch lives in the worker that talks to the store, so
the worker honours it on every piece of work it is given: while protection is paused, a rebuild that
would install filters takes them out instead. That matters for the case a switch elsewhere would get
wrong — saving a rule while the firewall is paused writes the file and rebuilds, and must not be
what resumes protection.

| Request | What the store is asked for |
|---|---|
| `POST /api/protection` with no body | flip, and report what it became |
| `POST /api/protection` with `{"enabled":false}` | pause |
| `POST /api/protection` with `{"enabled":true}` | resume |

Both answer with the whole state, like the settings route does, and the `protection` field in that
state is what the page, the MCP `status` tool and the tray menu label read. Two consequences are
worth knowing:

- **The default deny of the store is ours too.** Pausing takes the base permits and the unconditional
  block out with the rules, which is the difference between "the tool stops filtering" and "the
  tool filters less". Other software in the store is untouched.
- **A paused tool keeps watching.** The connection feed and the Detected list are filled by the
  monitor, not by the worker, so learning continues while the firewall is paused, and the decisions
  made in that time are written to `rules.toml` as usual.

## Stopping

Both routes end the process rather than only the tray thread:

- the page's `Quit` button posts `POST /api/shutdown`;
- the tray's `Quit` clears the same flag.

The flag is `AppState::running`. The accept loop waits on it, and after it is cleared the loop waits
a short grace period so the client that asked for the stop receives its reply before the process
ends. The MCP endpoint no longer offers that action: `shutdown` was a writing tool and is gone,
so an agent cannot stop the process and the page or the tray has to do it.

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
