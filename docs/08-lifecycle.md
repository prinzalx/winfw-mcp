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
tool carry a `startup` object with the filters the store held, the filters the rules describe, and
three lists of rule names — `added`, `changed` and `gone` — for what the file gained, flipped or
lost while the tool was closed. The names come from the filters the previous run left behind, which
carry the rule's label, so a rule that appeared, vanished or flipped its action is named even when
the filter counts come out equal. An edit that keeps a rule's name, its action and its number of
filters — a narrowed port, say — leaves the same trace as no edit at all and is not claimed. The
page shows this under the store banner and stays quiet when nothing disagrees — an unchanged restart
and a store the tool refused both have nothing to report there, because a refusal has no counts to
compare and is already named by the banner itself.

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
is thirty characters the user did not ask for and cannot type, and it travels in the fragment of that
URL, where the balloon has no reason to show it. A balloon the shell refuses is a debug line rather than a failure,
because the icon is in the notification area either way, and a startup that shows nothing at all is
what PLAN.md section 1 was written against.

A tray icon is not a widget: `Shell_NotifyIconW` binds an icon to a *window* and delivers its clicks
as messages to that window's procedure. So the tray owns a message-only window and the thread that
pumps its messages, which is also why the tray cannot live on one of the server's request threads.

## Only one at a time

A second `--serve` does not start a second server. The name `Local\winfw-mcp.serve` is claimed with
a mutex before anything is bound or rebuilt, and whoever loses it logs one line and ends with a
non-zero status:

```
WARN winfw_mcp: another instance is serving; this start stops here url=http://127.0.0.1:8788/
```

A second double-click is a mistake rather than a wish for a second firewall, so the second process
opens no browser and hands nothing over. Bringing the running page to the front is the tray's job,
and a process that ends here has no tray of its own yet.

Two details make this work rather than look like it works:

- **The running instance's port is recorded.** A busy port makes a server fall forward to the next
  free port, so the configured port is not necessarily the served one. The running instance writes
  the port it got to `server.port` in the data directory and takes the file with it when it stops.
  The second start names that port in its log line.
- **Only `--serve` and `--takeover` are guarded.** A one-shot apply or clear is over in a moment,
  and the live store serialises two overlapping transactions on its own, so there is nothing to
  protect there.

`Local\` scopes the name to the terminal-services session, which fits a per-user tool: two accounts
on one machine may each run the tool, and each owns the rules in its own `%APPDATA%`.

The one process that may have to wait for the name is the elevated newcomer of a relaunch. It starts
while the old instance is still holding the name — the old process asks the shell first and stops
only once the shell has said yes — so it runs as `--takeover` and waits up to five seconds for the
name to be released. If the name is still held afterwards, it ends like any second start. The
newcomer generates its own session token and shows its own tray, so a token is never handed from
the old process to the new one.

## Clicking

- **Left click** opens the browser on the UI. The URL is handed to the shell, which means the
  browser is the user's, not ours.
- **Right click** opens a menu with `Open`, `Pause learning`, `Pause protection` and `Quit`, and
  `Relaunch elevated` between the pauses and `Quit` while the process is not elevated. `Open` does
  what a left click does. `Pause learning` and `Pause protection` flip a running flag and write no
  file, so each pause lasts for this run only: a restart reads `config.toml` again and the labels
  read `Pause` again. The menu is built when it opens, so a label always reflects the flag the
  monitor or the worker reads; a change made in the web in between is picked up the next time the
  menu opens. `Pause protection` and `Relaunch elevated` are the same requests the page sends, so the
  tray is a client of the API rather than a second way in. `Pause learning` is the one entry the tray
  applies itself: it flips the same running flag the settings route writes, without a request of its
  own, which is invisible to the guard because nothing crosses the socket. `Quit` is the same stop as
  below.
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
