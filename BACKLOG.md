# Backlog

Collected after milestone 10, the last milestone of [PLAN.md](PLAN.md). None of this is scheduled;
the list exists so that an extension plan can be drawn from it later without having to remember
which questions were already noticed.

Each item says what it is and, where I already know it, what the code does today, so a later
planning round does not start from a guess.

## Runtime and lifecycle

1. **Single-instance check at startup.** Nothing checks whether another instance is already
   running. Starting a second one today binds a second port or fails on the bind, and both processes
   would write the same files and the same WFP objects. Needs a defined answer for the second
   process: exit, or open the browser on the running one and exit.

2. **Quit keeps the firewall rules.** Answered while collecting: yes, the rules outlive the process.
   Every filter is added with `FWPM_FILTER_FLAG_PERSISTENT`, so a quit or a terminate leaves the
   filters in the store, and `--clear` is the way to take the tool out again. What an ordinary
   `simplewall` popup does is therefore already matched; nothing to implement unless we want quit
   to optionally clear as well.

## Rules and matching

3. **Learning mode is per application, not per destination.** `Detected` carries `app`, `display`,
   `seen_ms`, `hits` and `allowed` — no remote address. So the case `tool.exe` is allowed toward
   `site1.com` and now touches `site2.com` cannot be noticed: an application an enabled rule already
   covers is not collected at all, whatever it talks to. Making the destination visible means
   adding a remote-address dimension to the collection, which is a real model change, not a field.

4. **No default deny.** We install our own permit and block filters in a sublayer of our own and
   change nothing about who else decides. A program in neither list is therefore **not** denied by
   us; it is decided by the filters of other providers, in practice the Windows Firewall, which is
   still running. A "block everything we say nothing about" mode has to either set the base filters
   or move the Windows Firewall out of the way, and that is the biggest behavioural decision on this
   list.

5. **Blocked and unruly attempts are mixed.** Blocked connections and connections with no rule at
   all both end up as `allowed: false`, and the field only says what the last connection did. There
   is no list that answers "what did the firewall block" separately from "what has no rule yet", and
   the recent-connections feed keeps only the newest entries.

## Rules and their files

6. **Escaping when rules are stored.** Answered in part while collecting: `rules.toml` writes
   patterns as TOML *literal* strings (`'C:\Program Files\*'`), so backslashes survive a round trip
   without any escaping, and both the device form and the drive form are accepted on input. The
   fragile boundary is not the file but **JSON over HTTP** — the web UI body, the Share string and
   the MCP arguments all carry the same path through a syntax where `\` is an escape character.
   Worth a deliberate test of the worst path we can build, and worth looking at how the reference
   implementation quotes paths, since it solves the same problem.

## Presentation

7. **Icons are missing.** Neither the tray icon nor the executable carries a logo. Anything simple
   is fine; the executable one needs a Windows resource file, which the build does not have yet.

## Process

8. **Re-audit every stage of PLAN.md** and check that the code each stage promises really exists in
   full, rather than assuming the milestone table is the truth.

9. **Compare each feature against the `simplewall` reference** and look for things the C original
   handled that we did not think of — including syntactic details such as how it quotes and stores
   a path, which is the same question as item 6.
