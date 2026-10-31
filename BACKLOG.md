# Backlog

Open items and audit findings. Nothing here is scheduled. The list exists so that an extension plan
can be drawn from it later without having to remember which questions were already noticed, and so
that nobody re-discovers the same gap twice.

Two audits produced most of what follows, both done against `v0.10.0`:

- **Stage audit** — every section of [PLAN.md](PLAN.md) checked against the code, asking whether the
  code a stage promises really exists in full.
- **Reference comparison** — every feature compared against the C original
  (`C:\BLOB\output\333\simplewall`, plus its helper library `routine`), asking whether the reference
  solved something we did not think of.

Findings marked **[verified]** were re-checked by hand in the sources; the rest come from the audit
passes and should be re-read before they are acted on.

## 1. Likely bugs

These are not missing features; they are behaviour that differs from what the code says it does.

| # | Finding | Evidence |
|---|---|---|
| B1 | **`Quit` in the tray did not stop the process.** `Quit` posted `PostQuitMessage`, which ends the *tray thread's* message loop only, while the accept loop in `Server::serve()` checked no flag: the icon disappeared and the server kept serving. **Fixed in 0.11.0** — `AppState::running` is now the flag the accept loop waits on, and both `Quit` and `POST /api/shutdown` clear it. | [verified] fixed; `src/server.rs` (`AppState::running`, `request_stop`), `src/tray.rs` (`SERVER_RUNNING`) |
| B2 | **`learn_mode` is inert.** The setting is read, stored and reported, but the monitor collects unconditionally, so `learn_mode = false` still fills the Detected list. **Fixed in 0.11.2** — the monitor now takes the setting and only offers events to the detector while learning is on; the connection log still fills either way. Verified with an elevated run: off → 21 events and an empty Detected list, on → the same traffic produces Detected entries. | fixed; `src/monitor.rs` (`Sink::learning`, gate in `on_event`), `src/main.rs` (`serve`) |
| B3 | **A port conflict terminates the app.** `Server::bind` returned an error and `--serve` propagated it, while PLAN.md §9 asked for a fallback so a conflict does not kill the tray app. **Fixed in 0.11.3** — `Server::bind` now walks forward to the next free port of eight, warns in the log, and the tray opens the port it actually got. | fixed; `src/server.rs` (`Server::bind`, `PORT_ATTEMPTS`) |
| B4 | **A wildcard rule silently missed applications until something wrote.** Expansion was rebuilt only when a write happened, from the applications the detector had seen; a one-shot run expanded against nothing. **Fixed in 0.11.4** — seen applications are recorded whatever `learn_mode` says, a newly seen application under an enabled pattern triggers a rebuild, the store is rebuilt from the rules at startup, and a one-shot `--apply` expands against the seen list on disk. | fixed; `src/learn.rs` (`seen`, `note_app`), `src/monitor.rs` (`on_event`), `src/main.rs` (`serve`, `sync_store`) |

There was also an open question behind B1: stopping the tool from the browser needed a route that
did not exist, so stopping meant `taskkill`. It exists since 0.11.0 as `POST /api/shutdown`, is
offered by a `Quit` button on the page, and is an MCP tool of its own. Every way of stopping leaves
the persistent filters in place, which is what item 6 of §2 asked about.

Found while auditing, and worth knowing even though it is not a bug: the filter key is derived from
the rule name **plus its index** (`src/wfp.rs:510`), so the UI's repeated default name `new rule`
cannot collide. [verified]

## 2. The original list

Kept as asked, with the two audits now folded in below.

| # | Item | Status |
|---|---|---|
| 1 | Single-instance check at startup | open — see §5.5 |
| 2 | Re-audit every stage of PLAN.md | **done**, findings in §3 |
| 3 | Compare every feature against simplewall | **done**, findings in §4 |
| 4 | Rules and their storage are fragile around escaping | partly answered — see §4.4 |
| 5 | Systray needs a logo, and so does the executable | open |
| 6 | Does quit keep the firewall rules? | **answered: yes.** Filters are added with `FWPM_FILTER_FLAG_PERSISTENT` (`src/wfp.rs:484`) and outlive the process; `--clear` removes them. The reference behaves the same way. |
| 7 | A new destination for an already allowed application must be noticed | open — this is §4.2, the biggest model gap |
| 8 | Entries for attempted accesses that were blocked, and for accesses with no allow | partly — see §4.3 |
| 9 | Is an application in neither list therefore denied? | **answered: not by us** — see §4.1 |

## 3. Findings: PLAN.md stage audit

### 3.1 Lifecycle and tray

- **The start popup does not exist.** PLAN.md §1 promises a popup that confirms the tool is running
  and shows the local URL, then closes. A tray icon was built instead, which the code documents as a
  deliberate replacement (`src/tray.rs:3-6`), but nothing at startup shows the URL to the user.
- **The tray menu has only `Quit`.** The planned `Open` and `Pause protection` are absent; `Open` is
  reachable only through a left click. [verified] There is no pause concept in the code at all.
- **The UI never says whether the monitor is running.** A refused net-event subscription is only
  logged (`src/monitor.rs:273-286`), so if the monitor thread dies the page keeps showing the last
  events as if they were live.
- **Reconcile on startup is missing in `--serve`.** PLAN.md §6 wants the WFP store reconciled against
  `rules.toml` at startup with the diff surfaced in the UI. `--serve` only loads the files and binds;
  the banner shows store counts, never a diff.

### 3.2 Settings

- **There is no write path for settings at all.** No `POST /api/settings` route, no settings control
  in the page, no MCP tool to change one. The only place `Settings::save` is called from the server is
  the profile switch. So `port`, `log_level`, `learn_mode` and `theme` are file-only and read-only in
  the UI, which contradicts PLAN.md §2's promise that every change in the web UI is written through.
- **`theme` is decorative.** The field exists in config, is reported in the state, and appears nowhere
  in `web/index.html`; the styling is fixed.
- **Logs do not rotate.** PLAN.md §2 calls `logs\` rotating. It is one append-only file with no size
  bound, and tracing goes to stderr only, so in a release build the log file holds almost nothing.

### 3.3 Files, export and import

- **No Profiles area in export.** `Area` is `rules | config | detected | all` (`src/export.rs:22-27`),
  so `profiles\` is never exported.
- **Import appends one shared rule; it does not replace.** PLAN.md §2 describes import as "replace what
  you have" and defers it. What exists is `POST /api/rules/import` appending one Base64-decoded rule.
  There is no way to load a whole exported rules file back in.
- **No decode direction over MCP.** `rules.share` encodes; a client cannot decode a share string
  because no import tool is exposed.
- **No generation kept of a rules file.** `write_atomic` prevents torn writes but keeps no previous
  version, so a corrupt-but-parseable `rules.toml` is unrecoverable. The reference writes a
  `profile.xml.bak` and falls back to it. See §4.4.

### 3.4 Profiles

- **A new profile cannot be created from the browser.** The selector lists existing names only. A
  name typed into `POST /api/profiles/switch` is created on demand, but nothing renames or deletes a
  profile, and stale files are never cleaned up.
- **The Detected list is not scoped per profile.** `learn.json` is shared, and it is the pool a
  wildcard pattern expands against, so switching profile silently changes what a wildcard means.

### 3.5 WFP

- **No retry when the engine is opened.** PLAN.md §5 asks for a retry while the Base Filtering Engine
  comes up. The open is attempted once (`src/wfp.rs:180-196`), and the comment justifying that cites
  "no writes to protect", which stopped being true at milestone 3.
- **No fallback net-event subscription.** Only `FwpmNetEventSubscribe4` is used; PLAN.md §5 expected
  the older revisions to be loaded for older builds.
- **UWP package display names are absent.** PLAN.md §5 allowed dropping them in v1, so this is an
  accepted deferral rather than an oversight.
- **"Relaunch elevated" is prose, not an action.** The degraded-store banner tells the user to start
  the tool as administrator, but there is no route to do it.
- **Drive and device paths are resolved once.** The map is cached at startup and `WM_DEVICECHANGE` is
  not handled, so a volume mounted after start is not known. The module documents this itself
  (`src/device.rs:9-10`).

### 3.6 MCP

- **The write gate is not in the core.** PLAN.md §10 wants it enforced below the transport. It lives
  inside `mcp_tool` in `server.rs`, and a comment there claims the opposite of what the code does.
- **`mcp_writes = "rules"` promises add, edit, remove and reorder; only add exists.**
- **`mcp_writes = "all"` promises flipping settings and switching profiles; only profiles work**
  (see §3.2).
- **An MCP `rules.allow` of a Detected entry leaves the entry in the list.** Only the HTTP route
  dismisses, so milestone 9's exit test is met only from the browser.
- **No protection against a write race.** No generation counter exists; every write is a full rebuild
  and the last writer wins silently. PLAN.md §10 asked for this before the MCP endpoint shipped.

### 3.7 Architecture, and things the plan named but the build does not use

- **No `winfw-core` library crate.** Everything is one binary; the rule that only `wfp.rs` calls the
  `Fwpm*` API is honoured, the crate split is not.
- **`rmcp` was rejected in favour of hand-written JSON-RPC** (`src/mcp.rs:4-8`). Deliberate, and the
  comment in `Cargo.toml` that still announces it as a dependency to be added is stale.
- **`quick-xml` is absent**, so an existing simplewall profile cannot be read at all. PLAN.md §6 listed
  it for exactly that.
- **The `mcp-template` structure was not carried over**: no contract document, no per-tool smoke
  tests, no skill file, no `tests/` directory.
- **Doc drift**: `src/server.rs:14-27` route table omits the two profile routes, and `src/export.rs:3`
  cites PLAN.md section 3 for export when it is section 2.

## 4. Findings: comparison with simplewall

The reference keeps its WFP semantics in `src/wfp.c`, a file the plan never mentions; nearly all of
this section comes from there. [verified that the file exists]

### 4.1 Default deny — the largest difference

The reference **is** default-deny, by base filters rather than by disabling anything: an unconditioned
`FWP_ACTION_BLOCK` at `FWW_LOWEST` on the connect and the recv/accept layers (`wfp.c:1827-1838`).
[verified] Our tool installs no such filter, so an application we say nothing about falls through to
whatever the machine's other filters decide — in practice the Windows Firewall, which still runs.

Everything else in this section is what the reference needs in order to be able to turn that block on
safely, and what we therefore also lack:

- **Loopback permits** at `FWW_IMPORTANT` (`wfp.c:1605-1643`), so localhost survives the block.
  [verified]
- **IPv6 plumbing permits**: 6to4 plus ICMPv6 types 133 to 136 (`wfp.c:1656-1688`). Without these a
  default block breaks the IPv6 stack. [verified]
- **Stealth-mode filters** against port scanners (`wfp.c:1691-1741`).
- **Boot-time filters** with `FWPM_FILTER_FLAG_BOOTTIME`, enforced before the BFE service starts
  (`wfp.c:1743-1787`). [verified]
- **Optionally turning Windows Firewall off** through `INetFwPolicy2`, as a user choice, not as the
  mechanism.
- **A seven-level weight ladder** (`FWW_IMPORTANT` down to `FWW_LOWEST`) against our two weights. Our
  numeric values `0x0F` and `0x0E` collide with the reference's `FWW_IMPORTANT` and `FWW_HIGHEST`, so
  on a machine where both tools have installed filters, the relative order is arbitrary.

### 4.2 Rule dimensions we do not have

A reference rule (`ITEM_RULE`, `main.h:350-390`) carries applications as a **set**, plus protocol,
direction, address family, a remote address list, a local address list, a comment, a rule class, and
an OS-version gate. Ours is `name`, `action`, `pattern`, `enabled`, and the only WFP condition we set
is `FWPM_CONDITION_ALE_APP_ID`. Missing entirely:

- **Protocol** (TCP / UDP / by number). Every one of our rules is protocol-agnostic.
- **Direction** in / out / any. We always install on all four ALE layers.
- **Address family.** We always install for both IPv4 and IPv6.
- **Remote address**, with CIDR prefix and ranges — this is the per-destination dimension the original
  list asks about in item 7.
- **Local address** as a separate dimension.
- **Ports and port ranges** (`80`, `1024-2048`).
- **Multi-valued** remote and local lists inside one rule.
- **Comment** on a rule and on an application.
- **Rule class / group** (blocklist, system, user), which also decides the weight, and a separate
  overlay table so a stock rule can be toggled without editing it.
- **Application identity beyond a path.** The reference matches services through
  `FWPM_CONDITION_ALE_USER_ID` and UWP packages through `ALE_PACKAGE_ID`, not through a path at all,
  and it taxes each application with a type (`regular`, `device`, `service`, `UWP`, …) which drives
  that choice. We match only `ALE_APP_ID`.
- **Per-application extras**: a file hash, a timer that allows or blocks for N seconds, and a
  "cannot be deleted" flag for system-critical entries.
- A rule **with no applications is force-disabled** on load in the reference. We have no equivalent
  sanity check.

### 4.3 Blocked versus unruly

The reference keeps these apart in three ways we cannot copy today:

- **Unruly** — an application no rule speaks about goes into a stored applications list. That is our
  Detected list, and it is the part we do have.
- **Blocked by one of *its own* filters** — the notification fires only when the dropping filter's
  provider key is its own (`is_myprovider`, `log.c:549-553`). **We never ask which filter produced a
  verdict**, so we cannot tell "blocked by my rule" from "blocked by something else on the machine".
- **Which class blocked it** — derived from the dropping filter's weight, and used to keep noise out of
  the log.

Related, the reference also keeps a real **connection table** (state, local and remote address and
port, byte counters, from `GetExtendedTcpTable` / `UdpTable`), not only an event stream. Our event
record has no local address or port, no remote address, no user name, no package SID, no loopback flag
and no layer or filter name.

### 4.4 Storage, quoting and escaping

Item 4 of the original list, and the news is mostly good:

- The reference stores rules as XML attributes and lets the writer do the quoting, so it has no manual
  escaping problem either. Our TOML literal strings plus JSON are equivalent. **Not a gap.**
- What the reference does that we do not: it **expands environment variables on read and un-expands
  them on write** (`db.c:221`, `db.c:980`), so a profile survives a move to a machine where
  `%ProgramFiles%` differs. We store literal text.
- It repairs stored paths on load: a `\device\…` path is converted to a drive path (`db.c:229`), and
  short 8.3 paths containing `~` are expanded with `GetLongPathNameW` (`profile.c:428`) so the same
  program does not appear twice. We map only the drive prefix, once per process.
- It **lowercases the application path handed to WFP**, with the comment "lower is important!"
  (`wfp.c:2176`, `wfp.c:2199`), and it identifies applications by a **case-insensitive hash**
  (`db.c:422`). Our Detected entries are keyed on exact string equality of the device path, so the
  same program reported with different casing would create a second entry.
- It **validates a rule string on input** against a small character whitelist and refuses anything else
  with a balloon tip. We never validate a pattern at all, so a typo is silently a rule that matches
  nothing.
- Its file format has a **magic, a body-type flag and a SHA256 checksum** of the body, plus a schema
  version with migration. `rules.toml` has neither a version field nor a checksum, and because we
  reject unknown fields, a future field breaks an older binary rather than degrading.
- Wildcards are **our invention**: the reference has none for application paths and matches the
  application-ID blob exactly. Because WFP cannot match `*` or `?`, we expand a pattern against
  observed paths under a fixed cap of 32 (`src/wfp.rs:557`), and that truncation is silent.

### 4.5 Runtime

- **Single instance is solved in the reference** by a named mutant, and it brings the running window to
  the front instead of starting twice (`routine/src/rapp.c:403`). We have no guard at all: two
  `--serve` processes are separated only by whichever fails to bind the port, and two one-shot apply
  runs can race on the store.
- **Volatile filters.** The reference defaults to persistent filters but offers a temporary mode where
  the persistent flag is simply not set, giving filters that die with the reboot. We always set the
  persistent flag, with no way out.
- **Install state is queryable and three-valued** in the reference: disabled, enabled, enabled until
  reboot. We have no stored notion of "filtering is on"; we can only ask the store.
- **Security descriptors.** The reference sets explicit DACLs on the engine, provider, sublayer, callout
  and filter it creates (`security.c`). We set none, so nothing marks those objects as ours in a way
  another non-elevated process has to respect.
- **Session and transaction.** The reference opens the engine with its own session key and a nine-second
  transaction wait; we open with a null session, which works but cannot scope volatile filters.
- **Engine options.** The reference sets `FWPM_ENGINE_COLLECT_NET_EVENTS` and
  `FWPM_ENGINE_PACKET_QUEUING`, and restores the collect option on shutdown (`wfp.c:334-409`). We set
  no engine option on our own session, and PLAN.md §5 records that at least the collect option has to
  be set for a subscription to fire at all — worth re-checking which session ours ends up on.
- **Log discipline.** The reference caps its log file size and quotes every CSV field; ours is one
  unbounded append-only file.

## 5. What is solid

Both passes agree on the foundation, and it is worth writing down so it does not get re-litigated.

1. **Data directory and atomic writes.** Layout under `%APPDATA%\winfw-mcp`, load exactly once at
   startup, `*.tmp` plus rename with `sync_all`, unknown config keys rejected, older configs without
   newer keys still load.
2. **Learning mode mechanics.** Collect per application when no rule covers it, count up without a
   redundant write, newest first, capped and persisted, allow and deny produce a real rule and rebuild
   the store, dismiss only after the store accepted, nothing auto-applied.
3. **The write path.** One worker thread owns the engine handle, full rebuild in one transaction, file
   written before the store on every mutation route, deny outranks allow by weight, persistent provider
   and sublayer under fixed GUIDs.
4. **The MCP access model.** Read-only by default, a refusal that names the setting, a refusal returned
   as a tool result with `isError` rather than as a transport error.
5. **Degraded operation without elevation.** Reported per store class, surfaced as a banner, not a
   crash.

## 6. Suggested priority for an extension plan

Roughly by how much they cost to change later:

1. **Default deny and its base filters** (§4.1) — until this exists the tool is an add-on list, not a
   firewall. It needs the loopback and IPv6 permits to be safe to enable.
2. **Remote destination, protocol, direction and address family** (§4.2) — a rule-shape change, and
   item 7 of the original list cannot be answered without it.
3. **Which filter decided an event** (§4.3) — without provider attribution no honest "blocked by rule
   X" view is possible.
4. **A settings write path** (§3.2) — currently three of four settings cannot be changed at all.
5. **The four bugs in §1**, all small.
6. **Storage hardening**: rule-string validation, previous-generation backup, a version field
   (§4.4).
7. **Runtime finishing touches**: single instance, volatile filter mode, tray menu, icons (item 5).
