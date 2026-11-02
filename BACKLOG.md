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
| B5 | **A rules file that cannot be parsed is replaced by its backup without a trace in the log.** `RuleFile::load_or_create` warns about the fallback, but the rules are read before `init_tracing` installs the subscriber, so the warning is dropped and the page then shows the backup's rules while the file on disk holds something else. Found while testing 0.61.0 with a hand-edited `rules.toml` whose Windows path was written with a single backslash, which TOML reads as an escape. | `src/main.rs` (load order), `src/rules.rs` (`load_or_create`) |

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
| 1 | Single-instance check at startup | **closed in 0.16.0, changed in 0.59.0** — the first `--serve` claims a named mutex; a second start no longer opens the browser, it logs one line and ends with a non-zero status. See [the lifecycle chapter](docs/08-lifecycle.md#only-one-at-a-time). |
| 2 | Re-audit every stage of PLAN.md | **done**, findings in §3 |
| 3 | Compare every feature against simplewall | **done**, findings in §4 |
| 4 | Rules and their storage are fragile around escaping | **answered** — TOML literal strings make escaping a non-problem (§4.4); what was fragile was the missing validation, the missing version and the missing backup, all closed in 0.24.0 |
| 5 | Systray needs a logo, and so does the executable | **closed in 0.17.0** — `assets/winfw-mcp.ico` (generated by `assets/make_icon.py`) is compiled in by `build.rs`, gives the exe its icon and version info, is loaded by the tray, and is served to the browser as `/favicon.ico`. |
| 6 | Does quit keep the firewall rules? | **answered: yes.** Filters are added with `FWPM_FILTER_FLAG_PERSISTENT` (`src/wfp.rs:484`) and outlive the process; `--clear` removes them. The reference behaves the same way. |
| 7 | A new destination for an already allowed application must be noticed | **closed in 0.20.0** — the detector now reads the event's `remote_addr` and asks whether any enabled rule of that application *reaches* it; if not, a Detected entry with that destination is collected, and allow or deny turn it into a rule naming the address. See [learning mode](docs/04-learning-mode.md#applications-and-the-destinations-they-reach) |
| 8 | Entries for attempted accesses that were blocked, and for accesses with no allow | **closed in 0.18.0** — every event names the filter behind its verdict, and the UI reports the rule that filter came from ("by other" when the store blamed a filter we did not install). The blocked/no-allow entries were already logged; they can now be attributed. See [WFP internals](docs/07-wfp-internals.md#naming-the-filter-that-decided-an-event). |
| 9 | Is an application in neither list therefore denied? | **answered: not by us** — see §4.1 |

## 3. Findings: PLAN.md stage audit

### 3.1 Lifecycle and tray

- ~~**The start popup does not exist.**~~ — closed in 0.41.0. PLAN.md §1 promises a popup that
  confirms the tool is running and shows the local URL, then closes. The tray icon came first and for
  a while *was* the announcement; the popup is now the balloon the icon is modified with, it names
  the address, and it closes itself (`src/tray.rs`, `NIF_INFO`). What is left of the finding is
  whether the balloon should be suppressible at all.
- ~~**The tray menu has only `Quit`.**~~ — closed in 0.21.0 for the menu itself: right click now
  opens `Open`, `Pause learning` and `Quit`, and the pause label is built when the menu opens, so it
  follows the flag the monitor reads. The *other* pause PLAN.md §1 named — `Pause protection`,
  which stops enforcing rather than stop collecting — is closed in **0.43.0**: the flag is held by
  the worker that talks to the store and honoured on every piece of work it is given, so a rebuild
  asked for while paused clears instead of installing. What is left of the finding is whether a
  paused tool should say so somewhere louder than a word in the header.
- ~~**The UI never says whether the monitor is running.**~~ — closed in 0.27.0. The thread
  publishes what subscribing did (`starting`, `running`, `refused` with the code, `stopped`) and
  both reports carry how many events the log took in, so an empty list names its reason. The
  monitor's own health over time followed in **0.46.0**: every event stamps the log with the
  wall-clock time of its arrival, the state reports the stamp next to the count, and the page says
  how long ago the newest event was. What is left is interpretation, not information: a running
  feed with a stale stamp could still be a machine that genuinely did not connect, and only the
  user can tell that from a stuck subscription.
- ~~**Reconcile on startup is missing in `--serve`.**~~ — closed in 0.31.0. PLAN.md §6 wants the WFP
  store reconciled against `rules.toml` at startup with the diff surfaced in the UI. The rebuild was
  always made; what was missing was its answer, which now travels to `/api/state` and MCP `status` as
  a `startup` object and to the banner as a line. The *content* of that diff followed in **0.45.0**:
  it now names the rules the file gained, lost, or flipped, so a rule whose action changed while the
  tool was closed is reported even when the counts come out equal. A field narrowed on a rule that
  keeps its name, action and filter count still leaves no trace, which the `startup` prose now says
  out loud rather than promising more than the store can tell.

### 3.2 Settings

- ~~**`port` and `log_level` are still file-only.**~~ — the log level closed in 0.39.0. The
  filter `tracing` installs at startup is now wrapped in a `reload` layer whose handle the state
  holds, so `POST /api/settings` swaps it and the next event is judged by the new level. A level the
  filter cannot read is refused before the file is written, rather than written and then silently
  ignored. What is left is `port` alone: the listener is already bound, and a server that moved its
  own port while a browser tab held the old one would be worse than a restart.
- ~~**A bad value in a settings body answers `500 Internal Server Error`.**~~ — closed in 0.34.0.
  A theme, policy or log level the server cannot read was refused before anything was written,
  which was right, but `status_text` had no branch for it and the client was told the server
  broke. Found by a live run of 0.32.0 and pre-existing: it had answered that way for
  `default_policy` since the route existed. Body parsing now fails as a `BadRequest`, and one
  helper maps it to `400` at the single place a route result becomes a response. What is **not**
  remapped is a refusal about the state — a store that says no, an index past the end — which
  stays `500` on purpose. A TOML text the restore reader rejects (`RuleFile::from_text`) and a
  pattern that fails `validate_pattern` are still `500` too; whether "the file content makes no
  sense" belongs to the client or the server is an open question for the next time one of them
  bites.
- ~~**`theme` is decorative.**~~ — closed in 0.32.0. The field existed in config, was reported in the
  state, and appeared nowhere in `web/index.html`. It is now an enumerated setting (`light`, `dark`,
  `auto`), the header cycles it with a click, and the page applies it: `data-theme` on the root for
  the two fixed choices, removed for `auto`, which leaves the operating system in charge.
- ~~**Logs do not rotate.**~~ — closed in 0.26.0. PLAN.md §2 calls `logs\` rotating, and it now does:
  tracing writes to the file and the console, the file rolls at a megabyte to `<name>.1`, and the
  startup lines the ad-hoc helper appended are `info!` lines like every other. The level of a
  **running** process, which a rolling file could never answer, followed in 0.39.0.

### 3.3 Files, export and import

- ~~**No Profiles area in export.**~~ — closed in 0.30.0. `Area` took a `profiles` value and `all`
  walks into `export\profiles\`, so a backup of everything is everything again. What is left of the
  finding is the whole-file import in the next bullet, which export alone does not settle.
- ~~**Import appends one shared rule; it does not replace.**~~ — closed in 0.33.0 for the file
  direction. PLAN.md §2 describes import as "replace what you have" and defers it. `POST
  /api/rules/replace` (and the MCP `rules.import` tool) now take the text of a whole rules file,
  read it with the same reader startup uses, and replace the live list with it, keeping the
  generation they replaced as the backup. The share string keeps appending, because a pasted rule
  and a restored file are two different intentions.
- ~~**No decode direction over MCP.**~~ — closed in 0.29.0. `rules.decode` reads a share string back
  and writes it only when the caller asks with `add`, so the read stays available under the default
  `mcp_writes = none`. What is left is the whole-file import two bullets above, which one rule at a
  time does not settle.
- ~~**No generation kept of a rules file.**~~ — closed in 0.24.0. Every rule-file write copies the
  file that was there to `<name>.bak` first, and a file that cannot be parsed at startup falls back
  to it with a warning rather than failing to start. What the backup cannot cover is a file that
  parses but lost its rules, because then the loss itself becomes the backup. See §4.4.

### 3.4 Profiles

- ~~**A new profile cannot be created from the browser.**~~ — closed in 0.28.0. `New`, `Rename` and
  `Delete` sit beside the selector, and a name already in use is refused rather than silently
  overwritten. What is left of the finding is that the Detected list is still shared between
  profiles (the next bullet), which a profile manager does not settle.
- **The Detected list is not scoped per profile.** ~~`learn.json` is shared~~ — closed in 0.55.0.
  The lists are keyed by profile name inside `learn.json`, an entry is collected into the list of
  the profile that is live, and switching, renaming or deleting a profile moves its list along.
  What is left of the finding is the other half of the file: the *seen pool* stays shared on
  purpose, because an application one profile has seen is still an application that exists, and a
  wildcard of the live profile expands against all of them.

### 3.5 WFP

- ~~**No retry when the engine is opened.**~~ — closed in 0.35.0. PLAN.md §5 asks for a retry while
  the Base Filtering Engine comes up, and the worker thread of the server opens the engine once for
  the life of the process, so a boot-time miss used to stand for the whole session. Five attempts
  over 3.7 seconds now, in `Engine::open_retrying`, and the stale "no writes to protect" comment is
  gone with the single-attempt it described. What the retry does **not** cover is an engine that
  comes and goes while the server runs: the handle is still opened once, and a service restarted
  mid-session is not re-discovered until the next start.
- **No fallback net-event subscription.** Only `FwpmNetEventSubscribe4` is used; PLAN.md §5 expected
  the older revisions to be loaded for older builds.
- **UWP package display names are absent.** PLAN.md §5 allowed dropping them in v1, so this is an
  accepted deferral rather than an oversight.
- ~~**"Relaunch elevated" is prose, not an action.**~~ — closed by **0.49.0**:
  `POST /api/relaunch` asks the shell for the elevated start, the banner carries the button, and
  the tray menu offers the entry while the process is not elevated.
- ~~**Drive and device paths are resolved once.** The map is cached at startup and
  `WM_DEVICECHANGE` is not handled, so a volume mounted after start is not known. The module
  documents this itself (`src/device.rs:9-10`).~~ — closed by **0.50.0**: a lookup that misses a
  drive-shaped path re-asks the system and retries, throttled to one re-ask per second, so the
  tray needs no device-notification window. Filters already installed from a path that was
  untranslated at the time are still the old text until the next apply, which is now its own
  item below.
- **A filter installed from an untranslated drive path is not corrected by the re-ask.** The
  translation happens when a filter is built, so a rule for a drive that did not exist at that
  moment went into the store with `d:\...` as its literal text. Any later write to the rule list
  rebuilds the filters and fixes it; nothing notices on its own.

### 3.6 MCP

- ~~**The write gate is not in the core.**~~ — the gate itself is gone since **0.36.0**: the writing
  tools were deleted rather than gated, so there is nothing left to enforce below the transport. The
  finding was right that a check in `mcp_tool` could be walked around; the answer was to remove what
  it checked.
- ~~**`mcp_writes = "rules"` promises add, edit, remove and reorder; only add exists.**~~ — closed by
  the removal rather than by implementing the promise. Edit remains open *as HTTP work*; reorder
  closed in **0.47.0** with `POST /api/rules/move` and the order column, which was a user-facing gap
  rather than an agent-facing one. In-place editing of a rule's fields is the last piece.
- ~~**`mcp_writes = "all"` promises flipping settings and switching profiles; only profiles work**
  (see §3.2).~~ — moot in the same way. The setting is still read from an old `config.toml` so such a
  file loads, and the next save drops the key.
- ~~**No protection against a write race.**~~ — closed by **0.48.0**: the state answers a generation
  counter and a whole-list write that names a stale one is refused `409` rather than applied. A
  client that names no generation still wins silently, which is the documented behaviour rather than
  a hole. What remains open is the question of extending the same check to routes that take an index
  (`/api/rules/share`, `POST /api/detected`) rather than a whole list.
- **An agent cannot stop the tool.** `shutdown` was a writing tool, so since **0.36.0** the endpoint
  has no way to end the process. That is the intended reading of "read only", but a client written
  against the old list will look for a method that is no longer there.

### 3.7 Architecture, and things the plan named but the build does not use

- **No `winfw-core` library crate.** Everything is one binary; the rule that only `wfp.rs` calls the
  `Fwpm*` API is honoured, the crate split is not.
- ~~**`rmcp` was rejected in favour of hand-written JSON-RPC**~~ — closed in 0.44.1. The rejection
  stands (`src/mcp.rs:4-8`); the comment in `Cargo.toml` that still announced the crate as a
  dependency milestone 9 would add now says what was decided and why.
- ~~**`quick-xml` is absent**, so an existing simplewall profile cannot be read at all.~~ — closed in
  0.57.0. PLAN.md §6 listed it for exactly that, and `src/simplewall.rs` now reads a profile through
  it. What is *not* done: there is no import button on the page, only the `--import` flag, and the
  XML is read but never written, so this tool cannot hand a file back to the C original.
- **The `mcp-template` structure was not carried over**: no contract document, no per-tool smoke
  tests, no skill file, no `tests/` directory.
- **Doc drift, closed in 0.53.0**: chapter 8 claimed every tray entry is the same request the page
  sends, which made the tray wholly a client of the guarded API. `Pause learning` is not: it flips
  the shared running flag in-process, so nothing crosses the socket and the guard never sees it.
  That is not a hole — the flag is the same one the settings route writes — but the chapter said the
  opposite of the truth, and the Layout in the development chapter had forgotten `src/elevated.rs`
  since 0.49.0 added it.
- **Doc drift, closed in 0.38.1**: the route table in the server module comment omitted
  `/api/settings`, `/api/profiles`, `/api/profiles/switch` and `/favicon.ico`, all four of which the
  router answers. It waited for the move in §28 on purpose, so the table was not edited twice. The
  other half of this finding — `src/export.rs:3` citing PLAN.md section 3 for what is section 2 —
  was closed earlier.
- **Doc drift, closed in 0.37.0**: chapter 7 still claimed the local endpoint and the loopback marker
  were "still only in the event and not in the log", which stopped being true in 0.25.0.
- **Doc drift, closed in 0.38.0**: chapter 4 described `rules.allow` and `rules.deny` as things an
  agent calls over MCP although both were removed in 0.36.0, and chapter 3 still offered an agent
  `rules.decode` and a profile switch over MCP. The two chapters now say that an agent reads
  `detected.list` and that a human decides on the page.
- **`edition = "2024"` is the newest stable edition, not an oversight.** Rust releases an edition every
  three years and each arrives with the toolchain that adopts it, so edition 2027 does not exist for
  `rustc` 1.99.1 yet (it accepts `2015|2018|2021|2024|future`). Migrate deliberately when it lands;
  an edition changes language semantics and is not a cosmetic version bump.

## 4. Findings: comparison with simplewall

The reference keeps its WFP semantics in `src/wfp.c`, a file the plan never mentions; nearly all of
this section comes from there. [verified that the file exists]

### 4.1 Default deny — the largest difference *(closed in 0.12.0)*

The reference **is** default-deny, by base filters rather than by disabling anything: an unconditioned
`FWP_ACTION_BLOCK` at `FWW_LOWEST` on the connect and the recv/accept layers (`wfp.c:1827-1838`).
[verified] Since 0.12.0 our tool can install the same shape through `default_policy = "deny"` in
`config.toml`; since 0.61.0 it is also the **default**, so an application no ALLOW rule mentions is
blocked, which is the behaviour of the reference. `allow` remains selectable in the file and on the
page, and under it traffic we say nothing about falls through to whatever the machine's other filters
decide — in practice the Windows Firewall, which still runs.

Installed with the policy, and therefore no longer missing:

- **Loopback permits** at `FWW_IMPORTANT` (`wfp.c:1605-1643`), so localhost survives the block.
  [verified]
- **IPv6 plumbing permits**: 6to4 plus ICMPv6 types 133 to 136 (`wfp.c:1656-1688`). Without these a
  default block breaks the IPv6 stack. [verified]

Still open, in descending order of how much they are worth:

- ~~A setting the web UI can change.~~ Closed: the header of the page switches the policy, writes
  `config.toml` and rebuilds the store in one request.
- **Stealth-mode filters** against port scanners (`wfp.c:1691-1741`).
- **Boot-time filters** with `FWPM_FILTER_FLAG_BOOTTIME`, enforced before the BFE service starts
  (`wfp.c:1743-1787`). [verified]
- **Optionally turning Windows Firewall off** through `INetFwPolicy2`, as a user choice, not as the
  mechanism.
- **A seven-level weight ladder** (`FWW_IMPORTANT` down to `FWW_LOWEST`) against our four weights.
  Our numeric values collide with the reference's, so on a machine where both tools have installed
  filters the relative order is arbitrary. Measured alongside this: WFP rejects a `FWP_UINT8` weight
  of `0` **and** of `0x10` with `FWP_E_INVALID_WEIGHT`, so the usable window ends at `0x0F`.

### 4.2 Rule dimensions we do not have

A reference rule (`ITEM_RULE`, `main.h:350-390`) carries applications as a **set**, plus protocol,
direction, address family, a remote address list, a local address list, a comment, a rule class, and
an OS-version gate. Ours was `name`, `action`, `pattern`, `enabled`, and the only WFP condition we
set is `FWPM_CONDITION_ALE_APP_ID`.

**Closed in 0.14.0:** protocol (TCP/UDP), direction (in/out, which picks the layers) and port
(single or range). **Closed in 0.15.0:** the remote address with a CIDR prefix, and with it the
address family, which an address decides for itself. Still missing:

- ~~**Protocol by number.** Only TCP and UDP are offered; the reference also takes a number, which
  is how a rule about ESP or GRE would be written.~~ — closed by **0.51.0**: a number from 1 to 255
  is accepted in the file, over HTTP and in a share string, quoted or bare, and the page field
  became a text field so a number can be typed at all (§45).
- **Protocol names beyond the two.** The number works, but a rule about ESP reads better as a name,
  and the reference has the list. Only worth doing together with a table of the names, not on its
  own.
- ~~**Address family.** We always install for both IPv4 and IPv6.~~ — done in 0.15.0, as a
  consequence of the remote address: a rule with a v4 address is installed on the v4 layers only.
  A rule **without** an address still goes on both families, which is right.
- ~~**Remote address**, with CIDR prefix and ranges — this is the per-destination dimension the
  original list asks about in item 7, and it is the largest dimension left. It needs
  `FWP_V4_ADDR_AND_MASK`/`FWP_V6_ADDR_AND_MASK`, which the crate exports.~~ — done in 0.15.0,
  except **address ranges** (`10.0.0.1` to `10.0.0.9`), which the reference supports through a
  `FWP_RANGE_TYPE` of `FWP_UINT32` or `FWP_BYTE_ARRAY16_TYPE`.~~ — the span landed in **0.56.0**:
  `remote` takes `10.0.0.1-10.0.0.9` as well as an address or a prefix, and the store gets a
  `FWP_MATCH_RANGE` condition whose bounds are a `FWP_UINT32` pair or a `FWP_BYTE_ARRAY16_TYPE`
  pair (§50).
- **Local address** as a separate dimension.
- ~~**Ports and port ranges** (`80`, `1024-2048`)~~ — done in 0.14.0.
- **Multi-valued** remote and local lists inside one rule. Our four narrowing fields are
  single-valued: one protocol, one direction, one port range, one address. A rule that wants TCP
  *and* UDP simply leaves the field out, and two ports that are not contiguous need two rules.
- ~~**Comment** on a rule~~ — closed in 0.42.0 for a rule: `comment` is an optional string that
  decides nothing, is skipped when absent, travels with the share string and shows in the page.
  What is left is the reference's *per-application* comment, which has no place to live here because
  a Detected entry is a record of an event rather than one of a person's intentions.
- **Rule class / group** (blocklist, system, user), which also decides the weight, and a separate
  overlay table so a stock rule can be toggled without editing it.
- **Application identity beyond a path.** The reference matches services through
  `FWPM_CONDITION_ALE_USER_ID` and UWP packages through `ALE_PACKAGE_ID`, not through a path at all,
  and it taxes each application with a type (`regular`, `device`, `service`, `UWP`, …) which drives
  that choice. We match only `ALE_APP_ID`.
- **Per-application extras**: a file hash, a timer that allows or blocks for N seconds, and a
  "cannot be deleted" flag for system-critical entries.
- ~~A rule **with no applications is force-disabled** on load in the reference. We have no
  equivalent sanity check.~~ — closed by **0.52.0** without a code change, because the case cannot
  arise here: a rule holds exactly one `pattern`, the field is required, and `validate_pattern`
  refuses an empty one wherever a pattern arrives (§46). The residual case is a hand-edited
  `pattern = ""`, which loads unchecked like every other pattern in the file and installs a filter
  whose application condition is an empty blob, so it matches nothing. The rule ends up inert,
  which is what disabling it would have achieved.

### 4.3 Blocked versus unruly

The reference separates three things here; as of 0.18.0 so do we on the first two:

- **Unruly** — an application no rule speaks about goes into a stored applications list. That is our
  Detected list, and it is the part we do have.
- **By one of *its own* filters** — the notification fires only when the dropping filter's provider
  key is its own (`is_myprovider`, `log.c:549-553`). We match that in 0.18.0: each event's `filterId`
  is looked up in a table built from our own `apply`, so "blocked by my rule" and "blocked by
  something else on the machine" are told apart, and the page names the rule.
- **Which class blocked it** — the reference derives a class from the dropping filter's weight, and
  uses it to keep noise out of the log. We do not derive a class, and the weight ladder is not yet a
  class label in our event record; that distinction remains open.

Related, the reference also keeps a real **connection table** (state, local and remote address and
port, byte counters, from `GetExtendedTcpTable` / `UdpTable`), not only an event stream. Our event
record names both endpoints and both ports (`local_addr`, `local_port`, `remote_addr`,
`remote_port`) since 0.25.0, and it carries the `loopback` marker the callback reports plus the
`local_network` flag 0.37.0 added for the view that shows only traffic that left the machine. The
deciding filter's *rule* name it has had since 0.18.0. What it still does not name is the **user**
(the SID in the event header, which needs a lookup per event), the **package SID**, a **layer name**,
and any **byte counter**, because an event is a moment rather than a table.

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
- It **validates a rule string on input** against a small character whitelist and refuses anything
  else with a balloon tip. Since 0.24.0 so do we, in the shape `_app_isappvalidpath` checks
  (`helper.c:574`) plus the characters a Windows path cannot hold: a pattern must be absolute, and
  no control character or `"`, `<`, `>`, `|` gets in. On every route a pattern arrives by — the
  page, the HTTP API, MCP, import — not on the file, so a file an older binary wrote is never
  refused after the fact.
- Its file format has a **magic, a body-type flag and a SHA256 checksum** of the body, plus a schema
  version with migration. Since 0.24.0 `rules.toml` carries a version (`version = 1`): a file
  without the line is read as this version, and a newer one is refused with both versions named,
  which is the graceful half of what the reference's migration does for us. A **checksum** is still
  absent, so a file that parses but lost content is not noticed; the `.bak` in §3.3 is what covers
  that case now instead.
- Wildcards are **our invention**: the reference has none for application paths and matches the
  application-ID blob exactly. Because WFP cannot match `*` or `?`, we expand a pattern against
  observed paths under a fixed cap of 32 (`src/wfp.rs`), which the log and the page report since 0.60.0
  rather than swallowing: a pattern over the cap names its matches and what was installed.

### 4.5 Runtime

- **Single instance is solved in the reference** by a named mutant, and it brings the running window to
  the front instead of starting twice (`routine/src/rapp.c:403`). We closed this in 0.16.0 the same
  way, with a named mutex rather than the port binding. Since 0.59.0 a second start no longer opens
  a browser at all: it logs one line and exits with a non-zero status. The reference's *window
  restore* is against the facts for a tool whose UI is a browser page nobody reloads, so it is
  closed as not applicable rather than open.
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

1. **Default deny and its base filters** (§4.1) — done in 0.12.0 for the WFP half: the block, the
   loopback permits and the IPv6 permits are installed when `default_policy = "deny"`. What is left of
   the item was making the policy changeable at runtime, which 0.13.0 closed with the settings write
   path.
2. ~~**Remote destination and address family** (§4.2)~~ — done. Protocol, direction and port landed
   in 0.14.0, the destination address in 0.15.0, and item 7 of the original list — noticing that an
   application already allowed to one network reached a different one — landed in 0.20.0.
3. ~~**Which filter decided an event** (§4.3)~~ — done in 0.18.0. `apply` records every filter it
   installs under the id WFP reports against the rule it came from, the worker republishes that table
   on every rebuild, and the monitor resolves an event's `filterId` through it, so the page and the
   API can say "blocked by rule X" honestly. What is left is §4.3's last point (a class derived from
   filter weight) and the two fields no event names directly. The remote address joined the record in
   0.19.0 and the local endpoint with the loopback marker in 0.25.0, so every endpoint an event can
   name is reported; the user name (the SID in the header, which needs a lookup per event) is what
   is left.
4. ~~**A settings write path** (§3.2)~~ — done in 0.13.0 for the two settings that matter at runtime.
   `POST /api/settings` and the MCP tool `settings.set` change `learn_mode` and `default_policy` on a
   running process, write `config.toml`, and rebuild the store. `theme` joined them in 0.32.0. What
   is left is small: `port` needs a restart because the listener is already bound. `log_level` takes
   effect at once now, so all four settings the route names are live in the same request.
5. **The four bugs in §1**, all small.
6. ~~**Storage hardening**~~ — done in 0.24.0: rule-string validation (an absolute path, no
   characters a path cannot hold), a previous-generation backup with a fallback on load, and a
   version field in `rules.toml` (§4.4). A checksum of the body is the one part of the reference's
   file format still not copied.
7. **Runtime finishing touches**: the single instance landed in 0.16.0, the icons in 0.17.0 and
   the tray menu (`Open`, `Pause learning`, `Quit`) in 0.21.0 and volatile filter mode
   (`volatile_filters`, taken out on a clean stop) in 0.22.0. Log rotation, which was the last
   open part of it, landed in 0.26.0. Nothing of the item is left.
8. ~~**The Detected list is short in the answer, not in the data** (§62.1)~~ — done in 0.65.0. The
   answer is ordered by `seen_ms` before it is cut, so the twenty entries the page shows are the
   twenty that asked most recently, and `detected_total` counts the whole list so a badge can say
   `47+`. Deciding whether the page should paginate the whole list instead is still open; see §64.
9. ~~**No test loads the page** (§62.2)~~ — half done in 0.66.0. A test collects every element id the
   script asks for and asserts the markup declares it, which is the disagreement a change to either
   half produces; it was verified to fail when an id is renamed. What it cannot do is notice a script
   that no longer parses, because that needs a JavaScript parser, and a page that does not parse still
   renders its static HTML. Whether to add a parser to the test target alone is an open question.

## 7. Extension round notes (2026-11-01)

Two things were found while the settings write path was built, both recorded here rather than fixed
on the spot.

- **`Settings` is a startup snapshot with one stale field.** `AppState::settings` is never updated
  after startup, which is why `learn_mode` and `default_policy` now have their own atomics (`Live`).
  `active_profile` is written back from the snapshot on every settings save, so `apply_settings`
  has to copy `active_name()` into it by hand. A third runtime-mutable setting should join `Live`
  rather than repeat that trick.
- **A store rebuild answers with a refusal on an unelevated run.** `POST /api/settings` writes the
  file first and then rebuilds the store, so on a machine where the process is not administrator
  the file is changed and the route still reports an error. That matches what `POST /api/rules`
  already does, but it means "settings changed" and "the store agrees" are not the same claim; the
  banner is the only thing that tells them apart.

## 8. Rule-dimension round notes (2026-11-01)

Found while protocol, direction and port were built. The first is a live bug class, and it did
recur one round later, when the address conditions arrived (§9).

- **A pointer condition has to point at the value, not at an `Option` of it.** WFP keeps a pointer
  for `FWP_RANGE_TYPE` rather than a copy. Handing it `&raw const` of an `Option<FWP_RANGE0>` — the
  natural thing when the rule field is an `Option` — installs a filter whose range is read out of
  the wrong bytes, and the store answers `FWP_E_INVALID_ENUMERATOR` (`0x8032001D`) rather than
  anything about pointers. Build the `FWP_RANGE0` unconditionally and take its address.
- **A port means the remote port going out and the local port coming in.** Choosing one condition
  for every layer would make a port rule apply in one direction only. The reference picks per layer
  the same way (`wfp.c:1065`), so this is not an invention.
- **Running several `cargo test` processes at once breaks the live-store tests.** Each process is
  single-threaded, but they share one WFP store, so the filter counts interfere and the run goes
  red on tests that pass on their own. One cargo process at a time, always.

## 9. Remote-address round notes (2026-11-01)

Found while the remote address was built. They confirm what §8 warned about and add one point of
their own.

- **The pointer trap was real for addresses too, and the same fix applies.** The two address
  conditions are pointer conditions, and a rule carries one address in one of two families, so an
  `Option` of each would be two `Option`s where one is empty. Building an enum of the two structs
  and taking the address of the matched inner value keeps the pointer aimed at the struct; the live
  test installs a v4 and a v6 address through the real store to hold that.
- **A v4 address is a big-endian `u32` to WFP, a v6 address is a prefix length.** `FWP_V4_ADDR_AND_MASK`
  wants address and mask as `u32` read most significant octet first, which is what the reference
  gets by byte-swapping the `IN_ADDR` (`helper.c:1291`). `FWP_V6_ADDR_AND_MASK` takes the sixteen
  octets and the prefix as-is. Anyone extending this should not assume the two are shaped alike.
- **Normalising the host bits while reading is what keeps the file honest.** `10.0.0.5/24` is stored
  as `10.0.0.0/24`, so a rule file always shows the network the filter matches rather than whatever
  the user typed. A test asserts this for both families.
- **A hostname is not an address, and nothing resolves one.** The reference does not resolve names
  in a filter either, so `remote` refuses `example.com`. If name rules are ever wanted, they are a
  layer of their own on top of the address, not a WFP condition.
- **Address ranges are the remaining gap in the dimension** (§4.2). A prefix cannot express
  `10.0.0.1` to `10.0.0.9`; the reference does it with a `FWP_RANGE_TYPE` of `FWP_UINT32`. The
  port dimension already proves that shape here.

## 10. Filter-attribution round notes (2026-11-01)

Found while 0.18.0 ("which filter decided an event") was built.

- **A `filterId` is an index, not an identity.** It is handed out when a filter goes into the store
  and does not survive a rebuild, so it can only be read against the table of the rebuild that is in
  the store right now. That is why the worker republishes the table wholesale after every successful
  `apply` rather than merging into it.
- **Id `0` is a safe sentinel.** WFP never returns `0` from `FwpmFilterAdd0`, and the code asserts it.
  A zero therefore cleanly means "the event named no filter", distinct from "a filter we do not own".
- **The table lives in `monitor.rs`, not `wfp.rs`.** `wfp` is a Windows-only module, but the event
  type and its lookup table are needed on every platform so the crate still builds for a doc run. The
  attribution table is therefore defined where the event is defined.
- **Union access in a callback is `unsafe` in edition 2024.** Reading the event's classify arms needs
  an explicit `unsafe` block even inside the `unsafe fn` callback; the edition no longer treats the
  whole body as unsafe.
- **Permit and block both attribute.** Reading the id from both `classifyAllow` and `classifyDrop`
  means an allowed connection also names the permit that let it through, which the reference's
  provider-key check (only meaningful for drops) does not give for free.

## 11. Destination round notes (2026-11-01)

Found while 0.19.0 ("where did the connection go") was built.

- **The version selects the union arm, and nothing checks it.** `remoteAddrV4` and `remoteAddrV6`
  share storage, so reading the wrong one is not an error but a plausible-looking wrong address. The
  code trusts `ipVersion` and reports no address for the connectionless version.
- **Both sides read the v4 number the same way.** The store writes an address condition with
  `u32::from_be_bytes` of the octets and the monitor reads the event back with `Ipv4Addr::from` of
  the same number, which keeps a rule and a log line comparable. Reading it little-endian would print
  `34.216.184.93` for `93.184.216.34` and nobody would notice for a week.
- **An address is not a name.** The event reports the resolved address, so the log shows
  `93.184.216.34` where the user thinks `example.com`. Item 7 — offering a new *destination* for an
  application that is already allowed — therefore has to decide what a destination's identity is:
  the address, the address range a rule can express, or a name the event does not carry.

## 12. Learning-mode destination round notes (2026-11-01)

Found while 0.20.0 ("learning mode notices a destination") was built.

- **A `u128` has to be left-aligned or every address is contained.** A v4 address packed into the
  low 32 bits and a v6 address packed into the high 128 need one convention before a prefix mask
  means anything; the first version put v4 in the low word while the mask worked from the top, so
  `10.0.0.0/24` "contained" everything. `Cidr::contains` now shifts v4 left by 96 on both sides.
- **A destination entry is a second entry, not a second application.** The Detected identity became
  application *plus* destination, which is why `dismiss` takes the remote too and why the same
  application can legitimately hold one plain entry and one `to <address>` entry at once.
- **A name would still be nicer.** The entry the user decides on is `93.184.216.34`, while the rule
  they will write after editing is `*.example.com`. The event does not carry the name, and reverse
  lookup was deliberately not attempted here; a name-aware view of the Detected list stays on the
  table.

## 13. Tray menu round notes (2026-11-01)

Found while 0.21.0 ("the tray menu") was built.

- **A pause that writes no file is a different thing from a setting.** The web settings path writes
  `config.toml` and flips the flag together; the tray pause only flips the flag, deliberately, so
  the reference's pause semantics survive a restart of the *menu* rather than of the process. If a
  user expects the pause to be remembered, that expectation belongs to the file and should be
  settled through the page.
- **`Option<&Arc<T>>::is_some_and` takes `&Arc<T>`.** A method item like `Live::learning` does not
  get its receiver deref-coerced through it, so the closure is not optional; the compiler caught it,
  but it reads like it should work.
- **The menu is read-only state.** It reads the flag on open and writes nothing but the flag, which
  keeps the window procedure free of store, file and lock ordering questions.

## 14. Volatile filters round notes (2026-11-01)

Found while 0.22.0 ("volatile filters") was built. The dynamic-session design was implemented
first and rejected on evidence, not taste.

- **A handle with no session does not own its volatile filters.** Filters installed without
  `FWPM_FILTER_FLAG_PERSISTENT` from a sessionless handle belong to no session and survived closing
  the handle in a live test; only a real `FWPM_SESSION_FLAG_DYNAMIC` session takes them out with
  the last handle.
- **A dynamic session refuses the persistent objects our layout is built on.** With a session
  handle, deleting leftover persistent filters fails with `FWP_E_DYNAMIC_SESSION_IN_PROGRESS`
  (0x8032000B), and the provider and sublayer — created persistent for every run to find again —
  are in the same category. Making volatile mode work through a session would mean session-scoped
  providers or a second handle for every cleanup; the clear-on-shutdown is one message to the
  worker and cannot fail this way.
- **The kill case is the honest caveat.** A killed volatile run leaves its filters until the next
  start, whose startup cleanup removes every filter under our provider key before rebuilding. The
  next process can be any invocation (`--apply`, `--serve`), which is what bounds the gap.
- **`rule = []` followed by `[[rule]]` does not parse.** Hand-editing `rules.toml` to probe the
  live store hit this: the empty-array assignment and the array-of-tables header are duplicate
  keys in this parser's reading. Worth a line in the data chapter if users hand-edit rules.

## 15. Storage hardening round notes (2026-11-01)

Found while 0.24.0 ("harden the rule files") was built.

- **The version lives in the file, not in `RuleFile`.** A dozen places build a `RuleFile` by hand,
  and none of them cares which version wrote it, so `save`/`load_or_create` wrap the rules in a
  private `RuleFileDisk` envelope and the struct stayed as it was. The version also had to be
  serialized before the `[[rule]]` tables, which TOML reads as belonging to the last table opened.
- **A newer version falls back like any unreadable file.** The version check is a parse error, so a
  `rules.toml` from a future version with a backup present is *read from the backup* rather than
  refused outright. That is the right order of consequences (keep running on what we understand),
  but it means the version is what names the problem, not what stops it.
- **`\Windows` in a JSON body is one backslash too few.** Probing the HTTP API with `pattern:
  "C:\Windows\x.exe"` gave `invalid escape at column 56`: the JSON layer needs the doubled form,
  which the browser and `serde_json` produce on their own. Worth knowing when a probe is written by
  hand in a shell, where a heredoc collapses it.
- **Validation is deliberately absent on the file path.** An older binary may have written anything,
  and refusing to start over a pattern written years ago is worse than a rule that matches nothing.
  The check guards the door, not the archive.

## 16. Connection table round notes (2026-11-01)

Found while 0.25.0 ("finish the connection table") was built.

- **A union arm is not an answer.** Both endpoints live in unions of their own (`Anonymous1` for
  the local end, `Anonymous2` for the remote one), and the header says which of them it filled in
  `flags`. Believing the arm instead of the marker is how an event that named no local address
  printed `0.0.0.0`, because a zeroed v4 arm is exactly that. The reference reads the marker too.
- **Loopback is not in the header.** It is `isLoopback` on the classify arms — the same pointers
  the deciding `filterId` comes from — so an event of another type has no marker to report and
  reads `false`. Deriving it from "local equals remote" would have been a guess, and a wrong one
  for any connection where both ends were named.
- **Two tests now report the code rather than the machine.** `a_detected_application_becomes_a_rule`
  and `a_detected_destination_becomes_a_rule_that_reaches_it` asserted that a decided entry leaves
  the Detected list, which is only true once the store has accepted the rule. Unelevated, the store
  answers `0x80070005` and the entry stays — the documented behaviour — so the assertion now names
  that condition instead of failing over it. The suite is green elevated and unelevated.
- **Learning mode reads the remote end only, and that is worth a test.** The new field made the
  question visible: an event whose local address is an unreached network and whose remote end is
  empty must offer nothing, which is what `a_detected_destination_is_the_remote_end_and_never_the_local_one`
  now pins down.

## 17. Log rotation round notes (2026-11-01)

Found while 0.26.0 ("the log rotates") was built.

- **The rename has to close the handle first.** Windows refuses to move a file a handle has open,
  so a rotation that renames before closing is a rotation that silently does nothing. The handle is
  taken out of the slot, the rename and the reopen happen, and only then is the count reset; a
  rename that failed leaves the count alone so the next writer asks again rather than appending to a
  half-rotated file.
- **A bound checked before the write overshoots, by design.** The writer asks how many bytes it has
  already counted, so the generation that rolls is the limit *plus at most one line*. A test that
  demanded exactly a megabyte failed on the arithmetic rather than on the module, and the range is
  the honest assertion.
- **A log file is not worth failing a startup over.** The old helper appended to the file and
  dropped an error it had nowhere to report. Now a file that will not open is printed on the console
  and the run continues with the console alone, which is the right way round for a firewall.
- **The tee belongs to the module, not to `main`.** Because `MakeWriter` is implemented on the log
  itself, the subscriber gets one writer that is both halves, and a debug build still shows every
  line while the release build's lines survive in the data dir. ANSI is off for it: the same bytes
  go to both halves, and escape codes in a file are read in an editor later.
- **`cargo build --release` does not compile `#[cfg(test)]`.** A type error in a test was caught by
  the test run and not by the build, so the two are never the same check.

## 18. Event-feed status round notes (2026-11-01)

Found while 0.27.0 ("say why the connection list is empty") was built.

- **A supported degraded state still needs a face.** An unelevated run cannot open the event
  session, and that is documented behaviour, but the page answered an empty list with silence. The
  fix is not a banner nobody reads; it is the state next to the list it explains.
- **Refused without the code is not an answer.** `0x00000005` and any other failure look the same
  in the UI, and only one of them means "start elevated". The code travels with the state for that
  reason, which is also why the status is a struct rather than a `&'static str`.
- **The counter counts what arrived, not what survived.** The bounded log answers "how many events
  are in here", which after the capacity is reached is a constant. What distinguishes an idle feed
  from a working one is a count of what the callback handed over, so `EventLog::delivered()` reads
  the sequence counter rather than the queue length.
- **The status belongs to `Live`, not to a new channel.** The monitor thread already shares that
  struct with the request threads, so publishing to it needed no new plumbing and both reports —
  the page's and the MCP client's — read the same value. A mutex rather than an atomic, because the
  report carries the code with it and only one thread ever writes.
- **One helper so the two reports cannot disagree.** `AppState::monitor()` is what both
  `/api/state` and the MCP `status` tool answer with, which is the same rule the settings follow:
  the authoritative value is read in one place.

## 19. Profile management round notes (2026-11-01)

Found while 0.28.0 ("create, rename and delete a profile from the browser") was built.

- **A profile was always a file, so the browser only ever needed three verbs.** The profile list
  already came from the rules directory, which meant creating one was "write a file and switch to
  it" and deleting one was "remove the file". No new storage concept was needed, only the endpoints
  that admit a profile is a file.
- **A new profile copies the current rules rather than starting empty.** Starting empty would have
  dropped the live process onto a rule set with nothing but the built-ins, which reads as "the
  firewall stopped working". Copying first keeps the connection state a user expects while they edit
  the new set down.
- **The switch had to become a helper.** `switch_profile` owned the "read the rules, build a live
  filter set, apply it" sequence, so `make_live()` was extracted before the three new routes could
  reuse it. Refactoring first kept the routes at four lines each instead of duplicating the apply
  path three times.
- **Deleting the live profile falls back to the default rules.** There is no meaningful "no profile"
  state while the engine is running, so an empty name is the fallback. The default rules are also
  the only rules that cannot be deleted, which is why an empty name is refused rather than treated
  as a file called `""`.
- **A rename is a file rename, not a rewrite.** The rules are saved to the old name first so no edits
  are lost, then the rules file and its backup move together. Rewriting the content under a new name
  would have left the backup behind with the old name inside it.
- **The backup travels with the file.** Every delete removes the backup path too, because a stale
  backup for a profile that no longer exists can only ever confuse the next import.

## 20. MCP rule editing round notes (2026-11-01)

Found while 0.29.0 ("an agent can edit the rule list") was built.

- **An index is the only handle an agent has.** A rule the agent did not write has no name it can
  trust — the UI's default `new rule` repeats, and a rule it wrote itself may have been renamed by
  hand — so `rules.remove` takes the index `rules.list` reported. An index past the end is refused by
  name rather than answered with a no-op, because the usual cause is a list the agent read before
  something else changed it.
- **Removing has to reach the file, not only the store.** The rules are the source of truth and the
  store is derived from them, so the tool saves first and rebuilds after, exactly as the browser's
  route does. Rebuilding without writing would have undone itself on the next start.
- **A share string needed the other direction before it was a feature.** `rules.share` could encode
  since 0.12.0 and nothing over MCP could read one back, so an agent could hand a rule out but not
  take one in. `rules.decode` answers with the rule and writes nothing unless told to with `add`,
  which keeps the read usable under the default `mcp_writes = none`.
- **Decoding validates on the way in.** Base64 around JSON is a format a human edits by hand, so the
  pattern is checked before the write rather than after, and a share string holding `not-a-path` is
  refused like any other bad argument.
- **Dismissal was the asymmetry, not the rule.** Both paths could already append a rule; only the
  browser took the entry off the Detected list, so a decision made by an agent left work behind that
  a human then had to clear. Both now follow the same rule, and it is the one the store decides:
  dismissal happens only once the write is accepted, so an unelevated run leaves the entry visible
  instead of pretending the decision was lost.
- **The comparison is exact on purpose.** A Detected entry carries the application in device form and
  the destination as the text the event reported, so `rules.allow` dismisses against the arguments it
  was given rather than against a normalised copy, and an agent that passes what `detected.list`
  reported clears exactly one entry.

## 21. Profiles in export

- Export grew a fifth area, `profiles`, and the default `all` area walks into `export\profiles\`
  too. Profiles keep a subdirectory of their own because they are a set of equal files; flattened
  next to `rules.toml` the default rules file is impossible to pick out of a backup afterwards.
- An empty profiles directory exports nothing and leaves no directory behind, which is the normal
  state until the first profile exists.
- The names come from `rules::list_names`, the same sorted list the Profiles area reads, so a backup
  can never hold a file the interface does not show.
- The web UI posts an empty body to `POST /api/export`, which means `all`, so its Export button
  picked profiles up with no change of its own. Only the MCP schema needed the new value.

Three tests cover it: profiles copied by `all`, the `profiles` area leaving the single files out,
and an empty profiles directory exporting nothing.

## 22. Startup reconcile round notes

- The rebuild `--serve` makes of the store before it binds already answered with `removed` and
  `installed`, and the answer went into `info!` and nowhere else. It is kept now, in a `Startup`
  value the state holds for the life of the process.
- The two counts are the diff PLAN.md §6 asks for, and they were already correct: `apply()` removes
  every filter carrying our provider key and installs what the rules describe, so the pair says
  exactly what changed while the tool was closed.
- `differs` is computed at construction rather than in the page, so the HTTP body and the MCP tool
  cannot disagree about whether the difference is worth a line. It is true only when the store took
  the rebuild *and* the counts differ.
- A refused store keeps `differs` false on purpose. It has no counts to compare, and the degraded
  store banner names the refusal already; a second, emptier notice under it would read as a bug.
- A state built in a test is `measured: false`, which is its own field rather than a smuggled
  meaning in `ok`: two zeros from a process that never asked the store must not look like a store
  that was found empty.

Three tests: `differs` only when the counts differ, the state endpoint carrying the counts, and an
unmeasured state saying so instead of claiming a diff.

## 23. Theme round notes

- The setting was already written, loaded and reported; what it never had was a reader. Making it
  one turned out to be three separate things: a type that cannot hold a name the page cannot render,
  a style sheet that answers to that type, and a way to change it without editing a file.
- `theme` is an enum now rather than a `String`, for the reason the default policy has always had:
  a free string lets `neon` into `config.toml`, where it does nothing and explains nothing. An
  unknown name is refused at both entrances, and a name an older binary wrote is clamped to the
  default rather than failing the load, because a theme is not worth refusing to start over.
- The cycle lives in the page, not in Rust. A `next()` on the enum was written, then deleted: only
  the browser knows what the user clicked last, and a server-side cycle would disagree with a second
  tab the moment either was clicked.
- `auto` is the absence of a decision rather than a third value in the style sheet, so it is
  expressed by removing the `data-theme` attribute and letting `prefers-color-scheme` win. This is
  why the dark rules are written twice, once under the media query and once for an explicit
  `data-theme="dark"`: a chosen dark has to win over a light operating system.
- The theme is held in an `AtomicU8` beside the other two live settings, which is the same shape and
  the same reason: the state endpoint reads it on a different thread from the one that writes it. It
  is a `Default` impl written by hand now rather than derived, because a derived default would be
  `0`, and `0` is `auto`.
- A test for the refusal over MCP needed a state with `mcp_writes = all` and initially had the
  default, so it asserted the permission gate's message while believing it asserted the parser's.
  The two refusals look identical in the body, which is worth remembering about the next one.

## 24. Whole-file import round notes

- Export had no second half: a backup you cannot restore is a file you have to copy back by hand
  with the tool stopped. `POST /api/rules/replace` and MCP `rules.import` close that.
- The body is the file's **text**, not a path. A browser cannot name a path the server holds, and
  sending text means the same route serves a page, an agent and a `curl --data-binary`.
- The text goes through `RuleFile::from_text`, which is the reader startup uses, so the version
  check, the unknown-field refusal and the value parsers are the same rules a file on disk is held
  to. Validating with a different parser is how an import gets to write something the next start
  cannot read.
- Every pattern in the file is re-checked, not just the file's shape. A rules file exported by this
  build passed the check when it was written, but a person who edits it by hand has not been read
  by anything since, and a pattern the store cannot hold is exactly the mistake worth catching.
- The page asks before it posts. Replacing the list is the one action on it that can take rules
  away rather than only fail to add them, and a file chooser that fires on every selection needs
  its value cleared afterwards or the same file chosen twice looks like nothing happened.
- The share string keeps appending on purpose. A pasted rule and a restored file are different
  intentions, and one route that guesses between them would be a third thing nobody asked for.

## 25. Bad-request status round notes

- The refusal was always right; only its status lied. Every failure inside `Server::route` was
  printed into a `500` at one call site, so "you sent me something I cannot read" and "the store
  said no" were the same sentence to the client.
- The distinction is carried in the error, not in the status: a `BadRequest` marker type is what
  body parsing fails with, and `respond` downcasts once. Adding a route needs no thought about
  status afterwards, which is the reason the mapping moved out of the call site.
- `anyhow`'s `downcast_ref` sees the outermost error only, so a body parse must not run through
  `.context()` on its way out or the marker disappears inside the context wrapper. That is why
  `parse_body` builds the message itself.
- The old `parse_or_default` wrapped a `context` on a `Result` inside `Ok(...?)`, which is the
  shape clippy has been calling "enclosing `Ok` and `?` are unneeded" about since the route
  existed. The rewrite is what the lint wanted, and the warning count went down rather than up.
- Only the body was remapped. A refused store, a file that would not write and a share index past
  the end stay `500`, because those refusals are about the state and the client cannot fix them by
  sending the same body differently.
- Verified live as well as in tests: `theme: "neon"`, a truncated `{` and a misspelled field each
  answered `400`, a good theme still answered `200`, and `rules/share` at an index past the end
  answered `500`.

## 26. Engine-open retry round notes

- PLAN.md §5 asked for this retry from the start, and the comment that explained it away — "no
  writes to protect" — had stopped being true when the write path landed. A stale comment that
  once was honest is worse than none, because it reads like a decision still in force.
- The shape that mattered: the retry loop is generic over the attempt and over its sleep, so the
  wait policy is a function under test rather than a number living in a `thread::sleep` nobody can
  reach without a firewall service. The tests hand it a fake attempt that recovers on the third
  try and one that never does, and check what was slept, not how long the wall clock moved.
- Five attempts over 3.7 seconds is boot policy, not a mood: long enough to outlast a service
  still starting, short enough that a machine whose firewall service is *disabled* is slow to
  start rather than started slowly.
- The worker thread opens the engine once for the life of the process. The retry covers the
  service coming up; it does not cover a service restarted mid-session, which stays a miss until
  the next start. That gap is the next bullet under §3.5, deliberately not folded in here.
- The single-attempt `Engine::open` stays public for tests and for any caller that wants exactly
  one try; the long-running callers are the ones that moved to `open_retrying`.

## 27. Read-only endpoint round notes (2026-11-02)

- Deleting nine tools is a bigger API cut than any setting would have been, and the reason is worth
  keeping in words: a firewall rule is the way out to the network, so an agent allowed to write a rule
  is allowed to decide its own traffic is fine. Reading is a question; writing was the answer.
- The removal is by deletion, not by a switch, on purpose. A setting that defaults to read-only can be
  flipped by whoever edits `config.toml`, which is fine, but it also means the code carries a path
  nobody tested in anger. There is no `mcp_writes` any more, and the config keeps the key only so that
  an old file still loads.
- The HTTP half needed more thought than the MCP half. The tool often runs elevated, so a `POST` from
  this machine is a write done with rights the caller does not have. Hence the token, the `Host`
  check on every route, the `Origin` check and the content type on writes.
- The `Host` check applies to reads, and that is the DNS-rebinding defence rather than tidiness. A page
  whose domain resolved to `127.0.0.1` after it loaded can read the whole state of the firewall if
  nothing looks at the name it asked for.
- ~~The token is memory-only, which is a decision with a cost: a tab opened by typing the address has
  no token in its URL and has to learn it from the first state body. That is why the state carries it,
  and why a second instance opening the plain URL still works.~~ — changed in 0.58.0: the state stopped
  carrying it, and the tray hands it over in a URL fragment. See §53.
- One claim worth not overselling: a process running as the same user can read the token from
  `/api/state` and write anything. The guard defeats a page that is not ours, not an attacker with the
  account. The fingerprint on `rules.toml` is what addresses the file being edited behind our back, and
  it reports rather than prevents.
- `rules.toml.stamp` follows the active rules file, so a profile switch re-fingerprints rather than
  inheriting the previous profile's record. A profile with no stamp of its own is compared against the
  file as it was found, which means the first notice after a switch can only be produced by a change
  made after it.
- The MCP endpoint is exempt from the guard's write checks and must stay that way: it is configured with
  a URL, and a URL a human can copy is not a secret. Adding the token there would mean telling agents
  about sessions, which is the complication this round was meant to avoid.
- A UI bug surfaced on the way: `POST /api/rules/share` answers with a bare Base64 string, and the page
  read every response as JSON, so the share string failed to parse on its padding character. The page now
  answers according to the `content-type` it was given.

## 28. Splitting `src/server.rs` (done in 0.38.1)

Agreed 2026-11-02, deliberately *not* taken up while a feature round is open: the running work
(read-only MCP, the guarded HTTP API, external traffic only) is finished, tested and released first,
so the split lands on a clean tree rather than in the middle of a diff.

- The finding is honest: `src/server.rs` is about 3800 lines and the module comment still calls it a
  *transport*, which was true at milestone 2 and is not true now. HTTP transport, the guard, the shared
  state, the WFP worker, every route with its body types, profile management, the settings logic and the
  MCP dispatcher all live in one file, and roughly half the file is tests.
- The target is a directory `src/server/` with one job per file: `mod.rs` (the socket loop), `http.rs`
  (request, response, headers, body parsing), `guard.rs` (the guard and nothing else), `state.rs`,
  `worker.rs`, `routes.rs`, `profiles.rs`, `settings.rs`, `mcp_tools.rs`.
- Pure movement is the rule. No renames of routes, JSON fields, error texts, status codes or log
  messages, and no improvements on the side, however small. The public paths under `crate::server::`
  stay reachable through `pub use` in `mod.rs`, so no caller changes. Visibility is not widened beyond
  what the move forces.
- Two files are the point of the exercise. `guard.rs` must hold the guard and its helpers only, with no
  dependency on routes or the worker, so it can be reviewed in minutes. `mcp_tools.rs` must hold no write
  access to rules, settings, profiles or the store at all, which is checkable by grep and is the mechanical
  form of "the endpoint reads".
- Each `Server::route` match-arm becomes a function of its own, with `route` distributing only, and the
  route table in the module comment gets the routes it is missing (`/api/settings`, `/api/profiles`,
  `/api/profiles/switch`, `/favicon.ico`). That doc drift is the §3.7 finding this section closes.
- Acceptance: the same number of tests, all green elevated and unelevated, no new clippy warnings, a
  release build that starts, a page that loads, and an allow/deny from the Detected list that still
  reaches the store. A patch release, because nothing a user can observe changes.
- One note for whoever takes it: `writable_state()` in the tests was deleted in **0.36.0** (its last user
  was the removed writing tools), so the shared test helpers to move are `state()`, `state_with()`,
  `connection()` and `TEST_TOKEN`.

## 29. External-traffic-only round notes (2026-11-02)

- **The drop lives in the callback, not in `EventLog::push`.** That is deliberate: a test that hands
  an event straight to the log still gets it back, which is what a diagnosis of the log itself needs,
  and the callback is the one place that can keep an event out of the log, the counter, the seen list
  and the Detected list in a single step. The cost is that `delivered()` — the `running, N events`
  next to the heading — counts what the callback accepted rather than what the machine did. Written
  into chapter 7 rather than left to be rediscovered.
- **`local_network` is computed in the callback while the address is there**, not in the page. A
  client that hides local-network rows over MCP needs the same answer the page has, and re-parsing an
  address per request would put the rule for what counts as local in two places.
- **The loopback drop and `local_network` are two different questions** and are kept in two different
  functions on purpose: an event is dropped for what it is (a connection to this machine), and marked
  for where the destination lives (a network on the segment). An address that parses as neither is
  shown and unmarked, which is the only safe answer for a form the reader does not recognise.
- **The new key does not appear in an existing `config.toml`.** The file is written on the first run
  and on a settings change, not at every start, so an install that predates 0.37.0 has no
  `debug_show_loopback` line and reads the default (`false`). Someone has to type it to turn the
  switch on. Adding the key to every config at startup would rewrite the file on every run for no
  behaviour change, so it is left as it is and written down here.
- **Not protected by any of this**: the filter checkbox is presentation only and is not stored, so a
  reload shows the local network again. Persisting it in `config.toml` would need it to be a setting
  the page can write, which is the settings write path in §3.2.

## 30. Handbook alignment round notes (2026-11-02)

- **The audit was the handbook read against the code, not a proof-read.** Each claim about what the
  endpoint answers was compared with `tool_list`, and the route table in chapter 5 with the match
  arms of `Server::route`. The code was right everywhere; the prose was wrong in five places, and
  all five were left behind by **0.36.0**, which is what a release that deletes nine tools owes.
- **Corrected**: chapter 3 no longer hands an agent `rules.decode` or a profile switch, chapter 4
  puts the Detected decision on the page, chapter 5's import paragraph is past tense about
  `rules.import` and its route table lists `/favicon.ico` and says which connections
  `GET /api/events` streams, chapter 8 drops `shutdown` from the MCP tool list, chapter 10 states
  what an agent can see since **0.37.0**, and the README index rows name the question each chapter
  answers.
- **A tool name in the handbook is an API promise**, which is why prose gets its own release. Someone
  who reads "an agent can call `rules.allow`" sends the request, receives `-32601 method not found`,
  and cannot tell from the answer whether the endpoint is broken or the sentence is.
- **New in this round, not drifted**: chapter 2 now says that a config written before a key existed
  never gains it, because the file is written on the first run and on a settings change rather than
  at every start. This closes the gap §29 noticed for `debug_show_loopback`; `volatile_filters` has
  the same property and is named next to it. Verified against `SettingsEdit`, which accepts
  `learn_mode`, `default_policy`, `theme` and `log_level` and nothing else, so neither key can be
  written from the page.
- **Left alone on purpose**: the route table in the `src/server.rs` module comment is still four
  routes short of the router. It belongs to §28, and correcting it here would edit the same comment
  twice for no information the reader gains in between.
- **A flaky test found on the way, fixed in the helper.** `a_missing_file_is_created_with_the_defaults`
  failed on a run where it had passed before, and the cause was not the config code: `scratch_dir`
  names its directory after the process id, Windows recycles process ids, and the counter restarts at
  zero every run, so a run can land on a directory an earlier run left behind — and the helper only
  called `create_dir_all`, which accepts an existing directory. The directory it landed on held a
  `config.toml` written by a build from before **0.36.0**, which still wrote `mcp_writes`, so the test
  read that file instead of creating the defaults and compared `Some("none")` against `None`. The
  helper now removes the directory first, which is what its own doc comment always claimed. Tests
  still leave their directory behind to be inspected.

## 31. Module split round notes (2026-11-02)

- **`src/server.rs` is `src/server/` now**, nine files, and the move was the point: `guard.rs` is
  278 lines and holds nothing but the guard, so the whole answer to *who may write* fits on two
  screens, and `mcp_tools.rs` contains no `save(`, no `StoreWork::Apply`, no `StoreWork::Clear` and
  no assignment to `.rules`, which is the mechanical form of "the endpoint reads".
- **The tests were counted, not trusted.** 55 `#[test]` items in the old file, 55 in the new
  directory, and every test body compared byte-for-byte against `git show HEAD:src/server.rs`
  modulo indentation. 167 tests before, 167 after.
- **Four deviations from the plan, all forced.** `worker.rs` also took `first_read_error` and
  `summary`, the `cfg(windows)` helpers of `handle_work`. `http.rs` took two tests that check
  `respond` and `BadRequest`, which the plan's list of test buckets did not mention. The
  `include_str!`/`include_bytes!` paths went one level deeper. The route arms take only the
  arguments each arm actually uses rather than a uniform `(state, worker, request)`, because the
  uniform form warns about parameters it does not touch.
- **The module comment still calls the module a transport.** §28 called that out as untrue, and it
  was left alone because the rule for this round was *no improvements on the side*. It is a fair
  description of `mod.rs` and not of `state.rs` or `worker.rs`; rewording it is a later, separate
  edit.
- **Noticed and deliberately not touched**, in the order they were found: the `#[allow(dead_code)]`
  comment on `Request::new` claims the socket path uses `from_parts` when it calls `with_headers`;
  `type WFPWorkerAlias = WfpWorker;` has exactly one user, the `worker` field of `Server`; `guard`'s
  doc comment says "The three checks" while the function refuses on four grounds, since
  `content-type` is a rejection of its own.
- **One process lesson, written down because it cost a detour**: a batch of `cargo` commands fired
  in parallel produced three different failing test counts from the same tree. `cargo` blocked on
  each other's package-cache lock. Serial is not just the rule for the test *threads* here.

## 32. First-run examples and a live log level round notes

Both features are released in **0.39.0** and this section is closed. What is left is only what a
local shell cannot reach:

- A `--serve` run elevated has to show that the log file really starts and stops accepting lines
  after a level change. The unit tests prove the reported value and the refusal; they cannot prove
  that `logs\winfw-mcp.log` grows again after `error` becomes `debug`.
- The new icon sizes (16, 24, 32 and 48) need a look on a display at 125 % or 150 % scaling, which
  is the reason the 24-pixel entry was added.
- `RuleFile::examples()` is written only when the file is absent. A file that exists but is empty
  stays empty, and a profile that exists with nothing in it is the user's decision to keep it that
  way; nothing prompts for examples afterwards. (2026-11-02)

The decisions the round made, so that a later reader knows they were deliberate:

- **The examples are inert by construction.** `RuleFile::examples()` answers a rules file that does
  not exist yet with one allow and one deny: the applications `C:\test\tool1.exe` and
  `C:\test\tool2.exe`, the destinations `192.0.2.0/24` and `198.51.100.0/24`. Both prefixes are
  documentation ranges of RFC 5737 and both paths name a directory a normal machine does not have,
  so the pair shows the shape of a rule without deciding a single real connection.
- **`load_or_create` still means empty.** The examples are decided in `main.rs`, on the branch that
  knows whether the file existed, not inside the reader. That keeps the reader's promise — a file
  that is not there is empty — which is what the storage tests assert and what an emptied file
  depends on: a person who deletes every rule is not handed the examples back on the next start.
- **A remote address is CIDR, so the examples are not hostnames.** `example.com` and `evil.com` are
  what a person would type, but `Cidr::FromStr` refuses a name, and resolving one is a feature of
  the reference this build does not have yet (see section 4.2).
- **The log filter is a `reload::Layer` on a registry**, and the handle lives in `AppState`. A
  request that does not name the level leaves the filter alone, so editing the theme does not
  quietly drop a `RUST_LOG` override; a body that does name it replaces that override, because
  after an explicit write the file is what the user expects. A level the filter cannot read is
  refused rather than written and then ignored.
- **A state built without a subscriber remembers the level and changes nothing else.** That is
  every test, and it is the honest limit of what the unit tests can prove about a live reload.

## 33. Documentation overhaul round notes

Closed by the handbook pass that came after 0.39.0:

- The version history moved out of the handbook into a root `CHANGELOG.md`. The handbook answers
  how the tool works; the changelog answers what each release produced. The README index row for
  chapter 9 and its "working documents" line point at the new file.
- The section existed twice in the commit that made 0.40.0; the duplicate is gone and the
  numbering is unique again. (2026-11-02)
- The "since 0.x.y" narration is gone from chapters 2 to 8 and 10, replaced by the present tense.
  The two historical notes that stay (the writing tools in chapter 6) are about the *design*, not
  about a date.
- Chapter 10 gained the numbered request path (bind, mutex, reads, writes, `/mcp` without a
  token) so a reviewer can check the whole answer in one place, and the answer about test code is
  written down in chapter 9: it is all `#[cfg(test)]` and ships nowhere.

Open after the pass:

- The review is still owed by somebody who did not write it: the request path is documented, but
  nobody outside has confirmed that no other local caller can bypass the guard. The brief for that
  reviewer is `SECURITY_REVIEW.md` at the repository root, written for someone who has not seen
  the code. (2026-11-02)
- The elevated `--serve` observation from section 32 is still owed: that `logs\winfw-mcp.log`
  really starts and stops accepting lines when the level is changed through the web UI.
  (2026-11-02)
- `docs/05` still describes the page area by area; a screenshot has never been part of the
  handbook, and a reviewer may ask for one.

## 34. Start popup round notes

Released in **0.41.0**. The first bullet of §3.1 is closed: PLAN.md §1 promised a start popup that
says the tool is running and shows the local URL, and a double-clicked tool had nothing to say — a
release build has no console, so even the line the startup logs goes somewhere the user is not
looking.

The decisions the round made, so that a later reader knows they were deliberate:

- **The popup is a balloon, not a window.** `Shell_NotifyIconW` with `NIF_INFO` shows the address
  beside the icon and closes itself after the shell's display time. It needs no window, no widget and
  no second thread, which is what PLAN.md §1's "no layered popup-notification windows" was
  protecting.
- **The icon keeps its shell version unset.** Reporting a click on the balloon needs a version, and a
  version also moves the mouse events out of the high word of `lParam`, where the window procedure
  reads them today. The existing click path was worth more than a balloon click, so the balloon is
  read rather than used and only ever dismisses itself.
- **The text is the address without the token.** The tray opens the browser on a URL carrying the
  session token, and a token is thirty characters the user did not ask for in a balloon that is
  readable for a few seconds. The page reads its token from its own first response anyway, so the
  shorter text loses nothing.
- **A refused balloon costs a debug line.** The icon is in the notification area either way, and the
  popup is the least important thing the shell is asked for here.

Open after the round:

- Whether the popup should be suppressible — `--quiet`, or a setting — has not been asked. A tool
  started from the Startup folder shows it on every logon, which is the intended behaviour until
  somebody says otherwise. (2026-11-02)
- No human has seen the balloon yet: an unelevated `--serve` run reaches the `NIM_MODIFY` call, but
  whether the shell paints it on this desktop is a visual fact no unit test can assert. (2026-11-02)

## 35. Rule comment round notes

Released in **0.42.0**. The field is `comment` on a rule: optional, skipped when it is absent, and
never sent to the store.

The decisions the round made, so that a later reader knows they were deliberate:

- **The comment decides nothing.** It is not a rule dimension, so it does not narrow a connection and
  the store is not told about it. A wildcard rule expands into a dozen filters, and a comment written
  into each of them would be the same sentence a dozen times in a store nobody reads with a comment.
- **An absent comment is not written at all.** With the four narrowing fields this was already the
  rule, and it matters more here, because a comment is the first field an old file is certain not to
  have. A rules file that never uses the field is byte for byte what it was before.
- **Too long is refused, not cut.** The reference truncates at its buffer size. Refusing tells the
  person who typed it at the time, and keeps a file free of sentences that lost their ending. The
  limit is 200 characters, and a control character is refused for the same reason.
- **The examples carry comments.** A first-run file that shows the field teaches it; `rule` entries
  the user writes without one are unaffected.

Open after the round:

- The add-rule form on the page has no comment field of its own: a new rule arrives with the name
  `new rule` and an empty comment, which is editable in the table. A form that asks for the reason is
  a nicer interaction and has not been built. (2026-11-02)
- `POST /api/detected` writes no comment either, so a rule decided from the Detected list explains
  itself with its name alone. Whether the destination should be written as the comment is a design
  question, not a missing line of code. (2026-11-02)

## 36. Pause protection round notes

Nothing was opened by this round. Two things are worth writing down now that the switch exists:

- **A paused tool is quiet about it.** One word in the header is the whole announcement, and a
  machine whose firewall has been paused for a week looks like a machine whose firewall works. A
  tray tooltip, a second icon and a banner are all available; none of them is obviously right, so
  this waits for somebody to be annoyed by it.
- ~~**The export does not name the profile it came from.**~~ — closed in 0.44.0. `export\` held
  `rules.toml`, `config.toml`, `learn.json` and `profiles\`, and after a while nobody could say
  which profile a given directory belonged to. A rules, profiles or all export now also writes
  `profile.txt` naming the active profile, the unnamed one written as `default`. Nothing reads the
  directory back except a human, so this stays a note rather than a check.

## 37. Export profile round notes

Released in **0.44.0**. `export::run` took a third argument, the active profile name, and a rules,
profiles or all export writes it to `export\profile.txt`. The caller is the export route, which
already knew the name.

The decisions the round made:

- **`default` for the unnamed profile.** The rules of no named profile live in `rules.toml` and the
  page calls them `default`, so the file says the same thing the user saw. An empty name would have
  been accurate for a config file and useless for a human holding the export.
- **The file is written, not copied.** Unlike the other exports it has no source on disk to read, and
  writing it atomically like everything else keeps a half-written note from outliving a crash.
- **Pushed last into `files`.** A backup listing should read as data first and the note about where
  the data came from after it.
- **Config-only and Detected-only exports write no note.** Neither area carries rules, so neither has
  a profile to name, and a file that is always the same value would only invite the question of
  which rules it referred to.

Open after the round:

- `profile.txt` names the profile but says nothing about *when* the export ran, so two directories
  copied out on different days are still told apart by their timestamps. A timestamp line in the
  same file, or a full manifest with the version of the tool, would close that. (2026-11-02)
- Import still takes one shared rule or a whole rules file. Nothing in `export\` is read back by the
  tool, which means the directory is a backup format rather than an interchange format. (2026-11-02)

## 38. Cargo comment cleanup round notes

Released in **0.44.1**. No behaviour change; one comment in `Cargo.toml` was doing the wrong job.

The comment announced `rmcp` as "the one dependency milestone 9 will add", a promise written before
the milestone existed. Milestone 9 shipped hand-written JSON-RPC instead, and `src/mcp.rs` records
the reasoning — four method names are not worth a tokio runtime and an axum dependency. A new
reader of the manifest, though, would have expected a crate that would never arrive. The comment
now states the decision and points at the file that explains it, which is the only place a rejected
dependency should be argued.

Open after the round:

- Nothing was opened. The rest of §3.7 (`winfw-core`, `quick-xml`, the `mcp-template` structure) is
  untouched and unchanged in rank. (2026-11-02)

## 39. Startup diff names rules round notes

Released in **0.45.0**. The startup banner names rules now, not only counts.

The decisions the round made:

- **Names come from the store, not from a second file.** The filters the previous run left behind
  carry the rule's label in their *description* — the display name is the tool's own name on every
  filter we add — so the rebuild can compare what it is about to install against what it is
  removing without keeping any extra state on disk.
- **The comparison is per rule, not per filter.** One name counts once however many filters stood
  behind it; a wildcard rule that expanded to a dozen applications is one rule and is named once.
  A name is `changed` when the number of permits and blocks under it differs between the two sides,
  which is what catches a flipped action.
- **The base filters are not rules.** A deny policy's own filters are named `base#…`, are removed
  and reinstalled with every rebuild, and never appear in the diff.
- **Equal counts with a named change is news too.** `differs` now means the counts disagree *or* a
  name is in one of the three lists; the counts alone could not tell a restarted tool from a
  reconfigured one.

Open after the round:

- An edit that keeps a rule's name, its action and its filter count — a narrowed port or remote —
  leaves the same trace in the store as no edit at all, and the diff honestly does not claim it.
  Naming that would mean comparing the conditions of every filter, which is a deeper read of the
  store than this diff reaches. (2026-11-02)
- The lists are uncapped. A rule set of hundreds edited by hand could produce a banner of hundreds
  of names; a cap with a "…and N more" would only be worth it once somebody has one. (2026-11-02)

## 40. Monitor health over time round notes

Released in **0.46.0**. The event log stamps its newest event and both reports publish the stamp.

The decisions the round made:

- **The stamp is wall-clock, not monotonic.** The age is shown in a browser and read next to a
  wrist; no comparison across a clock change is asked of it, so milliseconds since the epoch in a
  plain atomic is enough and a `SystemTime` behind the log's mutex would have been the same answer
  with more lock held.
- **Zero means never, not midnight.** A log that took no event has no stamp, and the page says
  `no event yet` rather than an age measured from the epoch.
- **The stamp is kept on the log, not on the subscription status.** The status answers what
  subscribing did; the log knows what arrived. Keeping them apart means a refused subscription and
  a stale feed are two honest answers instead of one confused string.

Open after the round:

- The page shows the age as of the last state read; it does not tick on its own. A row that counts
  seconds up while you watch it is a nicer interaction and needs a timer the page does not have.
  (2026-11-02)

## 41. Rule reorder round notes

Released in **0.47.0**. The rules table grew an order column; up and down send
`POST /api/rules/move`, which rewrites the file and rebuilds the store.

The decisions the round made:

- **A move is a remove plus an insert, not a swap.** `{"index":1,"to":0}` says where the rule sits
  and where it should end up, which is what a person dragging a row means; a swap would answer a
  different question and the buttons would have to explain it.
- **A place outside the list is refused the way every other bad index is refused**: as an error the
  route reports, not as a clamp. A typo in a request must not shuffle the set by accident.
- **The rebuild is not optional.** Order only reaches WFP through the creation order inside one
  transaction, so the route takes the same `StoreWork::Apply` path a replacement takes instead of
  editing the file and hoping.
- **Both bounds are checked before anything is written**, so a refused move leaves the file and the
  in-memory list exactly as they were.

Open after the round:

- Two people with the page open can still overwrite each other (no generation counter yet, see
  §3.6); the move is as exposed as every other write in that respect. (2026-11-02)

## 42. Generation counter round notes

Released in **0.48.0**. State answers carry `generation`; whole-list writes may name theirs and a
stale name is refused `409` with the current state in the body.

The decisions the round made:

- **The counter counts writes of this run, not versions of the file.** A restart hands every client
  a fresh state anyway, so a per-run atomic answers the question without surviving anything.
- **Naming a generation is optional.** A client that does not know the counter gets the old
  unconditional behaviour, which kept every existing route test honest without editing it.
- **The counter belongs to the request, not to `rules.toml`.** `RuleFile` rejects unknown fields
  because the file has no generation to carry, so the whole-list body got its own type and the file
  format is byte for byte what it was.
- **The bump lives in `note_rules_written`,** the one place every rules write already calls, so a
  route cannot forget to move the counter the way a caller can forget to call a setter.
- **A conflict answers with the whole state,** not with an error string. The page applies it and the
  human sees what they were about to overwrite; asking the store for the inventory on the way made
  that free, because the answer was going to be built anyway.

Open after the round:

- `POST /api/detected` and `POST /api/rules/import` append to the server's own list and cannot
  contradict a client's copy, so they take no generation today. If a client ever edits a detected
  entry rather than accepting it, that route will want the same field. (2026-11-02)

## 43. Relaunch elevated round notes

Released in **0.49.0**. `POST /api/relaunch` asks the shell for an elevated start of this
executable and stops this process when the shell grants it. The degraded-store banner carries a
`Relaunch elevated` button while the process is not elevated, and the tray menu offers the entry
only while it is worth offering.

The decisions the round made:

- **The verb is the elevation.** `ShellExecuteW` with `runas` is what shows the UAC dialog. A
  refused dialog answers `ERROR_CANCELLED`, which the shell reports as status 5, and that is an
  ordinary refusal: the process stays exactly where it was and the page says so.
- **The stop is the flag shutdown already uses.** The accept loop ends after the answer is
  written, so the client that caused the relaunch reads its `200` before the port goes quiet.
- **The check is the token, not the store.** `TokenElevation` on the process token answers the
  question the route answers. A store that merely failed to open does not claim to know whether a
  relaunch would help, so the state now reports `elevated` next to the store report.
- **The elevated copy is a second `--serve` of the same executable.** It takes the instance lock
  after this process releases it and opens its own tab through its own tray, which is why the
  answer has the shape `POST /api/shutdown` gives.

Open after the round:

- The relaunch carries `--serve` and nothing else. A user who started the tool through a shortcut
  with arguments loses them; no such argument exists today.
- The first instance owns the port until it exits, so a relaunch while an older process is wedged
  leaves the new one to the port walk of eight. (2026-11-02)

## 44. Device re-resolution round notes

The item asked for `WM_DEVICECHANGE` in the tray. What the code does instead is re-ask on a lookup
miss, throttled, which turned out to be the smaller change and needs no window at all:

- The tray window is a message-only window (`HWND_MESSAGE`), and those do not receive broadcasts,
  so `WM_DEVICECHANGE` would have needed `RegisterDeviceNotificationW` and a handle to unregister
  again. The miss-driven re-ask covers the same case from the side that actually cares about the
  answer.
- The pause is one second, and only a path that could name a drive (`X:` as its first two
  characters) is allowed to cause a re-ask, so `*` and the host patterns do not burn a query every
  second. The tests count the queries to prove both halves.
- `OnceLock` became `RwLock<Option<Arc<[Mapping]>>>`, because a lock that can only be filled once
  cannot be re-filled. The read lock is dropped before the write lock is taken, so no lock is held
  across `QueryDosDeviceW`.
- Filters already installed from an untranslated path are not corrected by the re-ask, which is
  written down in section 3 as its own item rather than left inside this note.
- The cache is shared process-wide state, so every test in the module now declares the state it
  starts from. Tests that ran in a harmless order before can leave an empty cache behind for the
  next one.
- A first draft had a function named `allow_requery` that only read and updated the timestamp and
  never asked, so a miss translated nothing and the test that looked most likely to pass was the one
  that caught it. (2026-11-02)

## 45. Protocol by number round notes

- The enum grew a third case rather than becoming a newtype, so `tcp` and `udp` stay spelled the way
  every existing `rules.toml` spells them and only the new shape is a number.
- `deserialize_any` is what lets one field answer to a name and to a number. The price is that the
  visitor has to spell out every shape it accepts, and that `visit_i64` is not forwarded to
  `visit_u64` by serde: TOML hands integers over signed, so a visitor without it refuses every
  number in the file while accepting every number in JSON. Found by the round-trip test, not by the
  JSON one.
- Zero is refused rather than mapped to "every transport", because the field already has a way to
  say that, which is to be absent. Accepting `0` would mean two spellings for one idea and a
  question about which one wins.
- The page column became a text field. `select_choices` silently shows the first option when the
  current value is not in its list, so a stored `47` would have been displayed as "any" and
  rewritten to nothing on the next edit of an unrelated field.
- What is deliberately **not** here: names for the other transports. `protocol = "esp"` is still
  refused, and the honest position is that a name list is only worth having complete, which is its
  own item in section 4. (2026-11-02)

## 46. The rule that has no applications round notes

This release changes no code. It closes an item that was written down as a missing check and turned
out to be impossible here, which is worth recording because the two readings lead to different work:

- The reference's rule holds a **set** of applications, so "empty set" is a state a file can be in,
  and it disables such a rule on load rather than trusting it. Our rule holds exactly one
  `pattern`, and the field has no serde default, so a file without it fails to load at all.
- An empty string is a different case, and it was checked rather than assumed: `AppId::resolve("")`
  falls back to a blob of the pattern's own wide text, which for the empty string is a blob of
  size nought. That blob cannot equal the application id WFP reports for a real connection, so the
  filter matches nothing and the rule is inert. The reference would have greyed it out; we install
  something that never fires. Same outcome, one fewer concept. This was read out of the code rather
  than observed in a live store, which is what an elevated run is for.
- Note what this does **not** claim: that a pattern is validated when the file is read. It is not,
  and that is a decision written down in the data chapter, so a rule file an older binary wrote can
  always hold a value the current page would refuse. (2026-11-02)

## 47. Documentation drift and the last untested files round notes

This release changes no behaviour. It closes the distance between what the documentation claims and
what the code does, and it takes the two files that had no tests at all into the suite:

- Chapter 8 said every tray entry is a request the page sends. `Pause learning` is not: it calls
  `Live::toggle_learning()` in-process, and the guard — which sits on the socket — never sees it.
  Not a hole, since the flag is the same one the settings route writes, but the sentence had to go.
- The Layout in the development chapter did not list `src/elevated.rs`, the file 0.49.0 added.
- `src/main.rs` had no tests, although argument parsing decides what the process does to the live
  store. Two tests now cover it: the one flag names the command, and an argument that is not one
  known flag is refused rather than shrugged at — which is exactly what the parser's comment
  promises and nothing had checked.
- `app_ids` in the WFP layer had no tests for its cap on wildcard expansion, the thing that keeps
  one `C:\test\*.exe` rule from installing thousands of filters in a store the whole machine
  shares. Three tests now cover expansion up to the cap, the exact pattern that never looks at the
  applications it has seen, and the wildcard that must install its pattern before the monitor has
  seen anything — the last one matters because an empty expansion would install no filter at all
  and leave a rule the store cannot explain. (2026-11-02)

## 48. The elevated relaunch decision round notes

Release 0.54.0 changed no behaviour. It made the one decision in `src/elevated.rs` testable and
tested it, which is the whole file now except the FFI calls themselves.

- `ShellExecuteW` reports a start and a refusal the same way: a number. Only `status > 32` means
  granted, so the comparison decides whether this process stops itself — stopping on a refused
  dialog would leave the firewall with no tool and no server. It was welded inside the call; it is
  `granted()` now, with tests at null, `ERROR_CANCELLED` (5), 32 and 33.
- The boundary is worth spelling out: 32 is the last value the shell can report as an error, so
  the test asserts refusal at 32 and grant at 33, not "small versus large".
- `wide()` keeps a test for the terminator, because the arguments cross the FFI boundary as
  nul-terminated wide strings and a missing terminator is read as part of the argument by the
  shell, not as a crash here.
- What remains untested on purpose: `is_elevated()` and the relaunch itself. Both are the process
  asking the operating system about itself; an assertion on the value would assert the environment
  rather than the code, and asking for a real UAC dialog inside a test would leave an elevated
  process behind. The suite runs elevated and unelevated instead, and the relaunch route answers
  "already elevated" from the same function on an elevated runner, which is covered in the routes.
  (2026-11-02)

## 49. The Detected list follows the profile round notes

Release 0.55.0 scoped the Detected list per profile (§3.4), which the backlog had called the one
finding a profile manager does not settle.

- The lists are keyed by profile name inside the one `learn.json`, and the live name is held by
  the detector itself, so a monitor callback knows where an event belongs without asking the
  server. Profile switches, renames and deletes each carry the list along; deleting a profile
  takes its list with it, because entries waiting about rules nobody can select again are noise.
- The seen pool deliberately did **not** follow the profile. It is the set a wildcard rule is
  expanded against, an application an inactive profile saw is still an application that exists,
  and per-profile pools would make a wildcard narrower for reasons the page cannot show. The
  finding that led here confused the two lists; both now say which they are in their comments.
- Migration is by absence: a file with no `profiles` key moves its `entry` list to the default
  profile, and a file written since then carries no `entry` at all. A named profile that has never
  collected anything has no key either, so "absent" means empty and never means the default's.
- A page needs no change to show this: the state already carries the live list, and the switch
  already reloads the state. The route test asserts the entry vanishes and returns through
  `/api/state`, which is the only place the list travels.
- The Detected export needed no change and was checked rather than assumed: it copies the
  `learn.json` file, so a manual backup now carries every profile's list in one file. (2026-11-02)

## 50. The span of addresses round notes

Release 0.56.0 closed the last gap in the remote-address dimension (§4.2): `remote` now takes
`10.0.0.1-10.0.0.9` besides an address and a prefix.

- The text is told apart by the `-`, which no address text contains, so a rule file written before
  this release reads exactly as it did and no version number had to move. The field became an enum
  of a network and a span rather than a `Cidr` with an extra field, because the two shapes have
  nothing in common: one is an address and a prefix, the other two addresses and no prefix.
- The reference was read before the condition was written (`helper.c:1278`, `helper.c:1301`), and
  it settles two questions the crate cannot answer. A v4 bound is the address byteswapped, which is
  the number `u32::from_be_bytes` of the octets gives — the same convention the address-and-mask
  condition already uses here, so a span and a prefix name the same bytes. A v6 bound is not a
  number at all: it is a `FWP_BYTE_ARRAY16_TYPE` value pointing at the sixteen octets, which means
  a v6 span nests a pointer inside the pointer WFP keeps to the range. Both bounds and the range
  are held beside each other for the whole install, which is the same trap §8 and §9 recorded.
- Both families were installed against the live store, elevated: `192.168.1.10-192.168.1.20` and
  `2001:db8::1-2001:db8::ff`. That proves the store accepts the shapes; it does not prove the
  comparison order WFP applies to them, which no test here can observe without generating traffic
  through a filter. A live allow/deny check against a real connection is the honest follow-up.
- A span that ends before it starts is refused where the text is read, along with a span across the
  two families and an end that is not an address. The reference validates its address text the same
  way — with a balloon tip — rather than installing a filter that can never match.
- What a span does **not** buy: a multi-valued list (§4.2). A rule still holds one destination, so
  two spans that are not contiguous still need two rules. (2026-11-02)

## 51. The state of the remaining dimension list

The address dimension was closed by 0.56.0, which is worth recording here because the list in §4.2
is easy to read as "still wide open" and is not. What a rule can name today: one protocol (by name
or number), one direction, one port or port range, and one remote destination as an address, a
network or a span. What it still cannot:

- **A local address.** The reference carries one, and WFP has the field
  (`FWPM_CONDITION_IP_LOCAL_ADDRESS`), which is the shape a rule about a network interface would
  want. The three text shapes are already written, so this is one field, one condition and one
  page column.
- **A list of any of them.** A rule holds exactly one value per dimension, so TCP *and* UDP leaves
  the field out and two distant ports need two rules.
- **A name.** `remote` refuses `example.com` and nothing resolves one, so a rule learned from an
  event carries an address while the rule a person would write carries a name. The reference does
  not resolve names in a filter either; it names applications, not destinations.

Two of these are WFP work with the text format already settled; the third is a layer of its own,
as §9 said. None of them was started, and no decision here is hard to reverse. (2026-11-02)

## 52. Reading a profile of the C original round notes

Release 0.57.0 added `src/simplewall.rs` and the `--import <file>` flag, which closes the last item
of §3.7 that named a dependency the plan listed but the build did not use.

- Reading was done against the reference reader (`simplewall/src/db.c:283-420`) rather than against a
  remembered format, and that corrected two guesses before they became code. The sections that hold
  rules are `rules_custom` and `rules_system`; there is no section called `rules_user`, which is the
  name the profile *statistics* use for a count (`profile.c:869`) and nothing to do with the XML.
  `rules_config` is skipped on purpose: it is the enabled table of the built-in rules (`db.c:484-510`),
  not a rule.
- The attribute names are `name`, `apps`, `rule`, `rule_local`, `comment`, `dir`, `protocol`,
  `is_block`, `is_enabled`, `is_services`, `is_kernel`, `os_version` and `version` (`db.c:309-341`).
  `dir` and `protocol` are numbers, not words, and absent means outbound and any protocol, which is
  how the reference reads them (`_r_xml_getattribute_long` on a missing attribute yields 0).
- `version` is the address family and had no place in our model, so it is named in the comment of the
  rule it came from. This was found by comparing the attribute list of `_app_db_parse_rule` against
  our own field list rather than by testing, which is the kind of thing §4 exists for.
- One item that names several applications becomes one rule each, because our rule holds one pattern.
  Everything else the shape cannot carry is named in the comment, or in a note when no rule came from
  the item at all. Nothing is dropped in silence; that was the design rule, and it is what makes a
  hand-written profile safe to feed in.
- The reader is `quick-xml` with default features off, so no encoding detection is compiled in: the
  files simplewall writes are UTF-8 and the crate's own default decoder handles them. It also means
  the crate's lenient behaviour is what we ship — an unclosed tag is *not* an error, which surprised
  the first version of the failure test and is now what that test asserts about.
- Not built: writing XML back out, an import button on the page, and a merge mode. `--import` replaces
  the rule file of the active profile and exits without touching the live store, so the person looks
  at the result on the page and applies it in their own time. (2026-11-02)

## 53. The token leaves the state body round notes

Release 0.58.0 closes §27's open end: `/api/state` is a read, a read is answered to anyone on
loopback, and a secret handed out by a route anyone may read is one `curl` away from any process of
the same user. That is exactly the agent that builds a tool and then opens its own gate.

- The tray now opens `http://127.0.0.1:8788/#token=…`. A fragment is never put on the wire, so the
  document request the server answers is plain `GET /`, and the secret appears in no request line,
  no log line and no response body. Verified live: the body of `GET /api/state` holds no field named
  `token` and none of its value, and a `POST /api/shutdown` without a token is answered 401.
- The page reads the fragment, keeps the token in one variable, and removes the fragment again with
  `history.replaceState`, so the address bar shows the page rather than the secret. No storage, no
  cookie: a reload loses the write right, and that is the accepted cost of holding nothing on disk.
- A tab without a token reads but does not write. Every control that sends a writing request is
  built disabled — the buttons the tables make included — and the header ends with *read only · open
  from the tray icon to make changes*, so the situation is said before the first click rather than
  answered with a 401 after it. The header switches are spans, which have no disabled state, so they
  carry `aria-disabled` and a rule that takes away their pointer events.
- **The cost, stated plainly:** a script can no longer write at all. `curl` reads the state, cannot
  learn the token from it, and therefore cannot call `/api/shutdown` either; stopping the tool from a
  script that is not the tray means knowing the token out of band. Measured during this round with
  the test server up: `curl -X POST /api/shutdown` answered 401 and the process stayed up.
- Found on the way, and worth more than the change itself: **the page's script has not parsed since
  `bbec5ea` ("Stamp the feed with when it last spoke", the release after 0.45.0).** That commit turned
  a ternary into an `if` chain and left the original `const text =` line standing above the new
  `var text = "";`, which is not JavaScript. Because the tests never load the page and the Rust side
  answered correctly, nothing noticed: the static HTML rendered, so the page *looked* alive while no
  script ran. `node --check` on the extracted script is now part of how this is verified, and a test
  in `src/server/mod.rs` asserts the page reads the fragment and no longer reads `state.token`.
- Not done, and deliberately: a token in a query parameter would also have worked and would survive a
  reload, but it arrives on the wire, so the log of anything between the browser and us would carry
  it. The debug switch that shows the raw request line is still the only place a fragment-less
  request can be seen, and it is off by default.
- One thing this round did **not** settle, and it should be said: the page is only checked by
  `node --check` on the script extracted from it, which is a habit rather than a test. A broken page
  sat unnoticed for twelve releases because the Rust side kept answering correctly and the static HTML
  kept rendering. The route tests prove the server; nothing proves the page beyond the fact that it
  parses. (2026-11-02)

## 54. The second start ends quietly round notes

Followed by §55: the v0.59.0 tag shipped a test that did not compile; 0.59.1 is the fix.

Release 0.59.0 closes the open half of §2 point 1. A second `--serve` used to open the browser on
the running instance and exit with status `0`. Since there is no window to restore and nobody
reloads the page, that browser was a new tab on every mistyped double-click, and a process that
exits before the tray exists has no business opening a page at all.

- A loser of the instance name now logs one `WARN` line naming the running URL and ends with a
  non-zero status. No browser, no window, no token exchange. The exit is silent in the sense that
  a release build has no console, so the log file is where the line goes.
- The elevated relaunch is the one start that begins while the old instance still holds the name:
  `post_relaunch` asks the shell for the elevated start first and stops this process only after the
  shell said yes, so the newcomer can lose a race it should not lose. It is therefore started with
  the new `--takeover` flag, which polls the name for up to five seconds before it counts as a
  second start. The newcomer builds its own token and its own tray; no token crosses between the
  two processes. Verified by reading the path end to end, and by a test that claims a name of its
  own, releases it from a second thread, and asserts both halves: a name released during the
  patience is claimed, a name held past it is not.
- `server.port` is now written but read by nobody. It stays, because it is a cheap record of which
  port the running instance got and the second start still names it in its log line. Removing it is
  not worth a release of its own.
- The reference's *window restore* (§4.5) is closed as not applicable rather than left open: with a
  browser page as the UI there is no window of ours to bring forward.
- Still open, and unchanged by this round: the guard proves a writing request came from a tab the
  tray opened, but a process of the same user can inspect the browser process or its command line
  and read the fragment there. (§53 says the same about `curl`.) (2026-11-02)

## 55. The v0.59.0 tag shipped a test that did not compile

An editing slip in `src/instance.rs`: the line that built the test's mutex name was deleted while
the marker code around it was being rearranged, so the test target did not compile on the v0.59.0
tag and CI could not run. The shipped binary was not affected, because the broken part sat behind
`cfg(test)`.

- The dead marker is gone. The `Local\winfw-mcp.serve.takeover` name it created was never read by
  anything, which is what made it dead weight rather than unfinished work.
- 0.59.1 is the fix. It is a patch release of its own rather than an amended tag, because the
  handbook says a fix to a released milestone is a patch release, and because the tag was already
  pushed and released.
- Lesson for the process: a batch of parallel git calls in the same turn can interleave with an
  `edit_file` on the same repository. The `index.lock` complaint was the visible symptom; the
  invisible one was that the commit ran before the fix to the test. (2026-11-02)

## 56. The cap on wildcard expansion is not silent any more

Closing the half of §4.4 that was still open. The cap of 32 stays exactly where it was; what
changed is that a pattern over it says so in three places.

- `app_ids` returns the applications it hands out together with the number of matches it counted
  before the cap, and `Engine::add_rule` warns with the rule name, the pattern, the matches and the
  number installed. The count is taken before `take`, which is the part that is easy to get wrong:
  counting inside the filter would stop at the cap and report 32 matches for a pattern with 57.
- `/api/state` gained `pattern_truncations`, one entry per rule over the cap with `name`, `pattern`,
  `matches` and `installed`. Rules within the cap are absent rather than listed with `false`, so the
  array is empty in the normal case. The numbers come from the same seen list the worker expands
  against, and `pattern_reach` counts without resolving anything through WFP.
- The page shows *pattern has 42 matches, only 32 installed* under the pattern box of the affected
  rule, which is where somebody editing the pattern is looking.
- Measured live, elevated: a rule for `C:\Program Files\*` against 42 seen applications logged
  `matches=42 installed=32` and reported the same in the state.
- Two tests, 236 green, and the clippy count is back to the four groups it was, one of which the
  first draft of this change added and then removed by using `clamp`. (2026-11-02)

## 57. Default deny became the default (2026-11-02)

Point 4 of the five corrections. The order was the one the brief asked for: measure live first, flip
afterwards.

- Live, elevated, with `default_policy = "deny"`:
  - **(a)** the page and `/api/health` stayed reachable, so a deny does not lock the UI out.
  - **(b)** `C:/Windows/System32/curl.exe` with no rule was blocked, and a fresh entry appeared at the
    top of the Detected list with `allowed = false` and `kind = "blocked"`; the connection table
    attributed it to `base#block`.
  - **(d)** an ALLOW rule for that application plus a rebuild let it connect again.
  - **(e)** taking our filters out of the store restored connectivity, so the not-a-firewall switch
    works under deny too.
  - **(c) inbound was not verifiable on this host.** The base permit keys on
    `FWP_CONDITION_FLAG_IS_LOOPBACK`, and a connection to the machine's own LAN address is flagged
    loopback by WFP here, so a local client cannot tell "accepted on the LAN" apart from "accepted
    because loopback". The evidence for the inbound side is the code plus the unit test that asserts a
    `base#block` filter on each of the four authorization layers.
- **The earlier "DNS does not resolve under deny" was the client, not the resolver.** With
  `svchost.exe` allowed, a client that has a rule resolved a name and connected while a second client
  without a rule was blocked in the same deny window. Nothing to fix; the security chapter now states
  that a blocked client reports a timeout rather than a refusal.
- `Settings::default()` is `Deny`, a `default_policy` stored in `config.toml` still wins, and the page
  states the policy in the header in plain text for both values. An empty rules list under deny says so
  in the rules table, because an empty table under deny looks like a dead internet rather than like a
  decision.
- A live incident worth writing down: a deny window ran while the user was at the machine, and nothing
  outside the base permits worked until a rule existed. That is the feature, but it is the first time a
  person met it, which is why the header line and the empty-list hint belong to this release rather
  than to a later one.
- Found on the way and entered as **B5**: the rules file is read before the tracing subscriber exists,
  so the "read the backup instead" warning of a file that does not parse is lost, and the page then
  shows rules that are not the ones in the file on disk. Found by a hand-edited file whose Windows path
  was written with a single backslash, which TOML reads as an escape.
- Two tests (the default value, the policy line on the page), 238 green, `cargo fmt --check` clean,
  clippy still at its four warning groups. Docs: the config table, the rules chapter, the WFP chapter,
  and a new section in the security model naming what default deny leaves open. (2026-11-02)

## 58. One application, whatever the spelling (2026-11-02)

Point 5 of the five corrections. The identity of a Detected entry, the dismiss, and the seen pool
all compared application paths byte for byte, which on Windows means a second entry for nothing: the
firewall reports a device path in lower case, a person types what the shell shows them, and PLAN.md
section 4 already promised case-insensitive wildcards.

- The comparison ignores case in three places (`same_app`): finding an existing entry in `observe`,
  finding the path in the seen pool (`note_app`), and the retain in `dismiss`. Rule matching was
  already case-insensitive, because `wildcard_match` lowercases both sides.
- **The path handed to WFP was not lowercased, and measured live it does not need to be.** A rule
  written `C:\WINDOWS\system32\CURL.EXE` allowed the program the firewall reports as
  `C:\Windows\System32\curl.exe` (HTTP 200 under a deny policy), so `FwpmGetAppIdFromFileName0`
  resolves a path without regard to case. That is the check the brief asked for before copying the
  reference's `wfp.c:2176`; the outcome is that the path stays exactly as it was typed.
- Migration is done on load rather than by rewriting the file: for every profile the entries that
  differ only in spelling are folded into one, hits are added, the newer timestamp and the newer
  `allowed` win, and the `app`/`display` are taken from the older entry so the screen keeps the
  spelling a person has already read. The seen list keeps the newest occurrence, because that is the
  list a wildcard expansion builds filters from.
- A live incident belongs here: the deny window for this measurement ran while the user was at the
  machine, and the rule of thumb going forward is that a live test that installs deny is followed
  immediately by taking the filters out again. That is not a code change, it is how the tool is
  driven during development, and it is written into the development chapter.
- Four tests, 242 green, `cargo fmt --check` clean, clippy unchanged at four warnings. Docs: the
  learning-mode chapter names the comparison, and the WFP chapter gained the section on the
  application condition with the measurement in it. (2026-11-02)

## 59. A click on the tray icon finally works (2026-11-02)

Reported by the user: the icon was visible in the notification area, its tooltip read only
"winfw-mcp", and neither the left nor the right mouse button did anything.

Cause. The icon is registered with a callback message, and the shell reports the event that
triggered it inside the `lparam` of that message: the event in the low word, the icon id in the
high word. The window procedure read only the high word, so it compared the icon id `1` against
`WM_LBUTTONUP` and never matched; every click fell into the `_ => {}` arm and was dropped without a
trace. A second issue sat behind the first: `Shell_NotifyIconW(NIM_SETVERSION, …)` was never called,
and the modern Windows 10/11 shell reports a click as `NIN_SELECT` and the right button as
`WM_CONTEXTMENU` only once the icon has declared a version, so those events were never delivered at
all.

Fix. The callback is resolved through a pure `icon_action(low, high)` helper that reads both words
and takes whichever names a real event, so a shell that reports the event in either word is
understood. `NIM_SETVERSION` is now sent with version 4 so the shell sends `NIN_SELECT`,
`NIN_KEYSELECT` and `WM_CONTEXTMENU`, and a double click opens the page the same way a single one
does. The tooltip now names the address as well as the tool, which answers "which instance is this"
without a click.

Honest about the limits. `NIN_SELECT`, `WM_CONTEXTMENU`, `WM_LBUTTONDBLCLK` and `NIM_SETVERSION` are
exported by the `windows` crate; `NOTIFY_VERSION` and `NIN_KEYSELECT` are not, so they are defined
locally. The click behaviour cannot be exercised by an automated test in this environment: there is
no way to deliver a real shell click from a script, so the helper is tested for its decision table
and the wiring is argued from the protocol and the user's report, not from a recorded click.

Ghost icon caveat. A forced `taskkill` never runs `Shell_NotifyIconW(NIM_DELETE)`, so the icon stays
behind after a killed process and answers nothing when clicked. That is cosmetic and clears on one
click, but it explains part of the "nothing happens" feeling during development and it is worth
remembering when a live test ends with `taskkill`.

## 60. The tests write into the data directory, and it is not always the tool's

Found while writing the `--clear` shutdown check into the handbook, which meant looking at what the
data directory actually contains after a development session: it had picked up a `*.tmp` file from a
test run. Cause. `testutil::scratch_dir()` returns a fresh temporary directory for the tests that
want isolation, and those do not touch the real data directory. But the live-store tests and the ones
that build a `Server` go through the same code as production, and the code resolves the data
directory from `APPDATA` only (`%APPDATA%\winfw-mcp`); there is no `WINFW_DATA` override today. A
test that writes config, rules or the Detected store therefore writes into the real
`%APPDATA%\winfw-mcp`, next to the running tool's own files. Two consequences, both small but
neither zero:

- a development run and a test run can read each other's files, which is why a rule added in the web
  during a manual test can appear in the next `cargo test` until something cleans it;
- the data directory of the tool is not a clean record of what the tool wrote, because a test added
  to it too.

Not a bug in the sense of wrong behaviour — the tests pass and the tool works — but it makes the
data directory a poor source of truth for "what did the tool do", and it is the reason a manual test
is followed by a look at `rules.toml` rather than the other way round.

The fix is small and belongs with the next test-touching release, not with a docs change: make
`resolve()` honour a `WINFW_DATA` override, then point the tests at a scratch directory of their own
by setting it in the tests that build a `Server` or open the store, and leave the real data directory
to the running tool. Until then the handbook notes the caveat where it describes the data directory,
and the `--clear` check is run against the store rather than the directory listing.

## 61. Started by hand: four things the first manual run asked for (2026-11-02)

The tool was started by hand from PowerShell and from Explorer, elevated. Four findings, in the order
the owner gave them. These are decisions, not open questions.

1. **No parameters should do nothing but say so.** A run without arguments currently applies the rules
   to the live store and exits, which the owner calls counter-productive: nothing on screen explains
   the choice, and the release binary has no console (`windows_subsystem = "windows"`), so a double
   click appears to do nothing at all. Wanted: without parameters, make no change to the store and
   print the parameters and a minimal start example (`winfw-mcp.exe --serve`). Whether a double click
   should simply mean `--serve` is a follow-up decision, not assumed here.
2. **An unelevated start should ask, not limp.** Reading and writing the WFP store needs elevation;
   today an unelevated start runs and logs `0x00000005` access-denied warnings. Wanted: on an
   unelevated start, ask whether to relaunch elevated with the same parameters, and say in one or two
   lines what is lost by staying unelevated (the store cannot be read or written, so rules are not
   installed and the page shows a store it cannot confirm).
3. **`Quit` should mean as if nothing had been done.** `Quit` today leaves the persistent filters in
   place (see §2 item 6, and the note behind B1 in §1). Wanted: a `Quit` that also deactivates the
   rules it installed, block and allow alike. The existing `shutdown` behaviour stays reachable, so a
   user who wants the protection to outlive the process keeps that option.
4. **No button in the web page did anything (biggest finding).** Import and Export at the top, `Quit`
   and `Add rule` at the bottom all failed to act. Two suspicions, neither proven yet:
   - the page was opened without a session token, because no tray was running to open `#token=` for
     it (that start path is exactly what findings 1 and 2 are about), and a page without a token may
     read but must not write since 0.58.0 (§53). If so, the refusal was correct but the page gave no
     usable hint, which is itself the bug;
   - the page's script is broken again. The same failure shipped for twelve releases until 0.58.0,
     where a stray `const text =` line above a `var text = ""` stopped the whole script from parsing,
     and no test loads the page. A dead script also explains top and bottom buttons failing at once.

   The cheapest first check is the browser console, then a request to see whether a write reaches the
   server at all.

Live note from the same session: the one-shot run at 17:46 left 17 filters in the live store while no
process was running, and `curl https://example.com` returned nothing (exit 7). A firewall whose rules
outlive the process needs a visible way back, which is finding 3.

## 62. Two findings the page redesign produced (2026-11-02)

The redesign brief asked for two observations to be reported rather than fixed. Both are now
explained; neither was changed by the redesign.

1. **A blocked program can be missing from the Detected list.** `/api/state` answers at most
   `STATE_DETECTED` entries, which is 20 (`src/server/mod.rs`, truncated in
   `src/server/routes.rs`). A new entry is inserted at the front, but an entry that is only refreshed
   keeps its place: `Detector::observe` updates `seen_ms`, `hits` and `allowed` and returns without
   moving the entry. A program that has been connecting since before the twenty entries newer than it
   arrived is therefore present in `learn.json` and invisible to the page, which is how Waterfox came
   to be blocked and undetected at the same time. The data is right and the answer is short. For the
   extension plan: answer the newest twenty by `seen_ms` rather than by insertion order — cheap, and
   it also makes the list mean *what needs a decision lately* — or answer the whole list and let the
   page paginate, which is honest but grows the body on a busy machine.
   *Closed in 0.65.0, which took the first of the two: see §64.*

2. **The empty rules table was a dead script, not missing data.** At the time of the report
   `/api/state` answered `rules=2` (the two example rules), and the page assigns `state.rules.rule`
   and calls `renderRules()` on every state update, so the rules reached the browser. "No button works
   and the table is empty" is the signature of a script that never ran, which is the failure §61 item
   4 describes and the same class of bug that shipped for twelve releases until 0.58.0. The redesign
   moves the table onto the Rules tab, so a person looking for it has to open that tab; the page opens
   on Detected when an entry is waiting and on Connections otherwise.

*Not verified, and worth knowing:* this session has no way to look at a rendered page. Edge's
`--dump-dom` writes nothing to stdout on Windows, the headless screenshot is written asynchronously so
the file only appears a moment after the process returns, and the model in this session cannot view
images. The four files in `docs/screenshots/` are therefore recorded as artifacts and the visual check
is the owner's. What was checked instead is structure: the page parses as HTML with no mismatched or
unclosed tag, every one of the 48 element ids the script asks for exists in the markup, the four tab
panels are reached through `data-tab`, and `state.token` is gone from the file.

The page is 64 KB where the brief asked for under 60 KB; the owner accepted the overage.

Found on the way and not changed: the comment above the theme test in `src/server/settings.rs` still
says `log_level` "waits for" a restart, while `state.set_log_level` and the `tracing_subscriber::reload`
handle in `src/main.rs` have applied a new level to the running process since the reload layer landed.

## 63. The icon in the notification area reports its state (2026-11-02)

The owner reported that the icon showed nothing on hover beyond `winfw-mcp`, that neither mouse button
did anything, and that a double click did nothing either. What the code and the log say:

1. **The left button did work.** `open_url` is called from two places only — the icon click and the
   menu's `Open` entry — and the log held two `asked the shell for the browser` lines, each a few
   seconds after an icon was added. `ShellExecuteW` answered 42, which is above 32 and therefore
   success. So the click reached the shell; what was missing was anything the user could see.
2. **Hover answered nothing because the tooltip was written once.** It was composed at `NIM_ADD` from
   the tool name and the address and never touched again, so it could not reflect a protection paused
   from the menu. It now names both flags and the address, and a `WM_TIMER` every two seconds keeps it
   current (`tooltip_text`, `set_tooltip`).
3. **The menu was the weak part.** It is tracked on a message-only window. The window is now made
   foreground before `TrackPopupMenu` and the shell's empty post-tracking message is posted after it,
   and the flags carry `TPM_LEFTALIGN | TPM_RIGHTBUTTON`; without those a tracked menu can be gone
   before it is read, which is indistinguishable from a right button that does nothing.
4. **The version constant was wrong but harmless.** It carried a packed `0x0604` where the shell
   documents `4` (`NOTIFYICON_VERSION_4`). Measured against a live shell, `NIM_SETVERSION` accepted
   both — no refusal in the log either way — so this is correctness, not the cause.
5. **The reporting gap is closed.** Every icon event is logged (`info` for the one that opens the
   page, `debug` with both words for the rest). The first run with it produced
   `NIN_BALLOONSHOW` and `NIN_BALLOONTIMEOUT`, which proves the start popup is shown and confirms the
   callback arrives at all. Before this, "clicking does nothing" could not be told apart from "the
   shell never told us".

Still open, and the reason the owner's report may not reproduce:

- **A `taskkill /F` leaves a ghost icon.** A killed process never reaches `NIM_DELETE`, so the shell
  can keep an icon that answers nothing while the live icon sits in the overflow flyout. The tool
  cannot clean that up after the fact; stopping it through `Quit` or `POST /api/shutdown` does.
- **The menu cannot be verified without a hand on the mouse.** Everything above is what the code now
  guarantees; whether the owner sees the menu on their shell is the next manual run.
- 244 tests, `cargo fmt --check` clean, clippy still at the four known warnings, release build
  starts, page loads, network left unblocked.

## 64. The Detected answer follows the newest activity (2026-11-02)

0.65.0 closes §62.1. `StateJson::new` (`src/server/routes.rs`) now sorts the snapshot by `seen_ms`
descending before it truncates to `STATE_DETECTED`, and answers `detected_total` next to
`detected`. The sort is stable, so entries sharing a timestamp keep the order they were collected in.

What the sort fixes is the case the report describes: `Detector::observe` refreshes an entry in place,
so a program that has been running for a week has its newest question at the end of the list on disk.
Cutting that list as it stands answered the twenty oldest questions and hid the one being asked now.

Nothing about the collection changed. `Detector` still keeps insertion order, still caps the file at
`DETECTED_CAP` entries, and `detected.list` over MCP still answers the whole snapshot, so the agent
sees 100 entries while the page sees the newest 20. The cap values are untouched.

Two things worth recording for the extension plan:

1. **The page could paginate.** `detected_total` is the number a `Load all` button needs. The API has
   no offset today, and the whole list is small enough that answering it would not be absurd — the
   reason it is cut at all is the size of the body on a busy machine, not a limit of the data.
2. **`/api/state` is polled every two seconds.** Sorting 100 entries on every poll costs nothing, but
   it is worth remembering that the state answer is the hot path of the page.

*Found on the way:* the 0.64.0 release had no row of its own in `CHANGELOG.md`. Its text had been
appended to the 0.64.1 row behind a stray `|`, so the table rendered a third column and the release
was not listed. The two rows are separate again; no wording changed.

*Verified:* 245 tests (`cargo test -- --test-threads=1`), `cargo fmt --all -- --check` clean, clippy
unchanged at the four known warnings, `cargo build --release` builds. The new test collects 21
entries, refreshes the one at the end of the list with a much later timestamp, and asserts that the
answer starts with it, carries 20 entries and reports `detected_total = 21`. Without the sort that
entry is the one cut.

## 65. The page and its markup are checked against each other (2026-11-02)

Closing the half of §62.2 that could be closed without a JavaScript parser.

`every_element_the_page_script_asks_for_exists` (`src/server/mod.rs`) reads the embedded page and
collects the element ids its script asks for by name. Two places name an id: `el("…")` at the call
site, and the `WRITE_CONTROLS` array the script walks to enable or disable every write control. Both
are read, the names are deduplicated, and each has to appear in the markup as `id="…"`. The scan
yields 48 ids on the page as it stands.

The scan is deliberately not a parser. Two call sites pass a variable to `el()` instead of a literal,
and in both cases the variable holds one of the names the scan does collect, which is what makes the
set complete; that is written in the helper's comment rather than left to be rediscovered.

Verified by mutation, because a test that cannot fail is worth nothing here: renaming the
`detected-count` id in the markup makes the test fail with *the script asks for #detected-count, the
markup does not declare it*, which is exactly the mistake the test exists to catch.

What remains open is named in §6 item 9 and in the development chapter: a script that stops parsing is
still not noticed. The failure that shipped for twelve releases is of that kind, and the static HTML
renders whether or not the script runs, so the page looks alive. Closing it means a parser in the test
target alone, which the project has no reason to add yet.

*Verified:* 246 tests (`cargo test -- --test-threads=1`), `cargo fmt --all -- --check` clean, clippy
unchanged at the four known warnings.
