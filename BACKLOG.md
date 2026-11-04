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

Sections 1 to 6 are what is open. Everything from section 7 on was a round note, and the round
notes moved to [JOURNAL.md](JOURNAL.md) unchanged in 0.69.1. They kept their section numbers, so a
reference to a section number here, in [CHANGELOG.md](CHANGELOG.md) or in the handbook points at
that file, and the one section at the end of this file keeps the number it had.


## 1. Likely bugs

These are not missing features; they are behaviour that differs from what the code says it does.

| # | Finding | Evidence |
|---|---|---|
| B1 | **`Quit` in the tray did not stop the process.** `Quit` posted `PostQuitMessage`, which ends the *tray thread's* message loop only, while the accept loop in `Server::serve()` checked no flag: the icon disappeared and the server kept serving. **Fixed in 0.11.0** — `AppState::running` is now the flag the accept loop waits on, and both `Quit` and `POST /api/shutdown` clear it. | [verified] fixed; `src/server.rs` (`AppState::running`, `request_stop`), `src/tray.rs` (`SERVER_RUNNING`) |
| B2 | **`learn_mode` is inert.** The setting is read, stored and reported, but the monitor collects unconditionally, so `learn_mode = false` still fills the Detected list. **Fixed in 0.11.2** — the monitor now takes the setting and only offers events to the detector while learning is on; the connection log still fills either way. Verified with an elevated run: off → 21 events and an empty Detected list, on → the same traffic produces Detected entries. | fixed; `src/monitor.rs` (`Sink::learning`, gate in `on_event`), `src/main.rs` (`serve`) |
| B3 | **A port conflict terminates the app.** `Server::bind` returned an error and `--serve` propagated it, while PLAN.md §9 asked for a fallback so a conflict does not kill the tray app. **Fixed in 0.11.3** — `Server::bind` now walks forward to the next free port of eight, warns in the log, and the tray opens the port it actually got. | fixed; `src/server.rs` (`Server::bind`, `PORT_ATTEMPTS`) |
| B4 | **A wildcard rule silently missed applications until something wrote.** Expansion was rebuilt only when a write happened, from the applications the detector had seen; a one-shot run expanded against nothing. **Fixed in 0.11.4** — seen applications are recorded whatever `learn_mode` says, a newly seen application under an enabled pattern triggers a rebuild, the store is rebuilt from the rules at startup, and a one-shot `--apply` expands against the seen list on disk. | fixed; `src/learn.rs` (`seen`, `note_app`), `src/monitor.rs` (`on_event`), `src/main.rs` (`serve`, `sync_store`) |
| B5 | **A rules file that cannot be parsed is replaced by its backup without a trace in the log.** `RuleFile::load_or_create` warns about the fallback, but the rules were read before `init_tracing` installed the subscriber, so the warning was dropped and the page showed the backup's rules while the file on disk held something else. Found while testing 0.61.0 with a hand-edited `rules.toml` whose Windows path was written with a single backslash, which TOML reads as an escape. **Fixed in 0.67.0** — the subscriber is installed before the rule file is read; see §66. | fixed; `src/main.rs` (load order), `src/rules.rs` (`load_or_create`) |

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
- ~~**The expanded connection table promises a protocol it does not show.**~~ — **closed in 0.73.1**.
  Found while the account column was added in 0.72.0: `web/index.html` built the expanded row with the
  headings `target, local, protocol, time`, but the third cell held `event.kind + blame` — the verdict
  and the rule it blamed — so the `protocol` field of the event reached the browser unrendered. Neither
  of the two one-line answers was taken alone: the row has five columns now, protocol and verdict
  apart, and `protocolName` names `tcp` and `udp` and falls back to the number, because WFP reports a
  number and the other two protocols a machine sees are rare enough not to be worth a table.
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
  which is the graceful half of what the reference's migration does for us. A **checksum** over the
  body joined it in 0.70.0, so a file that parses but lost content is reported rather than believed.
  It is reported rather than refused, because a hand edit breaks it just as surely as a torn write
  does, and the `.bak` in §3.3 stays what covers the case where the content really is gone.
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

### 4.6 Services and the applications that host them

The reference knows a kind of application we do not have. Where we resolve a connection to a process
path, it asks the operating system for the process tag, and when that tag names a service the entry
becomes a service of its own (`DATA_APP_SERVICE`, `network.c:715`) carrying the service name. The
filter for such an entry does not match a path at all: it matches `FWPM_CONDITION_ALE_USER_ID`
against a security descriptor (`wfp.c:972`), which is the service's SID. Two rules in the UI then
apply a rule to the shared hosts as a convenience, `is_forservice` and `is_fordriver`, which add the
`svchost` and `ntoskrnl` entries to it (`wfp.c:1331`).

That is what a person means by a rule about a service, and it is the answer to the price the security
chapter names for default deny: one permit for `svchost.exe` and every service in that host may reach
the network, because DNS, DHCP and time sync are all the same path to us. We match on the path alone
(`src/wfp.rs`), so a rule cannot single one service out.

Two things make this more than a field to add. A service is a name, not a path, so a rule would carry
a different kind of subject and the Detected list would collect names rather than paths. And the
reference resolves a service to whichever process hosts it right now, which leaves the question what a
rule about a service that is not running should do — a question the reference answers by simply not
answering it. It is recorded here rather than started for that reason. (2026-11-03)

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
   name is reported. The user name landed in **0.72.0**: the event header names the account as a
   security identifier, `src/user.rs` resolves it through `LookupAccountSidW` behind a bounded cache,
   and the page, `/api/state` and `events.list` all carry it. What is left of this item is §4.3's last
   point (a class derived from filter weight) and the package SID, which no event of this tool has
   needed so far.
4. ~~**A settings write path** (§3.2)~~ — done in 0.13.0 for the two settings that matter at runtime.
   `POST /api/settings` and the MCP tool `settings.set` change `learn_mode` and `default_policy` on a
   running process, write `config.toml`, and rebuild the store. `theme` joined them in 0.32.0. What
   is left is small: `port` needs a restart because the listener is already bound. `log_level` takes
   effect at once now, so all four settings the route names are live in the same request.
5. **The four bugs in §1**, all small.
6. ~~**Storage hardening**~~ — done in 0.24.0 for the validation, the backup and the version field, and
   in **0.70.0** for the last piece: a checksum of the body in `rules.toml` (§4.4). Nothing of the
   reference's file format is missing now, and no part of it is planned either.
7. **Runtime finishing touches**: the single instance landed in 0.16.0, the icons in 0.17.0 and
   the tray menu (`Open`, `Pause learning`, `Quit`) in 0.21.0 and volatile filter mode
   (`volatile_filters`, taken out on a clean stop) in 0.22.0. Log rotation, which was the last
   open part of it, landed in 0.26.0. Nothing of the item is left.
8. ~~**The Detected list is short in the answer, not in the data** (§62.1)~~ — done in 0.65.0 and
   closed in 0.71.0. The answer is ordered by `seen_ms` before it is cut, and the cut is now the cap
   the list itself is kept to, so the answer carries every entry the data can hold and the page can
   act on all of them; pagination was considered in §64 and dropped for that reason.
   `detected_total` stays: the badge reads a count rather than the length of a list the server could
   one day truncate again.
9. ~~**No test loads the page** (§62.2)~~ — half done in 0.66.0. A test collects every element id the
   script asks for and asserts the markup declares it, which is the disagreement a change to either
   half produces; it was verified to fail when an id is renamed. What it could not do was notice a
   script that no longer parses, because that needs a JavaScript parser, and a page that does not parse
   still renders its static HTML. **Closed in 0.73.1 without a parser**: a test in `src/server/mod.rs`
   scans the one script block for brackets that do not match, skipping string
   literals, template literals and comments. It is not a parser and does not claim to be — a syntax
   error inside a balanced block still passes — but it catches the failure an edit actually produces,
   an unclosed block, and it asserts that against a broken snippet rather than trusting itself. A
   parser stays available if the page ever grows a build step. One limit is worth knowing before
   anyone trusts it further: the scanner knows no JavaScript, so it reads a regular expression
   literal as text. The page holds one such literal as of 0.74.0 and its parentheses balance, so the
   scan holds; a class like `/[)}]/` would need the scanner to know about regexes.

## 51. The state of the remaining dimension list

The address dimension was closed by 0.56.0, which is worth recording here because the list in §4.2
is easy to read as "still wide open" and is not. What a rule can name today: one protocol (by name
or number), one direction, one port, a port range or a list of them (0.74.0), one remote destination
as an address, a network or a span, and one local address (0.73.0). What it still cannot:

- ~~**A local address.**~~ — done in **0.73.0**. The reference carries one, WFP has the field
  (`FWPM_CONDITION_IP_LOCAL_ADDRESS`), and the three text shapes were already written, so it landed
  as one field reusing `Remote`, one condition and one page column. What it deliberately did not
  bring: `reaches()` still reads only `remote` (the local end is not a destination), and a rule that
  names two families — a v4 remote with a v6 local — yields no layers and installs nothing rather
  than being refused as a contradiction. The name of the type behind the field is still `Remote`,
  which reads oddly on the local end; renaming it would ripple through the share strings, so it
  waited.
- ~~**A list of any of them.**~~ — **partly done in 0.74.0**, for ports alone. The port field takes
  a comma-separated list of single ports and ranges and installs one filter per element, bounded to
  32 elements because each element costs a filter. Protocol lists were rejected on purpose:
  `FWP_UINT8_ARRAY` is ambiguous with a byte array in WFP, and *TCP and UDP* is already expressible
  by leaving the field out. `remote`, `local` and a program pattern still hold one value each.
- **A name.** `remote` refuses `example.com` and nothing resolves one, so a rule learned from an
  event carries an address while the rule a person would write carries a name. The reference
  does not resolve names in a filter either; it names applications, not destinations.
- **A service.** A rule names a path, and every service hosted by `svchost.exe` shares one path, so
  a rule cannot single one service out. The security chapter names the price of that under default
  deny, and §4.6 records what the reference does differently.

The port half of the list dimension is closed; the remote list, the local list and the application
pattern are WFP work with the text format already settled, the name is a layer of its own, as §9
said, and the service is a match dimension nobody has designed yet. No decision here is hard to
reverse. (2026-11-02, ports closed 2026-11-04)
