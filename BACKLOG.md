# Backlog

**Open points only.** What a round closed is written down in [JOURNAL.md](JOURNAL.md) and in
[CHANGELOG.md](CHANGELOG.md); nothing finished is kept here. The section numbers of the two audits
that produced most of these findings (`v0.10.0`) are named with each item, and their closed halves
are in the journal under "Closed findings carried over from the backlog".

No open point is scheduled. The list exists so that an extension plan can be drawn from it later
without re-discovering the same gap twice.

## 1. Bugs

None open. The five the audits found (§1) are all fixed; the journal names the releases.

## 2. Open findings from the stage audit

### 2.1 WFP

- **No fallback net-event subscription** (§3.5). Only `FwpmNetEventSubscribe4` is used; PLAN.md §5
  expected the older revisions to be loaded for older builds.
- **The engine handle is opened once** for the life of the process (§3.5). The retry added in 0.35.0
  covers a boot-time miss; a Base Filtering Engine restarted mid-session is not re-discovered until
  the next start.
- **A filter installed from an untranslated drive path is not corrected by the re-ask** (§3.5). The
  translation happens when a filter is built, so a rule for a drive that did not exist at that moment
  went into the store with `d:\...` as its literal text. The next write to the rule list fixes it;
  nothing notices on its own.
- **UWP package display names are absent** (§3.5). PLAN.md §5 allowed dropping them in v1, so this is
  an accepted deferral rather than an oversight.

### 2.2 Settings and errors

- **`port` stays file-only** (§3.2). Deliberate: the listener is already bound, and a server that
  moves its own port while a browser tab holds the old one is worse than a restart. Worth revisiting
  only together with a port file the tray could re-read.
- **`500` or `400` for content the server cannot make sense of** (§3.2). A rules text the restore
  reader rejects (`RuleFile::from_text`) and a pattern that fails `validate_pattern` still answer
  `500`. Whether "the file content makes no sense" belongs to the client or the server is undecided.

### 2.3 Rules and the API

- **Every rule edit writes the whole list** (§3.6). There is no single-rule route, so an edit that
  touches one field still replaces all rules and depends on the generation counter to notice that a
  second tab was faster.
- **The generation check covers only whole-list writes** (§3.6). Routes that take an index
  (`/api/rules/share`, `POST /api/detected`, `/api/rules/move`) cannot tell a stale client from a
  fresh one.
- **An agent cannot stop the tool** (§3.6). `shutdown` left the tool list when MCP became read-only,
  which is the intended reading of "read only", but a client written against the old list will look
  for a method that is no longer there.

### 2.4 Files, import and export

- **No import button on the page** (§3.7). `--import <file>` is the only way in, and the XML is read
  but never written, so this tool cannot hand a file back to the program it reads.

### 2.5 Architecture

- **No `winfw-core` library crate** (§3.7). Everything is one binary; the rule that only `wfp.rs`
  calls the `Fwpm*` API is honoured, the crate split is not.
- **The `mcp-template` structure was not carried over** (§3.7): no contract document, no per-tool
  smoke tests, no skill file, no `tests/` directory.
- **`edition = "2024"` waits for 2027** (§3.7). Rust releases an edition every three years, so 2027
  does not exist for `rustc` 1.99 yet. Migrate deliberately when it lands; an edition changes
  language semantics and is not a cosmetic version bump.

## 3. Open findings from the reference comparison

### 3.1 WFP features the reference has

- **Stealth-mode filters** against port scanners (§4.1).
- **Boot-time filters** with `FWPM_FILTER_FLAG_BOOTTIME`, enforced before the BFE service starts (§4.1).
- **Optionally turning Windows Firewall off** through `INetFwPolicy2`, as a user choice and not as the
  mechanism (§4.1).
- **The weight ladder** (§4.1). The reference has seven levels, we have four, and our numeric values
  collide with its, so on a machine where both have installed filters the relative order is arbitrary.
  Measured alongside this: WFP rejects a `FWP_UINT8` weight of `0` **and** of `0x10` with
  `FWP_E_INVALID_WEIGHT`, so the usable window ends at `0x0F`.
- **Security descriptors** (§4.5). The reference sets explicit DACLs on the engine, provider, sublayer,
  callout and filter it creates; we set none, so nothing marks those objects as ours in a way another
  non-elevated process has to respect.
- **Session and transaction** (§4.5). The reference opens the engine with its own session key and a
  nine-second transaction wait; we open with a null session, which works but cannot scope volatile
  filters.
- **Engine options** (§4.5). The reference sets `FWPM_ENGINE_COLLECT_NET_EVENTS` and
  `FWPM_ENGINE_PACKET_QUEUING` and restores the collect option on shutdown. We set no engine option on
  our own session, and PLAN.md §5 records that at least the collect option has to be set for a
  subscription to fire at all — worth re-checking which session ours ends up on.
- **Log discipline** (§4.5). The reference caps its log file size and quotes every CSV field. Ours
  rolls at a megabyte and holds tracing's formatting, not CSV.

### 3.2 Rule dimensions a rule cannot name

- **Protocol names beyond `tcp` and `udp`** (§4.2). The number works, but a rule about ESP reads
  better as a name. Only worth doing together with a table of names, not on its own.
- **Multi-valued remote, local and application patterns** (§4.2, §51). Ports took the list in 0.74.0;
  the other three hold one value each, so two distant ports of a program are two rules today. WFP
  work with the text format already settled.
- **Rule class or group** (§4.2), which also decides the weight, plus a separate overlay table so a
  stock rule can be toggled without editing it.
- **Application identity beyond a path** (§4.2). The reference matches services through
  `FWPM_CONDITION_ALE_USER_ID` and UWP packages through `ALE_PACKAGE_ID`, not through a path at all,
  and taxes each application with a type that drives that choice. We match only `ALE_APP_ID`.
- **Per-application extras** (§4.2): a file hash, a timer that allows or blocks for N seconds, and a
  "cannot be deleted" flag for system-critical entries.
- **A name** (§51). `remote` refuses `example.com` and nothing resolves one, so a rule learned from an
  event carries an address while the rule a person would write carries a name. Its own layer, not a
  field.
- **A service** (§4.6, §51). Every service hosted by `svchost.exe` shares one path, so a rule cannot
  single one service out. Undesigned: a service is a name rather than a path, the Detected list would
  collect names, and what a rule about a service that is not running should do is a question the
  reference does not answer either.

### 3.3 The event record

- **No class derived from the filter weight** (§4.3). The reference derives a class from the dropping
  filter's weight and keeps noise out of its log that way; our event names the filter and the rule but
  not the class.
- **Not named:** the package SID, a layer name, and any byte counter (§4.3). An event is a moment
  rather than a table, which is the reason and not an excuse.

### 3.4 Stored paths

- **Environment variables are neither expanded on read nor un-expanded on write** (§4.4), so a rule
  file does not survive a move to a machine where `%ProgramFiles%` differs. We store literal text.
- **Stored paths are not repaired on load** (§4.4). The reference converts a `\device\…` path to a
  drive path and expands short 8.3 paths containing `~` with `GetLongPathNameW`, so the same program
  does not appear twice. We map only the drive prefix.

## 4. Doc drift found this round

Two claims in the old §4.5 are behind the code and were left standing when the closed text moved to
the journal; both are worth a correction the next time the chapter is open.

- "We always set the persistent flag, with no way out" — `volatile_filters` exists since 0.22.0 and is
  a setting in `config.toml`.
- "Ours is one unbounded append-only file" — the log rolls at a megabyte since 0.26.0.

## 5. What is solid

Both audits agree on the foundation, and it is written down so it does not get re-litigated (§5).

1. **Data directory and atomic writes.** Layout under `%APPDATA%\winfw-mcp`, load exactly once at
   startup, `*.tmp` plus rename with `sync_all`, unknown config keys rejected, older configs without
   newer keys still load.
2. **Learning mode mechanics.** Collect per application when no rule covers it, count up without a
   redundant write, newest first, capped and persisted, allow and deny produce a real rule and rebuild
   the store, dismiss only after the store accepted, nothing auto-applied.
3. **The write path.** One worker thread owns the engine handle, full rebuild in one transaction, file
   written before the store on every mutation route, deny outranks allow by weight, persistent provider
   and sublayer under fixed GUIDs.
4. **The MCP access model.** Read-only on purpose, and a refusal returned as a tool result with
   `isError` rather than as a transport error.
5. **Degraded operation without elevation.** Reported per store class, surfaced as a banner, not a
   crash.

## 6. Suggested priority

Roughly by how much they cost to change later:

1. **Multi-valued `remote`, `local` and application pattern** (§3.2). One filter per element already
   works for ports since 0.74.0, so the shape is known; the text format is settled.
2. **A name** (§3.2). Its own layer of DNS resolution, and the thing a person expects to type.
3. **A service** (§3.2). The largest unanswered design question, and the price default deny names in
   the security chapter.
4. **Application identity beyond a path** (§3.2), which is the mechanism a service answer would use.
5. **The weight ladder and its collision** with other software on the machine (§3.1).
6. **The remaining WFP features** (§3.1): stealth mode, boot-time filters, DACLs, engine options.
7. **The smaller API gaps** (§2.3): the generation check on index routes, a single-rule edit route.
8. **Stored paths** (§3.4) and **import from the page** (§2.4).
