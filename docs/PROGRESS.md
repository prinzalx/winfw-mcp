# PROGRESS

The current status. Update it at the end of every lifecycle phase. Keep it short.

## Current phase

Phase 8 of 8: release readiness. **1.4.5 is released** (2026-11-07, tag
`v1.4.5`); the backlog is empty, so the next release needs a new owner request.

## Done

- 1.4.5 shipped: the decision-page round (blocked-only Connections, FQDN
  prefill, unique rows, live filters, red chips, permanent learning) and the
  framed service condition.
- TEMPLATE_00 retrofit (2026-11-22, `/templateify`): the standard documents
  (`BRIEF.md`, `AGENTS.md`, `docs/PROGRESS.md`, `docs/decisions/`), the three
  reviewer agents, `/release`, and `release/release.py` plus
  `release/include.txt` landed additively on top of the kept history.

## In progress

- Nothing open: the public snapshot is published (2026-11-22, public commit
  `de2099d`, 82 allowlisted files on `main` — carries the review fixes and the
  `assets/` + `release/` allowlist entries).

## Open questions

- D1: the copyright-holder name in the license section ("prinzalx" vs civil
  name).

## Next

- Any new release starts from a new owner request; each `/release` ends with
  `release/release.py publish` so the public repo stays current.

## Log

Newest line first. One line per phase end.

| Date | Phase | Result |
|---|---|---|
| 2026-11-22 | review | `/review` (medium) on `0e20a3f`: 14 findings (4 Critical), verdict Request changes; all 14 fixed (`release.py`, `include.txt`, docs) and verified (`py_compile`, probes, `check` PASS); snapshot republished (`de2099d`) |
| 2026-11-22 | retrofit | TEMPLATE_00 overlay landed additively; dev repo `winfw-mcp-dev` private; public repo `winfw-mcp` published (78 files, `a0434b1`) |
| 2026-11-07 | 8 | 1.4.5 released: 340 tests serially green, fmt/clippy clean, CI green |
