# 3. Rules and profiles

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

A rule names an action (`allow` or `deny`), an application pattern, a name, and whether it is
enabled. Rules live in `rules.toml` in the order they were written, and that order matters.

## Order, and why deny still wins

The order in `rules.toml` is exactly the order WFP evaluates, because applying is a full rebuild:
our filters are removed and re-added in rule order inside one transaction.

**Deny always beats allow.** A deny filter is installed one weight above an allow filter, so a
matching deny wins even when an allow rule comes earlier in the file. Between rules of the same
action the earlier one still wins, because equal weights are resolved in creation order and filters
are installed in file order.

An application that appears in neither list is not allowed by us: the rules decide the applications
they mention. What that means for traffic no rule mentions, and how the reference closes the gap
with base filters at the lowest weight, is in
[WFP internals](07-wfp-internals.md#what-the-reference-does-that-we-do-not).

## Wildcards

Rules match on `*` and `?`. Those wildcards are ours, not the kernel's: the translation to WFP is
done by this program, in one place. WFP itself compares an application path exactly, so a pattern
with a wildcard is expanded into the applications this tool has actually seen, and each of them
gets its own filter (up to a fixed cap). A pattern nothing was seen for yet is installed as it
stands, so the rule stays visible even before it can match.

The set of seen applications is wider than the Detected list: it grows whether or not
`learn_mode` is on, it includes applications an existing rule already covers, and dismissing or
deciding an entry does not remove it. When an application is seen for the first time and an
enabled rule is a pattern, the filters are rebuilt against the whole set, so a rule written
yesterday picks up a program installed today without a manual Apply. The store is also rebuilt
from the rules every time the tool starts, which is what keeps a rule edited while the process was
stopped honest.

## Device paths and drive paths

Application paths reach the firewall in device form (`\device\harddiskvolume3\...`), which nobody
reads comfortably, so the UI shows the drive form and a rule written in either form is accepted.

## Sharing a rule

One rule can be turned into a Base64 string (`POST /api/rules/share`) and pasted anywhere;
`POST /api/rules/import` appends the rule such a string carries. This is the manual backup path for
a single rule, next to the export of a whole area.

## Profiles

A profile is a file, not a table. The active profile is a name in `config.toml`, and its rules are
one file in `profiles\`. The unnamed default profile keeps using `rules.toml`, so a config from an
earlier version needs no migration.

Switching profiles writes the current rules back to the file they came from before the new one is
read, so no rule is ever only in memory. Switching is available from the page and over MCP, and the
choice survives a restart.

---

Previous: [2. Data and configuration](02-data-and-configuration.md) · Next: [4. Learning mode](04-learning-mode.md)
