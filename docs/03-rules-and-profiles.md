# 3. Rules and profiles

*Part of the [winfw-mcp handbook](../README.md#the-handbook).*

A rule names an action (`allow` or `deny`), an application pattern, a name, and whether it is
enabled. Rules live in `rules.toml` in the order they were written, and that order matters.

## The first two rules

A rules file that does not exist yet is not created empty. It is created with two example rules, so
the first screen already shows what a rule looks like instead of an empty table:

```toml
[[rule]]
name = "example allow"
action = "allow"
pattern = "C:\\test\\tool1.exe"
enabled = true
remote = "192.0.2.0/24"
comment = "the allow shape: this app may reach this network"

[[rule]]
name = "example deny"
action = "deny"
pattern = "C:\\test\\tool2.exe"
enabled = true
remote = "198.51.100.0/24"
comment = "the deny shape: this app may not"
```

Both are deliberately inert. The paths name `C:\test\`, which a normal machine does not have, and
the two networks are the documentation ranges of RFC 5737, which no host of a real network is ever
in, so the pair explains the format without deciding a single connection. Delete them, or edit them
into your first real rule; either way the file is ordinary from then on. A file you emptied yourself
is left empty, because it exists by then and is not written again.

## Narrowing a rule

Beyond the application, a rule can be narrowed by four optional fields. A rule that names none of
them is about all of them, which is every rule written before these fields existed.

| Field | Values | Meaning |
|---|---|---|
| `protocol` | `"tcp"`, `"udp"`, `47` | the transport the connection uses |
| `direction` | `"in"`, `"out"` | which way the connection goes |
| `port` | `"443"`, `"1024-2048"` | one port, or an inclusive range of them |
| `remote` | `"10.0.0.5"`, `"192.168.1.0/24"`, `"10.0.0.1-10.0.0.9"` | the address the connection goes to |

```toml
[[rule]]
name = "ssh"
action = "allow"
pattern = "C:\\Program Files\\*\\ssh.exe"
enabled = true
protocol = "tcp"
direction = "out"
port = "1024-2048"
remote = "192.168.1.0/24"
```

All four are written in the file, read back from it, shown in the page and accepted over both the
HTTP API and MCP. A value the server cannot read is refused rather than ignored, so `port = "http"`
bounces instead of silently turning into "every port".

`protocol` is the one field with two shapes. The two transports worth naming are written as their
names; everything else is written as its number, which is how a rule about GRE (47) or ESP (50)
exists at all. A number may be quoted or bare, and both are written back as a bare number, so
`protocol = "47"` becomes `protocol = 47` the next time the file is saved. Zero is refused: a rule
that wants every transport leaves the field out rather than naming protocol 0.

The narrowing is real, not cosmetic. `direction` decides which layers the rule is installed on, and
`protocol`, `port` and `remote` become conditions on the filter, so a narrowed rule leaves other
connections alone rather than deciding them. Details in
[WFP internals](07-wfp-internals.md#the-layers-a-rule-is-installed-on).

## Writing a remote address

`remote` is one address, one network or one span of addresses in either family, written the way
networks are written everywhere else:

| Written | Read as |
|---|---|
| `10.0.0.5` | `10.0.0.5/32`, one host |
| `192.168.1.0/24` | that network |
| `10.0.0.5/24` | `10.0.0.0/24` |
| `fe80::/10` | an IPv6 network |
| `::/0` | every IPv6 address |
| `10.0.0.1-10.0.0.9` | the nine hosts between the two ends, both included |

A bare address is a prefix as wide as its family, so it names one host. Host bits are dropped while
the text is read, which is why `10.0.0.5/24` is stored and shown as `10.0.0.0/24`: what is in the
file is exactly the network the filter matches. A prefix longer than the family (`10.0.0.5/33`,
`::/129`) is refused, and so is text that is not an address at all. A hostname such as
`example.com` is not an address; resolving names is not something WFP does for a filter condition,
so a name would have to be turned into an address by hand.

A span is told from the other two shapes by the `-` between its ends, which no address text
contains. It covers what a prefix cannot: `10.0.0.1-10.0.0.9` is nine hosts, while the narrowest
network that holds them all would also hold `10.0.0.0` and `10.0.0.10` to `10.0.0.15`. Both ends
have to be addresses of the same family and the first must not come after the second, so
`10.0.0.9-10.0.0.1` is refused rather than read as a span that matches nothing.

Because an IPv4 address can never match on an IPv6 layer and the other way round, an address also
narrows the layers the rule is installed on, exactly as `direction` does.

A port is matched on the side of the connection it is about: the remote port on the way out, the
local port on the way in. "Port 443" therefore means the same thing in both directions, which is
what the reference implementation does as well.

Writing a path by hand in TOML needs doubled backslashes, as in the example above: a single
backslash starts an escape sequence, and a file that fails to parse stops the tool at startup rather
than being partly read. Anything this tool writes itself is escaped correctly.

## Order, and why deny still wins

The order in `rules.toml` is exactly the order WFP evaluates, because applying is a full rebuild:
our filters are removed and re-added in rule order inside one transaction.

The page can change that order: the up and down buttons in the order column of the rules table send
`POST /api/rules/move`, which rewrites the file and rebuilds the filters, because a rebuild is the
only way order reaches WFP.

**Deny always beats allow.** A deny filter is installed one weight above an allow filter, so a
matching deny wins even when an allow rule comes earlier in the file. Between rules of the same
action the earlier one still wins, because equal weights are resolved in creation order and filters
are installed in file order.

An application that appears in neither list is not allowed by us: the rules decide the applications
they mention. With `default_policy = "deny"` that is enforced literally, down to a base block filter
at the bottom of the store; with the default `allow` traffic no rule mentions is left to the rest of
the machine. The base filters behind this are in
[WFP internals](07-wfp-internals.md#the-default-deny-base).

## Wildcards

Rules match on `*` and `?`. Those wildcards are ours, not the kernel's: the translation to WFP is
done by this program, in one place. WFP itself compares an application path exactly, so a pattern
with a wildcard is expanded into the applications this tool has actually seen, and each of them
gets its own filter. The expansion is capped at 32 applications: a broader pattern is installed for
the first 32 and says so, both as a warning in the log and as a note under the rule on the page
("pattern has 42 matches, only 32 installed"), because a firewall that quietly stops matching is one
nobody can reason about. A pattern nothing was seen for yet is installed as it stands, so the rule
stays visible even before it can match.

A pattern is checked on the way in, because a rule that cannot match anything is not a harmless
typo in a firewall: the connection it was supposed to decide goes the other way. It must be an
absolute path — rooted at a drive (`C:\...`) or at a single separator (`\device\...`, which is what
an application looks like before the drive map resolves it) — and it cannot contain a control
character or any of `"`, `<`, `>`, `|`, which a Windows path cannot hold either. `not-a-path` is
refused rather than stored as a rule nothing will ever match.

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

The table that translates the two forms is asked once and kept. A drive that appears later — a USB
disk mounted after the tool started, a network share mapped while it was already running — is
noticed the next time a path is looked up and does not match: the table is asked again, at most once
a second, and the lookup is retried against the answer. A pattern that is not a path at all (`*`, or
a host name) never triggers that re-ask.

What the re-ask does not do is rewrite filters that are already in the store. A rule pointing at a
drive that did not exist when the filters were installed went in with the drive form untranslated,
and it stays that way until the rules are applied again, which every later write to the rule list
does anyway.

## Commenting a rule

`comment` is the one field that decides nothing. It is a sentence for whoever reads the list next,
usually the person who wrote the rule six months earlier, and it is skipped when it is absent, so a
rules file that never uses it is written exactly as it was before the field existed.

```toml
[[rule]]
name = "vpn"
action = "allow"
pattern = "C:\\Program Files\\*\\vpn.exe"
enabled = true
comment = "must stay allowed or the vendor's updater hangs"
```

The page shows it in a column of its own and the Base64 share string carries it, which is what makes
a rule explainable when it travels by copy and paste. It is not sent to the store: a filter is what a
rule became, and a wildcard rule that expands to a dozen filters would repeat the same sentence a
dozen times in a store nobody reads with a comment.

Two hundred characters is the limit, and a control character is refused. Both are refusals rather
than cuts on purpose. The reference truncates at its buffer size, and a rule that quietly lost the
end of its reason is harder to trust than one refused at the moment it was written.

## Sharing a rule

One rule can be turned into a Base64 string (`POST /api/rules/share`) and pasted anywhere;
`POST /api/rules/import` appends the rule such a string carries. This is the manual backup path for
a single rule, next to the export of a whole area.

Reading such a string back is the page's job. The MCP endpoint is read-only, so an agent
can be handed a share string and can report what the page makes of it, but it cannot decode or append
one itself. On import the pattern is validated first, because a share string is Base64 around JSON a
human may have edited.

## Importing from the C original

`--import <file>` reads the XML a person exported from simplewall and writes the rules it understands
into the rule file of the active profile, replacing what was there. The two sections that hold rules
are read in document order; the list of applications, the table of built-in rules and the blocklist
are left alone, because they are not rules of this shape.

What a rule of this tool cannot express is not dropped in silence. An item that names several
applications becomes one rule each. An item that names several ports or addresses, a local address,
an address family, a service instead of a path, a service or kernel flag: all of it is named either
in the comment of the rule it came from or, when no rule came from it at all, as a note in the log.
The import writes and exits; it does not touch the live store, so the result is looked at on the page
before anything is installed.

## Profiles

A profile is a file, not a table. The active profile is a name in `config.toml`, and its rules are
one file in `profiles\`. The unnamed default profile keeps using `rules.toml`, so a config from an
earlier version needs no migration.

Switching profiles writes the current rules back to the file they came from before the new one is
read, so no rule is ever only in memory. Switching is available from the page, and the choice
survives a restart. The [Detected list](04-learning-mode.md) belongs to a profile the same way
its rules do: switching switches the list of applications waiting for a decision, so an entry
collected under one profile never asks a question about rules that are not live, and renaming or
deleting a profile moves its list along or takes it out. The one pool that does not follow the
profile is the set of applications this machine has been seen connecting with, because that is a
fact about the machine and a wildcard of the live profile expands against all of it.

The page can also create, rename and delete a profile. **New** copies the rules on screen into the
new file and switches to it, on the grounds that a profile started in a browser is meant to be a
different take on the rules you are looking at rather than an empty file to fill rule by rule; a
name already in use is refused rather than overwritten. **Rename** takes the file's backup along
with it, so the generation kept belongs to the file rather than to the name it had. **Delete**
removes the file and its backup, and falls back to `rules.toml` when the deleted profile was the
live one.

The unnamed default is not one of these files, so renaming or deleting it is refused: `rules.toml`
is where the tool falls back to, and removing it would leave nothing to fall back to.

---

Previous: [2. Data and configuration](02-data-and-configuration.md) · Next: [4. Learning mode](04-learning-mode.md)
