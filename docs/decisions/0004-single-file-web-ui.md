# ADR 0004: One embedded web file, no build step

## Status

Accepted (retroactively recorded 2026-11-22).

## Context

The UI is a browser page served by the binary. A normal JavaScript toolchain
would add a build step, a package manager and a bundle to every edit.

## Decision

The whole page is one file (`web/index.html`, inline CSS and JS) embedded
into the executable with `include_str!`.

## Consequences

The portable binary carries its UI; editing the page is editing one file, and
the running instance is rebuilt with the tool itself. The price: no bundler
catches a JavaScript syntax error, so a parse gate (`node target\parsecheck.js`
during development, a bracket scan in CI) stands in for one. Every page change
needs a rebuild and a server restart before the browser sees it.

## Alternatives

A separate `dist/` folder shipped beside the exe was rejected against the
single-file portability promise; a framework was rejected for a one-page UI
that mostly renders tables.
