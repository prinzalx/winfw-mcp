# ADR 0002: AGPL-3.0-only

## Status

Accepted (retroactively recorded 2026-11-22; shipped with 1.3.5).
Copyright-holder name in §C is open (D1, see `docs/PROGRESS.md`).

## Context

`Cargo.toml` named `MIT` with no license file beside it. MIT permits the one
thing the owner did not want: a firm taking the source into a closed product.

## Decision

The tool is licensed **AGPL-3.0-only**, full text in `LICENSE`.

## Consequences

Everyone may use it; a firm may sell it only with the whole source travelling
along under the same license; a fork owes every other user the same openness.
The license text is a public file and belongs in the public repository.

## Alternatives

GPL-3.0 was considered; the owner chose the stronger copyleft because the
tool's likely misuse is a hosted or closed product, where AGPL's network
clause keeps the source owed.
