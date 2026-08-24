# ADR 0006: Generate reports from canonical stored JSON

- Status: accepted
- Date: 2026-08-24

## Context

Reports must be reproducible, reviewable, safe to render, and unable to drift
from persisted forensic records. Rendering directly from ORM objects or adding
browser-side scripts would create alternate interpretations and injection risk.

## Decision

The service validates a shared `StructuralReport`, serializes it with stable
sorted-key UTF-8 JSON, stores it create-only, and hashes the exact bytes. HTML is
then rendered from that stored JSON with strict Jinja autoescaping and
self-contained CSS. The report exposes all tool/test states and consistency
sources, but no confidence percentage, probability, or authenticity verdict.

## Consequences

The same report object always serializes to the same bytes and SHA-256. HTML can
be printed or opened offline without JavaScript or a CDN. Report IDs and UTC run
timestamps intentionally differ between separate analyses; determinism applies
to reserialization of the same stored object, not to inventing identical run
identity across independent executions.
