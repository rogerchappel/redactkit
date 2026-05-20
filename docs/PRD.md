# redactkit PRD

Status: in-progress

## Summary

`redactkit` is a deterministic CLI for scrubbing secrets and private details
from logs, transcripts, cassettes, and fixtures before sharing them. It favors
explainable rules, local execution, and reviewable replacement maps.

## Source Attribution

Inspired by the rise of local-first agents and the need to share debugging
artifacts safely. This idea is renamed and reframed as a practical redaction
tool for developer fixtures rather than a broad DLP product.

## Problem

Developers need to paste logs and agent transcripts into issues, tests, and
reviews, but those files may contain tokens, URLs, emails, paths, and internal
names. Existing scanners often detect secrets but do not create clean,
shareable fixture files with stable placeholders.

## Target Users

- Developers sharing debug logs.
- Agent authors publishing fixture cassettes.
- Maintainers preparing repro bundles.

## V1 Scope

- `redactkit scan <files...>`
- `redactkit redact <files...> --out-dir redacted`
- Built-in rules for common tokens, keys, bearer headers, emails, URLs,
  home-directory paths, and IPv4 addresses.
- Stable placeholder mapping saved as `redactkit-map.json`.
- Custom JSON rule file support.
- Fixture-backed tests for detection, redaction, and stable mapping.

## Non-Goals

- Enterprise DLP policy engine.
- Network calls or telemetry.
- Binary file redaction.

## Success Criteria

- Redaction is deterministic across repeated runs.
- Reports explain which rule matched without exposing raw secrets.
- README includes before/after examples and safety caveats.

