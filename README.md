# redactkit

Local-first CLI for scrubbing secrets and private details from logs, transcripts, and fixtures.

## Status

This is an early v0.1.0 CLI and library for deterministic local scanning and redaction. No version has been published to npm or GitHub Releases yet.

## Install

Until the first version is published, install the CLI and library from the source repository:

```sh
git clone https://github.com/rogerchappel/redactkit.git
cd redactkit
corepack enable
pnpm install --frozen-lockfile
pnpm run build
pnpm link --global
```

After `pnpm link --global`, run `redactkit` as a CLI or import the library from the checkout. pnpm is the repository's authoritative package manager; its version is pinned in `package.json`, and `pnpm install --frozen-lockfile` uses the committed `pnpm-lock.yaml`. `pnpm run build` creates the executable and library files under `dist/`.

## Use

Scan files for built-in sensitive patterns:

```sh
node dist/src/cli.js scan fixtures/sample.log
```

Write redacted copies and a placeholder map:

```sh
node dist/src/cli.js redact fixtures/sample.log --out-dir tmp-redacted --map tmp-redacted/map.json
```

Use custom rules for project-specific identifiers:

```sh
node dist/src/cli.js redact examples/support-transcript.txt \
  --rules examples/custom-rules.json \
  --out-dir tmp-redacted \
  --map tmp-redacted/map.json
```

Options can appear before or after file operands. Unknown options, or
`--out-dir`, `--map`, and `--rules` without a value, are usage errors and exit
with status 2.

The rule file is JSON:

```json
{
  "rules": [
    {
      "name": "internal-ticket",
      "pattern": "SUP-[0-9]{6}",
      "flags": "g",
      "placeholder": "TICKET"
    }
  ]
}
```

Each rule must be an object with non-empty string `name` and `pattern` fields.
Optional `flags` and `description` fields must be strings, and `placeholder`
must be a non-empty string when present. `flags` accepts valid JavaScript
regular-expression flags. Invalid JSON, field values, patterns, or flags fail
before RedactKit creates an output directory, redacted file, or map.

The `g` flag is optional: RedactKit always iterates custom rules across the complete input.
The sticky `y` flag is accepted, but scanning treats it as global search so a
rule can find matches beyond offset zero; every other JavaScript flag keeps its
normal meaning.
Patterns that can match an empty string are also supported; iteration advances
by one Unicode code point after each empty match so scans and redactions finish
deterministically.

When a pattern contains a first capture group, RedactKit scans and replaces
only that captured value, preserving surrounding syntax such as assignment
keys, separators, quotes, and authorization schemes. Without a capture group,
the complete match is treated as sensitive.

The redacted output keeps stable placeholders such as
`<REDACTED_TICKET_001>`. The map file records the original value for local
review and should not be published with shared fixtures.

`scan` reports every detected rule match. `redact` reports and counts only the
non-overlapping replacements it actually applies, and its map contains only
those applied values. When rules overlap, the match starting furthest to the
right wins; matches at the same position prefer the longer span, then the rule
listed first. This selection is deterministic for both library and CLI use.

RedactKit never overwrites an input file. Before creating output directories or
writing files, redaction fails if a resolved output or map path aliases any
input path, including when relative and absolute spellings refer to the same
path. The `--map` path also must not collide with any generated redacted output
path. Choose a separate `--out-dir` and `--map` location.

## Verify

```sh
pnpm run build
npm test
pnpm run smoke
pnpm run package:smoke
pnpm run release:readiness
pnpm run release:check
```

## Release

The repository is configured for npm trusted publishing, but npm installation must not be advertised until the first package is actually available. Maintainers publish by pushing a semantic-version tag that exactly matches
`package.json` (for example, version `0.1.0` uses tag `v0.1.0`). The release
workflow uses npm trusted publishing with provenance, verifies that exact
version on the registry, and creates or repairs the matching GitHub release.
Re-running the workflow is safe when npm already contains that version. The source-install steps above remain the verified fallback before and after publication.

## Limitations

- Redaction rules are pattern-based and should be validated against your own data before sharing outputs.
- Keep placeholder maps private when they could re-identify sensitive values.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations. Changes should be small, reviewable, and verified before review.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

MIT
