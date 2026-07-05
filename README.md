# redactkit

Local-first CLI for scrubbing secrets and private details from logs, transcripts, and fixtures.

## Status

This is an early v0.1.0 CLI and library for deterministic local scanning and redaction.

## Install

```sh
npm install
npm run build
```

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

The redacted output keeps stable placeholders such as
`<REDACTED_TICKET_001>`. The map file records the original value for local
review and should not be published with shared fixtures.

## Verify

```sh
npm run build
npm test
npm run smoke
npm run package:smoke
npm run release:readiness
npm run release:check
```

## Limitations

- Redaction rules are pattern-based and should be validated against your own data before sharing outputs.
- Keep placeholder maps private when they could re-identify sensitive values.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution expectations. Changes should be small, reviewable, and verified before review.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## License

MIT
