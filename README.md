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
