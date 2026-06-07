# Task Breakdown

## Release readiness
- Keep package metadata aligned with the public GitHub repository, issue tracker, and README homepage.
- Run the local release checks before publishing or changing CLI behavior.
- Keep packaged policy files such as LICENSE and SECURITY.md included when they exist.

## Verification gates
- Parse package.json after metadata edits.
- Run npm pack dry-run before opening release-oriented pull requests.
- Use the README verification commands as the public smoke path for contributors.

## Follow-up candidates
- Add fixture-backed tests for any uncovered CLI branch before expanding the command surface.
- Refresh examples when CLI output formats change.
