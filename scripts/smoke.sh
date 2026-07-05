#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== redactkit smoke test ==="

expect_exit() {
  local expected="$1"
  shift

  set +e
  "$@"
  local actual=$?
  set -e

  if [ "$actual" -ne "$expected" ]; then
    echo "FAIL: expected exit $expected but got $actual for: $*"
    exit 1
  fi
}

# Build
echo "Building..."
npm run build >/dev/null

# Scan should find secrets in fixture
echo "Scanning sample.log..."
expect_exit 1 node dist/src/cli.js scan fixtures/sample.log

# Scan clean file should be zero exit
echo "Scanning clean.txt..."
node dist/src/cli.js scan fixtures/clean.txt
echo "✓ Clean file scan passed"

# Redact should produce output
echo "Redacting sample.log..."
rm -rf tmp-smoke
node dist/src/cli.js redact fixtures/sample.log --out-dir tmp-smoke/out --map tmp-smoke/map.json
echo "✓ Redact passed"

# Custom rules should work from a published example
echo "Redacting support transcript with custom rules..."
rm -rf tmp-smoke-custom
node dist/src/cli.js redact examples/support-transcript.txt --rules examples/custom-rules.json --out-dir tmp-smoke-custom/out --map tmp-smoke-custom/map.json
if grep -q "SUP-104221" tmp-smoke-custom/out/support-transcript.txt; then
  echo "FAIL: custom rule did not redact support ticket"
  exit 1
fi
if ! grep -q "REDACTED_TICKET" tmp-smoke-custom/out/support-transcript.txt; then
  echo "FAIL: custom placeholder missing from redacted output"
  exit 1
fi
echo "✓ Custom rule redaction passed"

# Verify redacted file doesn't contain raw secrets
if grep -q "Bearer eyJ" tmp-smoke/out/sample.log; then
  echo "FAIL: raw bearer token found in redacted output"
  exit 1
fi
echo "✓ No raw secrets in output"

# Verify map exists
if [ ! -f tmp-smoke/map.json ]; then
  echo "FAIL: map file not created"
  exit 1
fi
echo "✓ Map file created"

# Verify deterministic output
rm -rf tmp-smoke-2
node dist/src/cli.js redact fixtures/sample.log --out-dir tmp-smoke-2/out --map tmp-smoke-2/map.json
diff tmp-smoke/out/sample.log tmp-smoke-2/out/sample.log > /dev/null || {
  echo "FAIL: non-deterministic output"
  exit 1
}
echo "✓ Deterministic across runs"

# --help
node dist/src/cli.js --help | grep -q "redactkit" || { echo "FAIL: help output"; exit 1; }
echo "✓ Help text works"

# --version
node dist/src/cli.js --version | grep -qE "^[0-9]" || { echo "FAIL: version output"; exit 1; }
echo "✓ Version works"

# Unknown command
expect_exit 2 node dist/src/cli.js foobar
echo "✓ Unknown command handled"

# No files
expect_exit 2 node dist/src/cli.js scan
echo "✓ No-files error handled"

# Cleanup
rm -rf tmp-smoke tmp-smoke-2 tmp-smoke-custom

echo ""
echo "=== All smoke tests passed ✓ ==="
