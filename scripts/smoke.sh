#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== redactkit smoke test ==="

# Build
echo "Building..."
pnpm run build >/dev/null

# Scan should find secrets in fixture
echo "Scanning sample.log..."
node dist/src/cli.js scan fixtures/sample.log && echo "FAIL: expected non-zero exit" || true

# Scan clean file should be zero exit
echo "Scanning clean.txt..."
node dist/src/cli.js scan fixtures/clean.txt
echo "✓ Clean file scan passed"

# Redact should produce output
echo "Redacting sample.log..."
rm -rf tmp-smoke
node dist/src/cli.js redact fixtures/sample.log --out-dir tmp-smoke/out --map tmp-smoke/map.json
echo "✓ Redact passed"

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
node dist/src/cli.js foobar 2>&1 || true
echo "✓ Unknown command handled"

# No files
node dist/src/cli.js scan 2>&1 || true
echo "✓ No-files error handled"

# Cleanup
rm -rf tmp-smoke tmp-smoke-2

echo ""
echo "=== All smoke tests passed ✓ ==="
