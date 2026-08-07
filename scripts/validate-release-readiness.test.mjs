import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { validateReleaseReadiness } from './validate-release-readiness.mjs';

const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/release-workflows.json', import.meta.url), 'utf8'));

function fixtureRoot(workflow) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactkit-release-readiness-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    repository: 'example/redactkit',
    files: ['dist'],
    scripts: { 'package:smoke': 'true', 'release:check': 'true' },
  }));
  fs.writeFileSync(path.join(root, '.github', 'workflows', 'release.yml'), workflow);
  return root;
}

test('accepts the complete trusted-publishing release contract', (t) => {
  const root = fixtureRoot(fixtures.valid);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.deepEqual(validateReleaseReadiness(root), []);
});

for (const [guarantee, replacement] of Object.entries(fixtures.broken)) {
  test(`rejects a workflow missing the ${guarantee} guarantee`, (t) => {
    const root = fixtureRoot(fixtures.valid.replace(
      guarantee === 'publish' ? 'npm publish --provenance --access public'
        : guarantee === 'tag' ? 'test "$GITHUB_REF_NAME" = "v$(node -p \\"require(\'./package.json\').version\\")"'
          : guarantee === 'provenance' ? 'npm publish --provenance --access public'
            : guarantee === 'verification' ? 'npm view "${PACKAGE_NAME}@${PACKAGE_VERSION}" version'
              : /if gh release view[\s\S]*?fi/.exec(fixtures.valid)?.[0],
      replacement,
    ));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    assert.notDeepEqual(validateReleaseReadiness(root), []);
  });
}
