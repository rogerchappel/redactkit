import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { validateReleaseReadiness } from './validate-release-readiness.mjs';

const fixtures = JSON.parse(fs.readFileSync(new URL('./fixtures/release-workflows.json', import.meta.url), 'utf8'));

function fixtureRoot(workflow, { publishNpm = true, readme } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'redactkit-release-readiness-'));
  fs.mkdirSync(path.join(root, '.github', 'workflows'), { recursive: true });
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({
    packageManager: 'pnpm@10.11.0',
    repository: 'example/redactkit',
    files: ['dist'],
    scripts: { 'package:smoke': 'true', 'release:check': 'true' },
  }));
  fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9.0\n');
  fs.writeFileSync(path.join(root, 'releasebox.config.json'), JSON.stringify({
    release: { publishNpm },
  }));
  fs.writeFileSync(path.join(root, 'README.md'), readme ?? [
    '## Install',
    '',
    'Install from source:',
    '',
    '```sh',
    'git clone https://github.com/example/redactkit.git',
    'pnpm install --frozen-lockfile',
    'pnpm run build',
    '```',
  ].join('\n'));
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

test('rejects npm publishing when ReleaseBox disables it', (t) => {
  const root = fixtureRoot(fixtures.valid, { publishNpm: false });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.match(validateReleaseReadiness(root).join('\n'), /publishNpm/);
});

test('rejects an advertised npm install when npm publishing is disabled', (t) => {
  const root = fixtureRoot(fixtures.valid, {
    publishNpm: false,
    readme: '## Install\n\n```sh\nnpm install @rogerchappel/redactkit\n```',
  });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.match(validateReleaseReadiness(root).join('\n'), /README.*npm/);
});

test('requires a documented source-install fallback', (t) => {
  const root = fixtureRoot(fixtures.valid, {
    readme: '## Install\n\n```sh\nnpm install @rogerchappel/redactkit\n```',
  });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.match(validateReleaseReadiness(root).join('\n'), /source-install fallback/);
});

test('rejects conflicting package manager lockfiles', (t) => {
  const root = fixtureRoot(fixtures.valid);
  fs.writeFileSync(path.join(root, 'package-lock.json'), '{}');
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.match(validateReleaseReadiness(root).join('\n'), /package-lock/);
});

test('rejects workflow project installs that return to npm', (t) => {
  const root = fixtureRoot(`${fixtures.valid}\n      - run: npm ci\n`);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  assert.match(validateReleaseReadiness(root).join('\n'), /project dependencies with npm/);
});
