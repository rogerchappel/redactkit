import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function validateReleaseReadiness(root = process.cwd()) {
  const packagePath = path.join(root, 'package.json');
  const packageJson = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
  const scripts = packageJson.scripts ?? {};
  const failures = [];
  const requireField = (condition, message) => {
    if (!condition) failures.push(message);
  };

  requireField(packageJson.repository, 'package.json must declare repository metadata');
  requireField(Array.isArray(packageJson.files) && packageJson.files.length > 0, 'package.json must declare a non-empty files allowlist');
  requireField(scripts['package:smoke'], 'package.json scripts must include package:smoke');
  requireField(scripts['release:check'], 'package.json scripts must include release:check');

  const workflowDir = path.join(root, '.github', 'workflows');
  const workflowFiles = fs.existsSync(workflowDir)
    ? fs.readdirSync(workflowDir).filter((file) => /\.ya?ml$/.test(file))
    : [];
  requireField(workflowFiles.length > 0, 'repository must include at least one workflow file');

  const workflows = workflowFiles.map((file) => ({
    file,
    contents: fs.readFileSync(path.join(workflowDir, file), 'utf8'),
  }));
  for (const { file, contents } of workflows) {
    requireField(!/TODO|FIXME|template becomes an app|customization TODO/i.test(contents), `.github/workflows/${file} still contains placeholder text`);
  }

  const combined = workflows.map(({ contents }) => contents).join('\n');
  requireField(/release:check/.test(combined), 'CI workflows must run npm run release:check');

  const releaseWorkflow = workflows.find(({ contents }) => /tags:\s*[\s\S]*?v\*\.\*\.\*/.test(contents))?.contents ?? '';
  requireField(Boolean(releaseWorkflow), 'a release workflow must run for semantic version tags');
  requireField(/id-token:\s*write/.test(releaseWorkflow), 'release workflow must grant id-token: write for npm trusted publishing');
  requireField(/npm publish[^\n]*--provenance/.test(releaseWorkflow), 'release workflow must publish to npm with provenance');
  requireField(/GITHUB_REF_NAME[\s\S]*package[^\n]*version|package[^\n]*version[\s\S]*GITHUB_REF_NAME/.test(releaseWorkflow), 'release workflow must validate the tag against package.json version');
  requireField(/npm view[\s\S]*@?[^\s"']+@\$?\{?[^\s"'}]+\}?[\s\S]*version/.test(releaseWorkflow), 'release workflow must verify the exact published package version');
  requireField(/gh release view[\s\S]*gh release (?:edit|upload)|gh release view[\s\S]*gh release create/.test(releaseWorkflow), 'release workflow must recover an existing GitHub release without duplicating it');

  return failures;
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  const failures = validateReleaseReadiness(process.argv[2] ? path.resolve(process.argv[2]) : process.cwd());
  if (failures.length > 0) {
    console.error('Release readiness validation failed:');
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log('Release readiness validation passed.');
}
