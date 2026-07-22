import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, dirname, isAbsolute, relative, join, sep } from "node:path";
import type {
  RedactionRule,
  RedactionMatch,
  ScanResult,
  RedactResult,
  ScanOptions,
  RedactOptions,
} from "./types.js";
import { PlaceholderMap } from "./placeholders.js";
import { fingerprint } from "./fingerprint.js";
import { cloneRule, builtInRules } from "./rules.js";

function scanFile(
  filePath: string,
  rules: RedactionRule[],
  map: PlaceholderMap,
): RedactionMatch[] {
  const content = readFileSync(filePath, "utf8");
  const matches: RedactionMatch[] = [];

  for (const rule of rules) {
    // Reset lastIndex for global regexes
    const re = cloneRule(rule);
    let m: RegExpExecArray | null;
    // eslint-disable-next-line no-cond-assign
    while ((m = re.pattern.exec(content)) !== null) {
      // Extract the matched group (if capturing group exists, use group 1; else full match)
      const raw = m[1] ?? m[0];
      const placeholder = map.get(rule, raw);

      // Calculate line and column
      const before = content.slice(0, m.index);
      const lineStart = before.lastIndexOf("\n") + 1;
      const line = content.slice(0, m.index).split("\n").length;
      const column = m.index - lineStart + 1;

      matches.push({
        file: filePath,
        line,
        column,
        rule: rule.name,
        placeholder,
        fingerprint: fingerprint(raw),
      });
    }
  }

  return matches;
}

function resolveOutputPaths(filePaths: string[], outDir: string): string[] {
  if (filePaths.length === 0) return [];

  let commonParent = dirname(filePaths[0]);
  for (const filePath of filePaths.slice(1)) {
    let relativePath = relative(commonParent, filePath);
    while (
      relativePath === ".." ||
      relativePath.startsWith(`..${sep}`) ||
      isAbsolute(relativePath)
    ) {
      const parent = dirname(commonParent);
      if (parent === commonParent) {
        throw new Error("Input files must share a common parent directory");
      }
      commonParent = parent;
      relativePath = relative(commonParent, filePath);
    }
  }

  const outFiles = filePaths.map((filePath) => join(outDir, relative(commonParent, filePath)));
  if (new Set(outFiles).size !== outFiles.length) {
    throw new Error("Input files must resolve to distinct output paths");
  }
  return outFiles;
}

export function scan(options: ScanOptions): ScanResult {
  const map = new PlaceholderMap();
  const allMatches: RedactionMatch[] = [];

  for (const file of options.files) {
    const matches = scanFile(resolve(file), options.rules, map);
    allMatches.push(...matches);
  }

  return {
    files: options.files,
    matches: allMatches,
  };
}

export function redact(options: RedactOptions): RedactResult {
  const map = new PlaceholderMap();
  const allMatches: RedactionMatch[] = [];
  const written: string[] = [];
  const filePaths = options.files.map((file) => resolve(file));
  const outFiles = resolveOutputPaths(filePaths, options.outDir);

  mkdirSync(options.outDir, { recursive: true });

  for (const [index, filePath] of filePaths.entries()) {
    const content = readFileSync(filePath, "utf8");
    let output = content;

    // Collect matches
    const fileMatches = scanFile(filePath, options.rules, map);
    allMatches.push(...fileMatches);

    // Apply redactions — sort by position (reversed) so replacements don't shift indices
    const replacements: { start: number; end: number; rule: RedactionRule; raw: string }[] = [];

    for (const rule of options.rules) {
      const re = cloneRule(rule);
      let m: RegExpExecArray | null;
      // eslint-disable-next-line no-cond-assign
      while ((m = re.pattern.exec(content)) !== null) {
        replacements.push({
          start: m.index,
          end: m.index + m[0].length,
          rule,
          raw: m[1] ?? m[0],
        });
      }
    }

    // Sort descending by start position, then by length (longer matches first for overlapping)
    replacements.sort((a, b) => {
      if (a.start !== b.start) return b.start - a.start;
      return b.end - b.start - (a.end - a.start);
    });

    // Remove overlapping replacements (keep first at each position)
    const filtered: typeof replacements = [];
    let lastEnd = content.length;
    for (const r of replacements) {
      if (r.end <= lastEnd) {
        filtered.push(r);
        lastEnd = r.start;
      }
    }

    // Apply replacements
    for (const r of filtered) {
      const placeholder = map.get(r.rule, r.raw);
      output = output.slice(0, r.start) + placeholder + output.slice(r.end);
    }

    // Write redacted file
    const outFile = outFiles[index];
    mkdirSync(dirname(outFile), { recursive: true });
    writeFileSync(outFile, output, "utf8");
    written.push(outFile);
  }

  // Write map
  const mapPath = resolve(options.mapPath);
  mkdirSync(dirname(mapPath), { recursive: true });
  writeFileSync(mapPath, JSON.stringify(map.toJSON(), null, 2) + "\n", "utf8");

  return {
    files: options.files,
    matches: allMatches,
    outDir: options.outDir,
    mapPath,
    written,
  };
}

export { builtInRules, cloneRule, PlaceholderMap, fingerprint };
