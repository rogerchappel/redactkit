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

function* ruleMatches(rule: RedactionRule, content: string): Generator<RegExpExecArray> {
  let flags = rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`;
  if (!flags.includes("d")) flags += "d";
  const pattern = new RegExp(rule.pattern.source, flags);
  let match: RegExpExecArray | null;

  // RegExp.exec does not advance after an empty match, so advance by one code
  // point to keep user-supplied rules finite without changing their matches.
  // eslint-disable-next-line no-cond-assign
  while ((match = pattern.exec(content)) !== null) {
    yield match;
    if (match[0].length === 0) {
      const codePoint = content.codePointAt(pattern.lastIndex);
      pattern.lastIndex += codePoint !== undefined && codePoint > 0xffff ? 2 : 1;
    }
  }
}

function sensitiveSpan(match: RegExpExecArray): { start: number; end: number; raw: string } {
  const capture = match[1];
  const indices = match.indices?.[capture !== undefined ? 1 : 0];
  if (!indices) {
    throw new Error("Unable to locate redaction match");
  }
  return { start: indices[0], end: indices[1], raw: capture ?? match[0] };
}

function scanFile(
  filePath: string,
  rules: RedactionRule[],
  map: PlaceholderMap,
): RedactionMatch[] {
  const content = readFileSync(filePath, "utf8");
  const matches: RedactionMatch[] = [];

  for (const rule of rules) {
    for (const m of ruleMatches(rule, content)) {
      const { start, raw } = sensitiveSpan(m);
      const placeholder = map.get(rule, raw);

      // Calculate line and column
      const before = content.slice(0, start);
      const lineStart = before.lastIndexOf("\n") + 1;
      const line = before.split("\n").length;
      const column = start - lineStart + 1;

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
      for (const m of ruleMatches(rule, content)) {
        const span = sensitiveSpan(m);
        replacements.push({
          start: span.start,
          end: span.end,
          rule,
          raw: span.raw,
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
