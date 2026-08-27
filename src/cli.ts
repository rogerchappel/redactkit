#!/usr/bin/env node
import { resolve, join } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { redact, scan, builtInRules, cloneRule } from "./redact.js";
import type { RedactionRule, SerializableRule } from "./types.js";

class CliUsageError extends Error {}

function printHelp() {
  console.log(`redactkit — local-first log & fixture redaction

USAGE
  redactkit scan <files...>          Detect secrets without modifying files
  redactkit redact <files...>        Create redacted copies in --out-dir

OPTIONS
  --out-dir <dir>        Output directory for redacted files (default: redacted)
  --map <path>           Placeholder map path (default: redactkit-map.json)
  --rules <path>         Load custom rules from a JSON file
  --help, -h             Show this help
  --version, -v          Show version

EXAMPLES
  redactkit scan log.txt debug.log
  redactkit redact transcript.md --out-dir clean --map map.json
  redactkit redact *.log --rules ./my-rules.json

RULE FILE FORMAT (JSON)
  {
    "rules": [
      {
        "name": "internal-domain",
        "pattern": "mycorp\\\\.internal\\\\.com",
        "flags": "gi",
        "placeholder": "DOMAIN",
        "description": "Internal domain references"
      }
    ]
  }

  JavaScript regex flags are accepted. The g flag is optional; all matches are
  processed. Sticky y rules search the complete input. Empty matches advance
  by one Unicode code point.

EXIT CODES
  0   Success (for scan: no secrets found)
  1   Secrets detected (scan) or error occurred
  2   CLI usage error
`);
}

function parseArgs(argv: string[]): { command: string; files: string[]; flags: Record<string, string | true> } {
  const args = argv.slice(2);
  const files: string[] = [];
  const flags: Record<string, string | true> = {};

  // First pass: extract flags that appear anywhere
  for (const arg of args) {
    if (arg === "--help" || arg === "-h") {
      flags.help = true;
    } else if (arg === "--version" || arg === "-v") {
      flags.version = true;
    }
  }

  // Second pass: extract command and positional args
  const flagKeyMap: Record<string, string> = { "out-dir": "outDir", map: "map", rules: "rules" };
  let command = "help";
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--version" || arg === "-v" || arg === "--help" || arg === "-h") {
      continue;
    }
    if (arg === "--out-dir" || arg === "--map" || arg === "--rules") {
      const key = arg.slice(2);
      const value = args[i + 1];
      if (value === undefined || value.startsWith("-")) {
        throw new CliUsageError(`Option ${arg} requires a value.`);
      }
      flags[flagKeyMap[key] || key] = value;
      i++;
      continue;
    }
    if (arg.startsWith("-")) {
      throw new CliUsageError(`Unknown option: ${arg}`);
    }
    if (!arg.startsWith("-")) {
      if (command === "help") {
        command = arg;
      } else {
        files.push(arg);
      }
    }
  }

  return { command, files, flags };
}

function loadCustomRules(path: string): RedactionRule[] {
  let content: string;
  try {
    content = readFileSync(path, "utf8");
  } catch {
    throw new Error(`Invalid rule file ${path}: could not read file`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Invalid rule file ${path}: malformed JSON`);
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !("rules" in parsed) || !Array.isArray(parsed.rules)) {
    throw new Error(`Invalid rule file ${path}: expected { "rules": [...] }`);
  }

  return parsed.rules.map((value, index) => {
    const field = `rules[${index}]`;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error(`Invalid rule file ${path}: ${field} must be an object`);
    }

    const rule = value as Partial<SerializableRule>;
    if (typeof rule.name !== "string" || rule.name.trim() === "") {
      throw new Error(`Invalid rule file ${path}: ${field}.name must be a non-empty string`);
    }
    if (typeof rule.pattern !== "string" || rule.pattern.length === 0) {
      throw new Error(`Invalid rule file ${path}: ${field}.pattern must be a non-empty string`);
    }
    if (rule.flags !== undefined && typeof rule.flags !== "string") {
      throw new Error(`Invalid rule file ${path}: ${field}.flags must be a string`);
    }
    if (rule.placeholder !== undefined && (typeof rule.placeholder !== "string" || rule.placeholder.trim() === "")) {
      throw new Error(`Invalid rule file ${path}: ${field}.placeholder must be a non-empty string`);
    }
    if (rule.description !== undefined && typeof rule.description !== "string") {
      throw new Error(`Invalid rule file ${path}: ${field}.description must be a string`);
    }

    const flags = rule.flags ?? "g";
    try {
      new RegExp("", flags);
    } catch {
      throw new Error(`Invalid rule file ${path}: ${field} has invalid regular expression flags`);
    }

    let pattern: RegExp;
    try {
      pattern = new RegExp(rule.pattern, flags);
    } catch {
      throw new Error(`Invalid rule file ${path}: ${field} has invalid regular expression`);
    }

    return {
      name: rule.name,
      description: rule.description ?? "Custom rule from file",
      pattern,
      placeholder: rule.placeholder ?? "CUSTOM",
      source: "custom" as const,
    };
  });
}

async function main() {
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "package.json"), "utf8"));
  const { command, files, flags } = parseArgs(process.argv);

  if (flags.version) {
    console.log(pkg.version);
    process.exit(0);
  }

  if (flags.help || command === "help" || command === "--help" || command === "-h") {
    printHelp();
    process.exit(0);
  }

  if (command !== "scan" && command !== "redact") {
    console.error(`Unknown command: ${command}`);
    console.error("Usage: redactkit scan <files...>  or  redactkit redact <files...>");
    process.exit(2);
  }

  if (files.length === 0) {
    console.error(`Error: no files specified.`);
    console.error(`Usage: redactkit ${command} <files...>`);
    process.exit(2);
  }

  // Resolve all files
  const resolvedFiles = files.map((f) => resolve(f));
  const missing = resolvedFiles.filter((f) => !existsSync(f));
  if (missing.length > 0) {
    console.error(`Error: file(s) not found:`);
    for (const m of missing) console.error(`  ${m}`);
    process.exit(2);
  }

  // Load rules
  const rules: RedactionRule[] = [...builtInRules.map((r) => cloneRule(r))];
  if (typeof flags.rules === "string") {
    const custom = loadCustomRules(flags.rules);
    rules.push(...custom);
  }

  // Execute command
  if (command === "scan") {
    const result = scan({ files: resolvedFiles, rules });

    if (result.matches.length === 0) {
      console.log("✅ No secrets detected.");
      process.exit(0);
    }

    console.log(`🔍 Found ${result.matches.length} match(es):\n`);
    for (const match of result.matches) {
      console.log(
        `  ${match.file}:${match.line}:${match.column} — ${match.rule} → ${match.placeholder} (${match.fingerprint.slice(0, 8)}…)`,
      );
    }
    process.exit(1);
  }

  // command === "redact"
  const outDir = typeof flags.outDir === "string" ? resolve(flags.outDir) : resolve("redacted");
  const mapPath = typeof flags.map === "string" ? resolve(flags.map) : resolve("redactkit-map.json");

  const result = redact({ files: resolvedFiles, outDir, mapPath, rules });

  console.log(`🔒 Redacted ${result.matches.length} match(es) across ${result.written.length} file(s)`);
  console.log(`  Output: ${result.outDir}`);
  console.log(`  Map:    ${result.mapPath}`);
  for (const w of result.written) {
    console.log(`  → ${w}`);
  }
  process.exit(0);
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(err instanceof CliUsageError ? 2 : 1);
});
