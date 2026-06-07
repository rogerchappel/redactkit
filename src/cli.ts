#!/usr/bin/env node
import { resolve, join } from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { redact, scan, builtInRules, cloneRule } from "./redact.js";
import type { RedactionRule, SerializableRule } from "./types.js";

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
      flags[flagKeyMap[key] || key] = args[++i] as string;
      continue;
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
  const content = readFileSync(path, "utf8");
  const parsed = JSON.parse(content) as { rules?: SerializableRule[] };
  if (!parsed.rules || !Array.isArray(parsed.rules)) {
    throw new Error(`Invalid rule file: expected { "rules": [...] } in ${path}`);
  }

  return parsed.rules.map((r) => ({
    name: r.name,
    description: r.description ?? "Custom rule from file",
    pattern: new RegExp(r.pattern, r.flags ?? "g"),
    placeholder: r.placeholder ?? "CUSTOM",
    source: "custom" as const,
  }));
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
  process.exit(1);
});
