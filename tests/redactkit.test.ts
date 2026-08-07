import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve, join, relative } from "node:path";
import { scan, redact, builtInRules, cloneRule, fingerprint } from "../src/index.js";
import { PlaceholderMap } from "../src/placeholders.js";
import type { RedactionRule, RedactionMatch, PlaceholderRecord } from "../src/types.js";

const FIXTURES = resolve("fixtures");
const TMP = resolve("tmp-test");

describe("fingerprint", () => {
  it("produces a 12-char hex string", () => {
    const fp = fingerprint("hello");
    assert.equal(fp.length, 12);
    assert.match(fp, /^[0-9a-f]+$/);
  });

  it("is deterministic", () => {
    assert.equal(fingerprint("same"), fingerprint("same"));
  });

  it("differs for different inputs", () => {
    assert.notEqual(fingerprint("alpha"), fingerprint("beta"));
  });
});

describe("builtInRules", () => {
  const allRules = builtInRules as RedactionRule[];

  it("exports 6 default rules", () => {
    const names = allRules.map((r) => r.name);
    assert.deepEqual(names.sort(), ["bearer", "email", "home-path", "ipv4", "token", "url"].sort());
  });

  it("all rules have global flag", () => {
    for (const rule of allRules) {
      assert.match(rule.pattern.flags, /g/, `${rule.name} should be global`);
    }
  });

  it("all rules have source built-in", () => {
    for (const rule of allRules) {
      assert.equal(rule.source, "built-in");
    }
  });
});

describe("cloneRule", () => {
  const allRules = builtInRules as RedactionRule[];

  it("creates a regex with identical source and flags", () => {
    const rule = allRules.find((r) => r.name === "email")!;
    const cloned = cloneRule(rule);
    assert.equal(cloned.pattern.source, rule.pattern.source);
    assert.equal(cloned.pattern.flags, rule.pattern.flags);
  });
});

describe("PlaceholderMap", () => {
  const allRules = builtInRules as RedactionRule[];

  it("generates stable placeholders", () => {
    const map = new PlaceholderMap();
    const emailRule = allRules.find((r) => r.name === "email")!;
    const p1 = map.get(emailRule, "alice@example.com");
    const p2 = map.get(emailRule, "alice@example.com");
    assert.equal(p1, p2);
  });

  it("increments counter per rule", () => {
    const map = new PlaceholderMap();
    const emailRule = allRules.find((r) => r.name === "email")!;
    const p1 = map.get(emailRule, "a@b.com");
    const p2 = map.get(emailRule, "c@d.com");
    assert.notEqual(p1, p2);
    assert.match(p2, /EMAIL_002/);
  });

  it("serializes to JSON", () => {
    const map = new PlaceholderMap();
    const emailRule = allRules.find((r) => r.name === "email")!;
    map.get(emailRule, "test@test.com");
    const json = map.toJSON();
    assert.equal(json.version, 1);
    assert.equal(json.entries.length, 1);
    assert.equal(json.entries[0].rule, "email");
    assert.match(json.entries[0].placeholder, /REDACTED_EMAIL/);
  });

  it("loads existing map and resumes from it", () => {
    const map = new PlaceholderMap();
    const emailRule = allRules.find((r) => r.name === "email")!;
    map.get(emailRule, "test@test.com");
    const existing = map.toJSON();

    const map2 = new PlaceholderMap(existing);
    const p = map2.get(emailRule, "test@test.com");
    assert.equal(p, map.get(emailRule, "test@test.com"));
  });
});

describe("scan — fixture files", () => {
  const allRules = builtInRules as RedactionRule[];

  it("detects secrets in sample.log", () => {
    const result = scan({
      files: [join(FIXTURES, "sample.log")],
      rules: allRules.map(cloneRule),
    });
    assert.ok(result.matches.length > 0, "should find matches");
    const ruleNames = (result.matches as RedactionMatch[]).map((m) => m.rule);
    assert.ok(ruleNames.includes("bearer"), "should detect bearer");
    assert.ok(ruleNames.includes("email"), "should detect email");
    assert.ok(ruleNames.includes("url"), "should detect url");
  });

  it("detects secrets in config.json", () => {
    const result = scan({
      files: [join(FIXTURES, "config.json")],
      rules: allRules.map(cloneRule),
    });
    assert.ok(result.matches.length > 0);
    const ruleNames = (result.matches as RedactionMatch[]).map((m) => m.rule);
    assert.ok(ruleNames.includes("email"), "should detect email");
    assert.ok(ruleNames.includes("url"), "should detect url");
    assert.ok(ruleNames.includes("home-path"), "should detect home-path");
    assert.ok(ruleNames.includes("ipv4"), "should detect ipv4");
  });

  it("finds no secrets in clean.txt", () => {
    const result = scan({
      files: [join(FIXTURES, "clean.txt")],
      rules: allRules.map(cloneRule),
    });
    assert.equal(result.matches.length, 0);
  });

  it("reports line and column", () => {
    const result = scan({
      files: [join(FIXTURES, "sample.log")],
      rules: allRules.map(cloneRule),
    });
    for (const m of result.matches as RedactionMatch[]) {
      assert.ok(m.line > 0, `line should be > 0 for ${m.rule}`);
      assert.ok(m.column > 0, `column should be > 0 for ${m.rule}`);
    }
  });

  it("includes fingerprints", () => {
    const result = scan({
      files: [join(FIXTURES, "sample.log")],
      rules: allRules.map(cloneRule),
    });
    for (const m of result.matches as RedactionMatch[]) {
      assert.equal(m.fingerprint.length, 12);
    }
  });

  it("handles multiple files", () => {
    const result = scan({
      files: [join(FIXTURES, "sample.log"), join(FIXTURES, "config.json")],
      rules: allRules.map(cloneRule),
    });
    assert.equal(result.files.length, 2);
    assert.ok(result.matches.length > 0);
  });
});

describe("redact — fixture files", () => {
  const allRules = builtInRules as RedactionRule[];

  before(() => {
    rmSync(TMP, { recursive: true, force: true });
  });

  after(() => {
    rmSync(TMP, { recursive: true, force: true });
  });

  it("creates redacted output", () => {
    const result = redact({
      files: [join(FIXTURES, "sample.log")],
      outDir: join(TMP, "redact-1"),
      mapPath: join(TMP, "redact-1-map.json"),
      rules: allRules.map(cloneRule),
    });

    assert.equal(result.written.length, 1);
    assert.ok(existsSync(result.written[0]));
    assert.ok(existsSync(result.mapPath));

    const content = readFileSync(result.written[0], "utf8");
    assert.ok(!content.includes("Bearer eyJ"));
    assert.ok(!content.includes("developer@example.com"));
    assert.match(content, /REDACTED_BEARER/);
    assert.match(content, /REDACTED_EMAIL/);
  });

  it("creates map file matching format", () => {
    const result = redact({
      files: [join(FIXTURES, "sample.log")],
      outDir: join(TMP, "redact-2"),
      mapPath: join(TMP, "redact-2-map.json"),
      rules: allRules.map(cloneRule),
    });

    const map = JSON.parse(readFileSync(result.mapPath, "utf8"));
    assert.equal(map.version, 1);
    assert.ok(Array.isArray(map.entries));
    assert.ok(map.entries.length > 0);
  });

  it("redaction is deterministic across runs", () => {
    const outDir1 = join(TMP, "redact-3a");
    const outDir2 = join(TMP, "redact-3b");
    const file = join(FIXTURES, "sample.log");
    const rules = allRules.map(cloneRule);

    const r1 = redact({ files: [file], outDir: outDir1, mapPath: outDir1 + "-map.json", rules });
    const r2 = redact({ files: [file], outDir: outDir2, mapPath: outDir2 + "-map.json", rules });

    const c1 = readFileSync(r1.written[0], "utf8");
    const c2 = readFileSync(r2.written[0], "utf8");
    assert.equal(c1, c2);
  });

  it("handles config.json with nested secrets", () => {
    const result = redact({
      files: [join(FIXTURES, "config.json")],
      outDir: join(TMP, "redact-4"),
      mapPath: join(TMP, "redact-4-map.json"),
      rules: allRules.map(cloneRule),
    });

    const content = readFileSync(result.written[0], "utf8");
    const parsed = JSON.parse(content) as { config: { token: string; server: string } };
    assert.ok(!content.includes("alice@internal.corp"));
    assert.ok(!content.includes("staging.internal.corp"));
    assert.ok(!content.includes("ghp_ABC123"));
    assert.match(parsed.config.token, /^<REDACTED_TOKEN_\d{3}>$/);
    assert.equal(typeof parsed.config.server, "string");
  });

  it("handles http-request fixture", () => {
    const result = redact({
      files: [join(FIXTURES, "http-request.txt")],
      outDir: join(TMP, "redact-5"),
      mapPath: join(TMP, "redact-5-map.json"),
      rules: allRules.map(cloneRule),
    });

    const content = readFileSync(result.written[0], "utf8");
    assert.ok(!content.includes("ghp_REALTOKEN"));
    assert.match(content, /REDACTED_BEARER/);
  });

  it("writes all files to outDir", () => {
    const outDir = join(TMP, "redact-6");
    const result = redact({
      files: [join(FIXTURES, "sample.log"), join(FIXTURES, "config.json")],
      outDir,
      mapPath: outDir + "-map.json",
      rules: allRules.map(cloneRule),
    });

    assert.equal(result.written.length, 2);
    assert.ok(existsSync(join(outDir, "sample.log")));
    assert.ok(existsSync(join(outDir, "config.json")));
  });

  it("preserves relative paths when input basenames collide", () => {
    const inputDir = join(TMP, "redact-collision-input");
    const outDir = join(TMP, "redact-collision-output");
    const firstFile = join(inputDir, "first", "app.log");
    const secondFile = join(inputDir, "second", "app.log");
    mkdirSync(join(inputDir, "first"), { recursive: true });
    mkdirSync(join(inputDir, "second"), { recursive: true });
    writeFileSync(firstFile, "first: alice@example.com\n", "utf8");
    writeFileSync(secondFile, "second: bob@example.com\n", "utf8");

    const result = redact({
      files: [firstFile, secondFile],
      outDir,
      mapPath: outDir + "-map.json",
      rules: allRules.map(cloneRule),
    });

    const firstOutput = join(outDir, "first", "app.log");
    const secondOutput = join(outDir, "second", "app.log");
    assert.deepEqual(result.written, [firstOutput, secondOutput]);
    assert.match(readFileSync(firstOutput, "utf8"), /^first: <REDACTED_EMAIL_001>$/m);
    assert.match(readFileSync(secondOutput, "utf8"), /^second: <REDACTED_EMAIL_002>$/m);
  });

  for (const collision of ["output", "map"] as const) {
    it(`rejects a resolved ${collision} path that aliases an input before writing`, () => {
      const testDir = join(TMP, `redact-input-${collision}-collision`);
      const input = join(testDir, "input.txt");
      const outDir = collision === "output" ? testDir : join(testDir, "out");
      const mapPath = collision === "map" ? resolve(testDir, ".", "input.txt") : join(testDir, "map.json");
      const original = "contact: alice@example.com\n";
      mkdirSync(testDir, { recursive: true });
      writeFileSync(input, original, "utf8");

      assert.throws(
        () =>
          redact({
            files: [relative(process.cwd(), input)],
            outDir,
            mapPath,
            rules: allRules.map(cloneRule),
          }),
        new RegExp(`${collision} path aliases an input file`, "i"),
      );
      assert.equal(readFileSync(input, "utf8"), original);
      assert.equal(existsSync(join(testDir, "out")), false);
      assert.equal(existsSync(join(testDir, "map.json")), false);
    });
  }
});

describe("redact — with custom rules", () => {
  const allRules = builtInRules as RedactionRule[];

  it("applies custom rules alongside built-in", () => {
    const testDir = join(TMP, "redact-custom-1");
    mkdirSync(testDir, { recursive: true });
    const testFile = join(testDir, "orders.txt");
    writeFileSync(testFile, "Order ORD-ABC123 placed by user@example.com\nOrder ORD-DEF456 confirmed", "utf8");

    const customRules: RedactionRule[] = [
      {
        name: "order-id",
        description: "Internal order identifiers",
        pattern: /ORD-[A-Z0-9]{6}/g,
        placeholder: "ORDER_ID",
        source: "custom",
      },
    ];
    const rules = [...allRules.map(cloneRule), ...customRules];

    const result = redact({
      files: [testFile],
      outDir: join(TMP, "redact-custom-out"),
      mapPath: join(TMP, "redact-custom-map.json"),
      rules,
    });

    const content = readFileSync(result.written[0], "utf8");
    assert.ok(!content.includes("ORD-ABC123"));
    assert.ok(!content.includes("user@example.com"));
    assert.match(content, /REDACTED_ORDER_ID/);
    assert.match(content, /REDACTED_EMAIL/);
  });

  it("applies every match from a non-global custom rule", () => {
    const testDir = join(TMP, "redact-custom-non-global");
    const testFile = join(testDir, "tickets.txt");
    mkdirSync(testDir, { recursive: true });
    writeFileSync(testFile, "SUP-100001 and SUP-100002", "utf8");
    const rule: RedactionRule = {
      name: "ticket",
      description: "Support ticket",
      pattern: /SUP-[0-9]{6}/i,
      placeholder: "TICKET",
      source: "custom",
    };

    const scanResult = scan({ files: [testFile], rules: [rule] });
    assert.equal(scanResult.matches.length, 2);

    const result = redact({
      files: [testFile],
      outDir: join(TMP, "redact-custom-non-global-out"),
      mapPath: join(TMP, "redact-custom-non-global-map.json"),
      rules: [rule],
    });
    assert.equal(result.matches.length, 2);
    assert.equal(
      readFileSync(result.written[0], "utf8"),
      "<REDACTED_TICKET_001> and <REDACTED_TICKET_002>",
    );
  });

  it("preserves assignment context and reports the captured value position", () => {
    const testDir = join(TMP, "redact-custom-capture");
    const testFile = join(testDir, "input.txt");
    mkdirSync(testDir, { recursive: true });
    writeFileSync(testFile, "header\napi_key = secret-value-123\n", "utf8");
    const rule: RedactionRule = {
      name: "api-key",
      description: "API key assignment",
      pattern: /api_key\s*=\s*(secret-[a-z]+-[0-9]+)/,
      placeholder: "API_KEY",
      source: "custom",
    };

    const scanResult = scan({ files: [testFile], rules: [rule] });
    assert.deepEqual(
      { line: scanResult.matches[0].line, column: scanResult.matches[0].column },
      { line: 2, column: 11 },
    );

    const result = redact({
      files: [testFile],
      outDir: join(TMP, "redact-custom-capture-out"),
      mapPath: join(TMP, "redact-custom-capture-map.json"),
      rules: [rule],
    });
    assert.equal(readFileSync(result.written[0], "utf8"), "header\napi_key = <REDACTED_API_KEY_001>\n");
  });

  it("keeps the rightmost replacement when captured spans overlap", () => {
    const testDir = join(TMP, "redact-custom-overlap");
    const testFile = join(testDir, "input.txt");
    mkdirSync(testDir, { recursive: true });
    writeFileSync(testFile, "token=secret-value", "utf8");
    const rules: RedactionRule[] = [
      {
        name: "token",
        description: "Token value",
        pattern: /token=(secret-value)/,
        placeholder: "TOKEN",
        source: "custom",
      },
      {
        name: "suffix",
        description: "Overlapping suffix",
        pattern: /secret-(value)/,
        placeholder: "SUFFIX",
        source: "custom",
      },
    ];

    const result = redact({
      files: [testFile],
      outDir: join(TMP, "redact-custom-overlap-out"),
      mapPath: join(TMP, "redact-custom-overlap-map.json"),
      rules,
    });
    assert.equal(readFileSync(result.written[0], "utf8"), "token=secret-<REDACTED_SUFFIX_001>");
  });

  it("finishes scan and redact for a zero-length custom rule", () => {
    const testDir = join(TMP, "redact-custom-empty");
    const testFile = join(testDir, "input.txt");
    mkdirSync(testDir, { recursive: true });
    writeFileSync(testFile, "ab", "utf8");
    const rule: RedactionRule = {
      name: "boundary",
      description: "Empty boundary",
      pattern: /(?=.)/,
      placeholder: "BOUNDARY",
      source: "custom",
    };

    const scanResult = scan({ files: [testFile], rules: [rule] });
    assert.equal(scanResult.matches.length, 2);

    const result = redact({
      files: [testFile],
      outDir: join(TMP, "redact-custom-empty-out"),
      mapPath: join(TMP, "redact-custom-empty-map.json"),
      rules: [rule],
    });
    assert.equal(result.matches.length, 2);
    assert.equal(
      readFileSync(result.written[0], "utf8"),
      "<REDACTED_BOUNDARY_001>a<REDACTED_BOUNDARY_001>b",
    );
  });
});

describe("stable mapping — same value gets same placeholder", () => {
  const allRules = builtInRules as RedactionRule[];

  it("same email across files gets same placeholder within one call", () => {
    const testDir = join(TMP, "mapping-1");
    mkdirSync(testDir, { recursive: true });
    const f1 = join(testDir, "a.txt");
    const f2 = join(testDir, "b.txt");
    writeFileSync(f1, "contact: user@test.com for help", "utf8");
    writeFileSync(f2, "sent to user@test.com yesterday", "utf8");

    const result = redact({
      files: [f1, f2],
      outDir: join(TMP, "mapping-out"),
      mapPath: join(TMP, "mapping-map.json"),
      rules: allRules.map(cloneRule),
    });

    const map = JSON.parse(readFileSync(result.mapPath, "utf8"));
    const entries = (map.entries as unknown as PlaceholderRecord[]).filter((e) => e.rule === "email");
    assert.equal(entries.length, 1);
    assert.equal(entries[0].value, "user@test.com");
  });
});

describe("cli — custom rule files", () => {
  it("redacts example support tickets through --rules", () => {
    const outDir = join(TMP, "cli-custom-out");
    const mapPath = join(TMP, "cli-custom-map.json");
    rmSync(outDir, { recursive: true, force: true });
    rmSync(mapPath, { force: true });

    execFileSync(
      process.execPath,
      [
        "dist/src/cli.js",
        "redact",
        "examples/support-transcript.txt",
        "--rules",
        "examples/custom-rules.json",
        "--out-dir",
        outDir,
        "--map",
        mapPath,
      ],
      { encoding: "utf8" },
    );

    const output = readFileSync(join(outDir, "support-transcript.txt"), "utf8");
    assert.ok(!output.includes("SUP-104221"));
    assert.match(output, /REDACTED_TICKET/);

    const map = JSON.parse(readFileSync(mapPath, "utf8"));
    const ticketEntry = (map.entries as PlaceholderRecord[]).find((entry) => entry.rule === "internal-ticket");
    assert.equal(ticketEntry?.value, "SUP-104221");
  });

  for (const testCase of [
    { name: "non-global", pattern: "SUP-[0-9]{6}", flags: "i", expected: 2 },
    { name: "zero-length", pattern: "(?=.)", flags: "", expected: 21 },
  ]) {
    it(`finishes scan and redact for a ${testCase.name} rule`, () => {
      const testDir = join(TMP, `cli-custom-${testCase.name}`);
      const input = join(testDir, "input.txt");
      const rules = join(testDir, "rules.json");
      const outDir = join(testDir, "out");
      const mapPath = join(testDir, "map.json");
      mkdirSync(testDir, { recursive: true });
      writeFileSync(input, "SUP-100001 SUP-100002", "utf8");
      writeFileSync(
        rules,
        JSON.stringify({
          rules: [
            {
              name: testCase.name,
              pattern: testCase.pattern,
              flags: testCase.flags,
              placeholder: "CUSTOM",
            },
          ],
        }),
        "utf8",
      );

      const scanResult = spawnSync(
        process.execPath,
        ["dist/src/cli.js", "scan", input, "--rules", rules],
        { encoding: "utf8", timeout: 2_000 },
      );
      assert.equal(scanResult.error, undefined);
      assert.equal(scanResult.status, 1, scanResult.stderr);
      assert.match(scanResult.stdout, new RegExp(`Found ${testCase.expected} match\\(es\\)`));

      const redactResult = spawnSync(
        process.execPath,
        [
          "dist/src/cli.js",
          "redact",
          input,
          "--rules",
          rules,
          "--out-dir",
          outDir,
          "--map",
          mapPath,
        ],
        { encoding: "utf8", timeout: 2_000 },
      );
      assert.equal(redactResult.error, undefined);
      assert.equal(redactResult.status, 0, redactResult.stderr);
      assert.match(redactResult.stdout, new RegExp(`Redacted ${testCase.expected} match\\(es\\)`));
      assert.ok(existsSync(join(outDir, "input.txt")));
    });
  }
});

describe("cli — option validation", () => {
  function runCli(args: string[]) {
    return spawnSync(process.execPath, ["dist/src/cli.js", ...args], { encoding: "utf8" });
  }

  for (const option of ["--out-dir", "--map", "--rules"]) {
    it(`rejects ${option} without a value`, () => {
      const result = runCli(["redact", "fixtures/sample.log", option]);

      assert.equal(result.status, 2);
      assert.match(result.stderr, new RegExp(`Option ${option} requires a value`));
    });
  }

  it("rejects a value-taking option followed by another option", () => {
    const result = runCli(["redact", "fixtures/sample.log", "--out-dir", "--map", "map.json"]);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /Option --out-dir requires a value/);
  });

  it("rejects unknown options", () => {
    const result = runCli(["scan", "fixtures/clean.txt", "--bogus"]);

    assert.equal(result.status, 2);
    assert.match(result.stderr, /Unknown option: --bogus/);
  });

  it("accepts options before and after file operands", () => {
    const outDir = join(TMP, "cli-order-out");
    const mapPath = join(TMP, "cli-order-map.json");
    const result = runCli([
      "--out-dir",
      outDir,
      "redact",
      "fixtures/sample.log",
      "--map",
      mapPath,
    ]);

    assert.equal(result.status, 0, result.stderr);
    assert.ok(existsSync(join(outDir, "sample.log")));
    assert.ok(existsSync(mapPath));
  });

  for (const collision of ["output", "map"] as const) {
    it(`rejects a ${collision} path collision atomically`, () => {
      const testDir = join(TMP, `cli-${collision}-collision`);
      const input = join(testDir, "input.txt");
      const outDir = collision === "output" ? testDir : join(testDir, "out");
      const mapPath = collision === "map" ? input : join(testDir, "map.json");
      const original = "contact: alice@example.com\n";
      mkdirSync(testDir, { recursive: true });
      writeFileSync(input, original, "utf8");

      const result = runCli([
        "redact",
        relative(process.cwd(), input),
        "--out-dir",
        outDir,
        "--map",
        mapPath,
      ]);

      assert.equal(result.status, 1);
      assert.match(result.stderr, new RegExp(`${collision} path aliases an input file`, "i"));
      assert.equal(readFileSync(input, "utf8"), original);
      assert.equal(existsSync(join(testDir, "out")), false);
      assert.equal(existsSync(join(testDir, "map.json")), false);
    });
  }
});
