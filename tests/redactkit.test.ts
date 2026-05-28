import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, rmSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
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
    assert.ok(!content.includes("alice@internal.corp"));
    assert.ok(!content.includes("staging.internal.corp"));
    assert.ok(!content.includes("ghp_ABC123"));
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
