import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";

test("the package declares and runs on its minimum supported Node release", () => {
  const { engines } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(engines.node, ">=20.10.0");

  const output = execFileSync(
    "npx",
    ["--yes", "--package=node@20.10.0", "node", "dist/src/cli.js", "--version"],
    { encoding: "utf8" },
  );

  assert.equal(output.trim(), "0.1.0");
});
