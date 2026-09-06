import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

test("the packaged CLI reports its version on the minimum supported Node release", () => {
  const output = execFileSync(
    "npx",
    ["--yes", "--package=node@20.10.0", "node", "dist/src/cli.js", "--version"],
    { encoding: "utf8" },
  );

  assert.equal(output.trim(), "0.1.0");
});
