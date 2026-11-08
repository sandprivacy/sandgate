import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { VERSION } from "../version.js";

test("the compiled-in version matches package.json", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  assert.equal(VERSION, pkg.version, "bump src/version.ts together with package.json");
});
