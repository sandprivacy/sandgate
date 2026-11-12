import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { SERVER_VERSION, VERSION } from "../version.js";

test("the compiled-in version matches package.json", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));
  assert.equal(VERSION, pkg.version, "bump src/version.ts together with package.json");
});

test("the server version is a real release, never ahead of this one", () => {
  const parts = (v: string) => v.split(".").map(Number);
  const [a, b] = [parts(SERVER_VERSION), parts(VERSION)];
  assert.equal(a.length, 3);
  assert.ok(a.every(Number.isInteger));
  const cmp = a[0]! - b[0]! || a[1]! - b[1]! || a[2]! - b[2]!;
  assert.ok(cmp <= 0, `SERVER_VERSION ${SERVER_VERSION} is above VERSION ${VERSION}`);
});
