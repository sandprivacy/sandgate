import { test } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectPassphraseDpapi, dpapiDecryptCommand } from "../passphrase.js";

// DPAPI is Windows-only; the CI matrix covers both, so skip cleanly elsewhere.
const windowsOnly = { skip: process.platform !== "win32" };

test("DPAPI protect/decrypt round-trips the passphrase", windowsOnly, () => {
  const file = join(mkdtempSync(join(tmpdir(), "sandgate-dpapi-")), "pass.dpapi");
  protectPassphraseDpapi("correct horse battery staple", file);
  const decrypted = execSync(dpapiDecryptCommand(file), { encoding: "utf8" }).trim();
  assert.equal(decrypted, "correct horse battery staple");
});

test("protect refuses on non-Windows platforms", { skip: process.platform === "win32" }, () => {
  assert.throws(() => protectPassphraseDpapi("x", "/tmp/x"), /Windows-only/);
});
