import { test } from "node:test";
import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectPassphraseDpapi, dpapiDecryptCommand } from "../passphrase.js";

// DPAPI is Windows-only; the CI matrix covers both, so skip cleanly elsewhere.
// And some Windows environments (GitHub's hosted runners, for one) ship a
// PowerShell that cannot load Microsoft.PowerShell.Security at all: DPAPI
// is then unavailable to anyone, not broken in sandgate. Probe first.
function dpapiAvailable(): boolean {
  if (process.platform !== "win32") return false;
  try {
    const out = execSync(
      'powershell -NoProfile -NonInteractive -Command "Import-Module Microsoft.PowerShell.Security; ConvertTo-SecureString -String x -AsPlainText -Force | Out-Null; Write-Output ok"',
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 30_000 }
    );
    return out.trim() === "ok";
  } catch {
    return false;
  }
}
const windowsOnly = {
  skip: process.platform !== "win32" ? "DPAPI is Windows-only" : dpapiAvailable() ? false : "DPAPI unavailable in this environment",
};

test("DPAPI protect/decrypt round-trips the passphrase", windowsOnly, () => {
  const file = join(mkdtempSync(join(tmpdir(), "sandgate-dpapi-")), "pass.dpapi");
  protectPassphraseDpapi("correct horse battery staple", file);
  const decrypted = execSync(dpapiDecryptCommand(file), { encoding: "utf8" }).trim();
  assert.equal(decrypted, "correct horse battery staple");
});

test("protect refuses on non-Windows platforms", { skip: process.platform === "win32" }, () => {
  assert.throws(() => protectPassphraseDpapi("x", "/tmp/x"), /Windows-only/);
});
