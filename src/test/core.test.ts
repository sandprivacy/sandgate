import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Point sandgate at a throwaway home before importing modules that use it.
process.env.SANDGATE_HOME = mkdtempSync(join(tmpdir(), "sandgate-test-"));

const { saveVault, loadVault, rekeyVault } = await import("../vault.js");
const { generateCode, normalizeSecret } = await import("../totp.js");
const { loadConfig, saveConfig, totpPolicy } = await import("../config.js");

test("vault round-trips and rejects a wrong passphrase", () => {
  const data = {
    totp: { "github.com": { secret: "JBSWY3DPEHPK3PXP" } },
    sandmail: { apiKey: "sk_test" },
  };
  saveVault("correct horse", data);
  assert.deepEqual(loadVault("correct horse"), data);
  assert.throws(() => loadVault("wrong"), /wrong passphrase/);
});

test("rekey re-encrypts under the new passphrase and retires the old one", () => {
  const data = { totp: { "site.com": { secret: "JBSWY3DPEHPK3PXP" } } };
  saveVault("old-pass", data);
  rekeyVault("old-pass", "new-pass");
  assert.deepEqual(loadVault("new-pass"), data);
  assert.throws(() => loadVault("old-pass"), /wrong passphrase/);
  assert.throws(() => rekeyVault("old-pass", "whatever"), /wrong passphrase/);
});

test("totp generates stable 6-digit codes", () => {
  const a = generateCode("JBSWY3DPEHPK3PXP");
  const b = generateCode("JBSWY3DPEHPK3PXP");
  assert.match(a.code, /^\d{6}$/);
  assert.equal(a.code, b.code); // same 30s window
  assert.ok(a.secondsRemaining >= 1 && a.secondsRemaining <= 30);
});

test("normalizeSecret handles spaces, dashes, case and otpauth URIs", () => {
  assert.equal(normalizeSecret("jbsw y3dp-ehpk 3pxp"), "JBSWY3DPEHPK3PXP");
  assert.equal(
    normalizeSecret(
      "otpauth://totp/GitHub:user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
    ),
    "JBSWY3DPEHPK3PXP"
  );
});

test("policies default to approve for 2FA and honor overrides", () => {
  const config = loadConfig();
  assert.equal(totpPolicy(config, "github.com"), "approve");
  config.policies.totp["github.com"] = "auto";
  saveConfig(config);
  assert.equal(totpPolicy(loadConfig(), "github.com"), "auto");
});
