import { test } from "node:test";
import assert from "node:assert/strict";
import { extractVerification } from "../extract.js";

test("extracts a code near a context word", () => {
  const r = extractVerification(
    "Welcome",
    "Hello,\nYour verification code is 482913. It expires in 10 minutes."
  );
  assert.equal(r.code, "482913");
});

test("extracts a code from the subject", () => {
  const r = extractVerification("Your code is 774412", "See subject.");
  assert.equal(r.code, "774412");
});

test("extracts a standalone code on its own line", () => {
  const r = extractVerification("Sign in", "Use this to sign in:\n\n  90311258  \n\nThanks");
  assert.equal(r.code, "90311258");
});

test("does not mistake years or amounts for codes without context", () => {
  const r = extractVerification(
    "Invoice",
    "Your invoice for 2026 totals 149 euros. Thanks for your order."
  );
  assert.equal(r.code, null);
});

test("collects verification links", () => {
  const r = extractVerification(
    "Confirm your address",
    "Click https://example.com/verify?token=abc123 to continue.\n" +
      "Unsubscribe: https://example.com/unsubscribe"
  );
  assert.deepEqual(r.links, ["https://example.com/verify?token=abc123"]);
});

test("french verification emails work too", () => {
  const r = extractVerification(
    "Confirmation",
    "Votre code de vérification est 552901."
  );
  assert.equal(r.code, "552901");
});
