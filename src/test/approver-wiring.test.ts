import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newPairing, deriveKey, seal, open, aadForRequest, aadForDecision } from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import { pwaApproverFrom } from "../pwa-approver.js";
import { DEFAULT_CONFIG } from "../config.js";
import type { VaultData } from "../vault.js";
import type { BiometricCredential } from "../webauthn.js";

/**
 * Guards the wiring, not the crypto: enforcement must reach the phone
 * from every entry point. `sandgate test-approval` once built its own
 * approver config and quietly dropped requireBiometric, so an enforced
 * vault still accepted a bare tap. One builder now serves serve() and the
 * CLI, and this test fails if it ever stops enforcing.
 */

const CREDENTIAL: BiometricCredential = {
  credentialId: "unused-for-this-test",
  publicKeySpki: "unused-for-this-test",
  rpId: "localhost",
  origin: "http://localhost",
  enrolledAt: new Date().toISOString(),
};

/** A phone that taps Approve without producing any assertion. */
async function tapWithoutAssertion(relayUrl: string, pairId: string, secret: string) {
  const key = deriveKey(secret);
  for (let i = 0; i < 100; i++) {
    const res = await fetch(`${relayUrl}/api/pending?pairId=${pairId}`);
    const items = (await res.json()) as { requestId: string; payload: any }[];
    if (items.length) {
      const { requestId, payload } = items[0]!;
      const request = open<{ requireBiometric?: boolean }>(key, payload, aadForRequest(requestId));
      await fetch(`${relayUrl}/api/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairId,
          requestId,
          payload: seal(
            key,
            { requestId, approved: true, ts: Date.now() },
            aadForDecision(requestId)
          ),
        }),
      });
      return request;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("phone never saw a request");
}

/** Settle a promise without ever leaving a rejection unhandled. */
function settled<T>(p: Promise<T>): Promise<{ value?: T; error?: unknown }> {
  return p.then(
    (value) => ({ value }),
    (error) => ({ error })
  );
}

async function withRelay<T>(fn: (relayUrl: string) => Promise<T>): Promise<T> {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  try {
    return await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}

test("an enforced vault rejects an approval that carries no assertion", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const vault: VaultData = {
      totp: {},
      pwa: { relayUrl, pairId: pairing.pairId, secret: pairing.secret },
      biometric: CREDENTIAL,
    };
    const approver = pwaApproverFrom(vault, { ...DEFAULT_CONFIG, requireBiometric: true })!;
    const deciding = settled(approver.request({ title: "Pay 300 EUR", timeoutSec: 15 }));
    const request = await tapWithoutAssertion(relayUrl, pairing.pairId, pairing.secret);

    // The phone must be TOLD to ask for biometrics...
    assert.equal(request.requireBiometric, true, "the request did not demand a biometric");
    // ...and a bare tap must not pass for an approval.
    const outcome = await deciding;
    assert.equal(outcome.value, undefined, "a bare tap was accepted as an approval");
    assert.match(String(outcome.error), /without the required biometric assertion/);
  });
});

test("without enforcement, the same tap is a normal approval", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const vault: VaultData = {
      totp: {},
      pwa: { relayUrl, pairId: pairing.pairId, secret: pairing.secret },
    };
    const approver = pwaApproverFrom(vault, { ...DEFAULT_CONFIG, requireBiometric: false })!;
    const deciding = settled(approver.request({ title: "Harmless", timeoutSec: 15 }));
    const request = await tapWithoutAssertion(relayUrl, pairing.pairId, pairing.secret);
    assert.equal(request.requireBiometric, false);
    assert.deepEqual((await deciding).value, { approved: true, decision: "approved" });
  });
});

test("enforcement without an enrolled credential refuses instead of downgrading", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const vault: VaultData = {
      totp: {},
      pwa: { relayUrl, pairId: pairing.pairId, secret: pairing.secret },
    };
    const approver = pwaApproverFrom(vault, { ...DEFAULT_CONFIG, requireBiometric: true })!;
    const deciding = settled(approver.request({ title: "Pay 300 EUR", timeoutSec: 15 }));
    await tapWithoutAssertion(relayUrl, pairing.pairId, pairing.secret);
    const outcome = await deciding;
    assert.equal(outcome.value, undefined, "an unenrolled vault approved anyway");
    assert.match(String(outcome.error), /no credential is enrolled/);
  });
});
