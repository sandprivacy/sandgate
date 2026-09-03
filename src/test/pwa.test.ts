import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  newPairing,
  deriveKey,
  seal,
  open,
  aadForRequest,
  aadForDecision,
} from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import { PwaApprover } from "../pwa-approver.js";

test("seal/open round-trips; tampering and wrong AAD are rejected", () => {
  const { secret } = newPairing();
  const key = deriveKey(secret);
  const sealed = seal(key, { hello: "world" }, aadForRequest("r1"));
  assert.deepEqual(open(key, sealed, aadForRequest("r1")), { hello: "world" });

  assert.throws(() => open(key, sealed, aadForRequest("r2")), /authentication/);
  const tampered = { ...sealed, ct: sealed.ct.slice(0, -4) + "AAAA" };
  assert.throws(() => open(key, tampered, aadForRequest("r1")), /authentication/);
  const otherKey = deriveKey(newPairing().secret);
  assert.throws(() => open(otherKey, sealed, aadForRequest("r1")), /authentication/);
});

/** Plays the phone: polls pending, decrypts, answers. Same crypto as the PWA. */
async function phoneAnswers(
  relayUrl: string,
  pairId: string,
  secret: string,
  approved: boolean
): Promise<{ title: string }> {
  const key = deriveKey(secret);
  for (let i = 0; i < 50; i++) {
    const res = await fetch(`${relayUrl}/api/pending?pairId=${pairId}`);
    const items = (await res.json()) as { requestId: string; payload: any }[];
    if (items.length) {
      const item = items[0];
      const req = open<{ title: string }>(key, item.payload, aadForRequest(item.requestId));
      const decision = seal(
        key,
        { requestId: item.requestId, approved, ts: Date.now() },
        aadForDecision(item.requestId)
      );
      await fetch(`${relayUrl}/api/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId, requestId: item.requestId, payload: decision }),
      });
      return req;
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("phone never saw a pending request");
}

test("full approval round-trip through the relay (approve, deny, timeout)", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const approver = new PwaApprover({
      relayUrl,
      pairId: pairing.pairId,
      secret: pairing.secret,
    });

    // Approve
    const phone1 = phoneAnswers(relayUrl, pairing.pairId, pairing.secret, true);
    const r1 = await approver.request({ title: "Pay 300 EUR", timeoutSec: 10 });
    assert.deepEqual(r1, { approved: true, decision: "approved" });
    assert.equal((await phone1).title, "Pay 300 EUR"); // phone could read the sealed request

    // Deny
    const phone2 = phoneAnswers(relayUrl, pairing.pairId, pairing.secret, false);
    const r2 = await approver.request({ title: "Delete account", timeoutSec: 10 });
    assert.deepEqual(r2, { approved: false, decision: "denied" });
    await phone2;

    // Timeout (nobody answers)
    const r3 = await approver.request({ title: "Silence", timeoutSec: 1 });
    assert.deepEqual(r3, { approved: false, decision: "timeout" });
  } finally {
    relay.close();
  }
});

test("a relay cannot forge an approval (bad blob is rejected, request times out)", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const approver = new PwaApprover({
      relayUrl,
      pairId: pairing.pairId,
      secret: pairing.secret,
    });
    // "Evil relay": answers with a forged decision sealed under the WRONG key.
    const evil = (async () => {
      const wrongKey = deriveKey(newPairing().secret);
      for (let i = 0; i < 50; i++) {
        const res = await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`);
        const items = (await res.json()) as { requestId: string }[];
        if (items.length) {
          const forged = seal(
            wrongKey,
            { requestId: items[0].requestId, approved: true, ts: Date.now() },
            aadForDecision(items[0].requestId)
          );
          await fetch(`${relayUrl}/api/decision`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              pairId: pairing.pairId,
              requestId: items[0].requestId,
              payload: forged,
            }),
          });
          return;
        }
        await new Promise((r) => setTimeout(r, 50));
      }
    })();
    await assert.rejects(
      approver.request({ title: "Forgery target", timeoutSec: 3 }),
      /authentication/
    );
    await evil;
  } finally {
    relay.close();
  }
});
