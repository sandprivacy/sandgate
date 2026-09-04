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

test("SSE stream announces new requests to listening pages", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const res = await fetch(`${relayUrl}/api/events?pairId=${pairing.pairId}`);
    assert.equal(res.headers.get("content-type"), "text/event-stream");
    const reader = res.body!.getReader();

    const approver = new PwaApprover({
      relayUrl,
      pairId: pairing.pairId,
      secret: pairing.secret,
    });
    const pendingRequest = approver
      .request({ title: "SSE ping", timeoutSec: 1 })
      .catch(() => {});

    let streamed = "";
    const deadline = Date.now() + 5000;
    while (!streamed.includes("event: request") && Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      streamed += new TextDecoder().decode(value);
    }
    assert.ok(streamed.includes("event: request"), `stream was: ${streamed}`);
    reader.cancel();
    await pendingRequest;
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

test("a pairing cannot flood the phone with approval requests", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const key = deriveKey(pairing.secret);
    const post = (i: number) =>
      fetch(`${relayUrl}/api/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairId: pairing.pairId,
          requestId: `flood${i}${"x".repeat(8)}`,
          payload: seal(key, { title: "spam" }, aadForRequest(`flood${i}${"x".repeat(8)}`)),
        }),
      });

    // A handful of pending requests is normal; a flood is not.
    const codes: number[] = [];
    for (let i = 0; i < 12; i++) codes.push((await post(i)).status);
    assert.ok(codes.includes(429), `no request was ever refused: ${codes.join(",")}`);
    assert.equal(codes[0], 200, "the first request must still go through");
  } finally {
    relay.close();
  }
});
