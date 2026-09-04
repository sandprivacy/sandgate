import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRelay } from "../relay/server.js";
import { PwaApprover } from "../pwa-approver.js";
import { newPairing, deriveKey, seal, open, aadForRequest, aadForDecision } from "../pwacrypto.js";

/**
 * Several phones, one decision. The relay collects sealed answers; the
 * gateway counts distinct devices and stops at the first refusal. These
 * are the rules a team relies on, so each one is pinned.
 */

async function withRelay(fn: (url: string) => Promise<void>) {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-relay-")) });
  try {
    await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}

/** A phone: waits for the request, checks what it says, answers as told. */
async function phone(
  relayUrl: string,
  pairing: { pairId: string; secret: string },
  deviceId: string | undefined,
  approved: boolean
): Promise<{ quorum: number; shown: number; needed: number }> {
  const key = deriveKey(pairing.secret);
  for (let i = 0; i < 200; i++) {
    const items = (await (await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`)).json()) as {
      requestId: string;
      payload: any;
      decisions: number;
      needed: number;
    }[];
    if (items.length) {
      const item = items[0]!;
      const req = open<any>(key, item.payload, aadForRequest(item.requestId));
      await fetch(`${relayUrl}/api/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairId: pairing.pairId,
          requestId: item.requestId,
          payload: seal(
            key,
            { requestId: item.requestId, approved, ts: Date.now(), ...(deviceId ? { deviceId } : {}) },
            aadForDecision(item.requestId)
          ),
        }),
      });
      return { quorum: req.quorum, shown: item.decisions, needed: item.needed };
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("no request reached the phone");
}

test("two devices must both approve; one alone is silence", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const approver = new PwaApprover({ relayUrl, ...pairing, quorum: 2 });

    // Both say yes.
    const both = approver.request({ title: "Deploy to prod", timeoutSec: 10 });
    const first = await phone(relayUrl, pairing, "phone-A", true);
    assert.equal(first.quorum, 2, "the sealed request tells the phone how many must agree");
    assert.equal(first.needed, 2, "the relay knows how many answers to collect");
    const second = await phone(relayUrl, pairing, "phone-B", true);
    assert.equal(second.shown, 1, "the second phone sees one approval already in");
    assert.deepEqual(await both, { approved: true, decision: "approved" });

    // Only one says yes: not enough, so nothing happens.
    const alone = approver.request({ title: "Deploy to prod", timeoutSec: 3 });
    await phone(relayUrl, pairing, "phone-A", true);
    assert.deepEqual(await alone, { approved: false, decision: "timeout" });
  });
});

test("one refusal is final, whoever else approved", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const approver = new PwaApprover({ relayUrl, ...pairing, quorum: 2 });
    const pending = approver.request({ title: "Wire $50k", timeoutSec: 10 });
    await phone(relayUrl, pairing, "phone-A", true);
    await phone(relayUrl, pairing, "phone-B", false);
    assert.deepEqual(await pending, { approved: false, decision: "denied" });
  });
});

test("one device tapping twice is still one device", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const approver = new PwaApprover({ relayUrl, ...pairing, quorum: 2 });
    const pending = approver.request({ title: "Rotate keys", timeoutSec: 3 });
    await phone(relayUrl, pairing, "phone-A", true);
    await phone(relayUrl, pairing, "phone-A", true);
    assert.deepEqual(await pending, { approved: false, decision: "timeout" });

    // Apps from before quorums send no device id: they count as ONE
    // anonymous device between them, never as a quorum on their own.
    const legacy = approver.request({ title: "Rotate keys", timeoutSec: 3 });
    await phone(relayUrl, pairing, undefined, true);
    await phone(relayUrl, pairing, undefined, true);
    assert.deepEqual(await legacy, { approved: false, decision: "timeout" });
  });
});

test("with the default quorum nothing changes: first tap wins, request disappears", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const approver = new PwaApprover({ relayUrl, ...pairing });
    const pending = approver.request({ title: "Plain approval", timeoutSec: 10 });
    const seen = await phone(relayUrl, pairing, "phone-A", true);
    assert.equal(seen.quorum, 1);
    assert.deepEqual(await pending, { approved: true, decision: "approved" });
    const left = (await (await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`)).json()) as unknown[];
    assert.deepEqual(left, [], "an answered request must not linger on the phone");
  });
});
