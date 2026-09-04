import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  newPairing,
  newClaimSecret,
  sealClaim,
  openClaim,
  pairingLink,
  publishClaim,
} from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";

/**
 * A pairing link used to BE the secret: anyone who found it, whenever,
 * could read and answer every approval. Now it is a one-time claim on a
 * blob the relay hands out once and forgets. These tests are the
 * contract: single use, short life, unreadable to the relay.
 */

test("a claim opens with its secret and with nothing else", () => {
  const { pairId, secret } = newPairing();
  const claim = newClaimSecret();
  const sealed = sealClaim(claim, pairId, { secret, name: "laptop" });

  assert.deepEqual(openClaim(claim, pairId, sealed), { secret, name: "laptop" });
  assert.throws(() => openClaim(newClaimSecret(), pairId, sealed), /authentication/);
  // Bound to its pair id: a blob cannot be re-homed onto another pairing.
  assert.throws(() => openClaim(claim, newPairing().pairId, sealed), /authentication/);
});

test("the link carries the claim, never the channel secret", () => {
  const { pairId, secret } = newPairing();
  const claim = newClaimSecret();
  const link = pairingLink("https://relay.example/", pairId, claim, "vps prod");
  assert.equal(link, `https://relay.example/#p=${pairId}&c=${claim}&n=vps%20prod`);
  assert.ok(!link.includes(secret), "the channel secret must not be in the link");
});

test("the relay hands a claim out exactly once", async () => {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-relay-")) });
  const url = `http://localhost:${relay.port}`;
  try {
    const { pairId, secret } = newPairing();
    const claim = newClaimSecret();
    await publishClaim(url, pairId, sealClaim(claim, pairId, { secret }));

    const status = async () =>
      (await (await fetch(`${url}/api/pair-status?pairId=${pairId}`)).json()) as {
        claimed: boolean;
        claimPending: boolean;
      };
    assert.deepEqual(await status(), { subscribed: false, seen: false, claimed: false, claimPending: true });

    const first = await fetch(`${url}/api/claim?pairId=${pairId}`);
    assert.equal(first.status, 200);
    const { payload } = (await first.json()) as { payload: any };
    assert.equal(openClaim(claim, pairId, payload).secret, secret);

    // Second reader — the person who found the link later — gets nothing.
    const second = await fetch(`${url}/api/claim?pairId=${pairId}`);
    assert.equal(second.status, 404);
    assert.deepEqual(await status(), { subscribed: false, seen: false, claimed: true, claimPending: false });
  } finally {
    relay.close();
  }
});

test("an unclaimed link dies on its own", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sg-relay-")),
    claimTtlMs: 200,
  });
  const url = `http://localhost:${relay.port}`;
  try {
    const { pairId, secret } = newPairing();
    const claim = newClaimSecret();
    await publishClaim(url, pairId, sealClaim(claim, pairId, { secret }));
    await new Promise((r) => setTimeout(r, 350));
    const late = await fetch(`${url}/api/claim?pairId=${pairId}`);
    assert.equal(late.status, 404, "ten minutes later (here: 200ms) the blob must be gone");
  } finally {
    relay.close();
  }
});
