import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRelay } from "../relay/server.js";
import { newPairing } from "../pwacrypto.js";

/**
 * Operating the relay: what an operator watches, what a hostile client
 * hits, and the one static asset the app fetches on demand.
 */

async function withRelay(fn: (url: string) => Promise<void>) {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-relay-")) });
  try {
    await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}

test("metrics count what happened and name nobody", async () => {
  await withRelay(async (url) => {
    const { pairId } = newPairing();
    await fetch(`${url}/api/request`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId, requestId: "req_" + "x".repeat(12), payload: { iv: "a", ct: "b" } }),
    });
    const text = await (await fetch(`${url}/api/metrics`)).text();
    assert.match(text, /^sandgate_relay_requests_total 1$/m);
    assert.match(text, /^sandgate_relay_active_requests 1$/m);
    assert.match(text, /^sandgate_relay_decisions_total 0$/m);
    assert.ok(!text.includes(pairId), "metrics must not carry pair ids");
  });
});

test("one address cannot hammer the relay with invented pair ids", async () => {
  await withRelay(async (url) => {
    // The per-pairing limit is blind to this: every call uses a new id.
    let limited = 0;
    for (let i = 0; i < 260; i++) {
      const { pairId } = newPairing();
      const res = await fetch(`${url}/api/pending?pairId=${pairId}`);
      if (res.status === 429) limited++;
    }
    assert.ok(limited > 0, "the per-address limit must eventually answer 429");
    assert.ok(limited < 60, `limited ${limited} of 260: the limit must be generous to a real client`);
    // Health stays reachable for the uptime check, whatever the client did.
    assert.equal((await fetch(`${url}/api/health`)).status, 200);
    const text = await (await fetch(`${url}/api/metrics`)).text();
    assert.match(text, new RegExp(`^sandgate_relay_rate_limited_total ${limited}$`, "m"));
  });
});

test("the QR decoder is served from our own origin", async () => {
  await withRelay(async (url) => {
    const res = await fetch(`${url}/jsqr.js`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-type") ?? "", /javascript/);
    const body = await res.text();
    assert.ok(body.includes("jsQR"), "the bundled decoder must define jsQR");
    assert.ok(body.length > 100_000, "the whole decoder, not a stub");
  });
});

test("behind a local proxy, X-Forwarded-For tells clients apart", async () => {
  await withRelay(async (url) => {
    // Tests connect from loopback, which IS a local proxy position: the
    // header is honoured there. The rule under test is the predicate,
    // exercised through the limit: two "clients" behind loopback are
    // counted apart, so one of them can be limited while the other is not.
    let limitedA = 0;
    for (let i = 0; i < 250; i++) {
      const res = await fetch(`${url}/api/pending?pairId=${newPairing().pairId}`, {
        headers: { "x-forwarded-for": "203.0.113.5" },
      });
      if (res.status === 429) limitedA++;
    }
    assert.ok(limitedA > 0, "client A must hit the limit");
    const fresh = await fetch(`${url}/api/pending?pairId=${newPairing().pairId}`, {
      headers: { "x-forwarded-for": "203.0.113.6" },
    });
    assert.equal(fresh.status, 200, "client B is a different address and is not limited");
  });
});
