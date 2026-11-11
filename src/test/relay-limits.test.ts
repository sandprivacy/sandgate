import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startRelay, clientAddress, inRange } from "../relay/server.js";
import { newPairing, deriveKey, seal, aadForDecision } from "../pwacrypto.js";
import { PwaApprover } from "../pwa-approver.js";

/**
 * The 429s seen on a real phone: the relay had refused 8272 calls against
 * 614 requests. Behind Cloudflare every client had one of a handful of
 * edge addresses and shared one per-address limit; a gateway hitting it
 * while waiting gave up on the login; and requests whose gateway died
 * (a dropped SSH login) counted against the pairing for 30 minutes.
 */

async function withRelay(fn: (url: string) => Promise<void>) {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-limits-")) });
  try {
    await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}
const post = (url: string, path: string, body: unknown) =>
  fetch(url + path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

test("the client behind Cloudflare is the client, and nobody else can say so", () => {
  assert.ok(inRange("172.70.1.2", "172.64.0.0/13"));
  assert.ok(!inRange("172.72.0.1", "172.64.0.0/13"));
  assert.ok(inRange("2606:4700:10::ac43:1", "2606:4700::/32"));
  assert.ok(inRange("::ffff:104.16.5.5", "104.16.0.0/13"));
  // Cloudflare's edge connecting: CF-Connecting-IP is the phone.
  assert.equal(clientAddress("172.70.1.2", { "cf-connecting-ip": "198.51.100.9" }), "198.51.100.9");
  assert.equal(clientAddress("2606:4700:10::1", { "cf-connecting-ip": "198.51.100.9" }), "198.51.100.9");
  // cloudflared or a proxy on this host.
  assert.equal(clientAddress("127.0.0.1", { "cf-connecting-ip": "198.51.100.9" }), "198.51.100.9");
  assert.equal(clientAddress("172.17.0.1", { "x-forwarded-for": "198.51.100.9, 10.0.0.1" }), "198.51.100.9");
  // A stranger straight on the port cannot pick its own address.
  assert.equal(clientAddress("203.0.113.66", { "cf-connecting-ip": "1.2.3.4", "x-forwarded-for": "1.2.3.4" }), "203.0.113.66");
});

test("a vault in use is never refused for its address; invented ids still are", async () => {
  await withRelay(async (url) => {
    const { pairId } = newPairing();
    await post(url, "/api/hello", { pairId });
    let refused = 0;
    for (let i = 0; i < 300; i++) {
      if ((await fetch(`${url}/api/pending?pairIds=${pairId}`)).status === 429) refused++;
    }
    assert.equal(refused, 0, "a phone polling its own vaults must not hit the per-address limit");
    let limited = 0;
    for (let i = 0; i < 260; i++) {
      const res = await fetch(`${url}/api/pending?pairId=${newPairing().pairId}`);
      if (res.status === 429) {
        limited++;
        assert.equal((await res.json()).retryable, true);
      }
    }
    assert.ok(limited > 0, "invented pair ids still meet the wall");
    // Even then, the real vault keeps working.
    assert.equal((await fetch(`${url}/api/pending?pairId=${pairId}`)).status, 200);
  });
});

test("a request whose gateway died stops blocking the vault when it expires", async () => {
  await withRelay(async (url) => {
    const { pairId } = newPairing();
    const send = (n: number, ttlSec?: number) =>
      post(url, "/api/request", { pairId, requestId: "orphan_" + String(n).padStart(8, "0"), payload: { iv: "a", ct: "b" }, ttlSec });
    // Five SSH logins dropped mid-wait (Ctrl-C, VS Code reconnecting).
    for (let i = 0; i < 5; i++) assert.equal((await send(i, 10)).status, 200);
    assert.equal((await send(5, 10)).status, 429, "five undecided: the flood guard holds");
    await new Promise((r) => setTimeout(r, 10_500));
    // Before: refused for 30 minutes. Now: their deadline passed, they are gone.
    const pending = await (await fetch(`${url}/api/pending?pairId=${pairId}`)).json();
    assert.deepEqual(pending, [], "expired requests are not shown on the phone");
    assert.equal((await send(6, 60)).status, 200);
  });
});

test("a gateway re-sending its request keeps the answer already given", async () => {
  await withRelay(async (url) => {
    const { pairId, secret } = newPairing();
    const requestId = "repeat_000001";
    await post(url, "/api/request", { pairId, requestId, payload: { iv: "a", ct: "b" }, ttlSec: 60 });
    const decision = seal(deriveKey(secret), { requestId, approved: true, ts: Date.now() }, aadForDecision(requestId));
    await post(url, "/api/decision", { pairId, requestId, payload: decision });
    await post(url, "/api/request", { pairId, requestId, payload: { iv: "a", ct: "b" }, ttlSec: 60 });
    const res = await fetch(`${url}/api/decision?pairId=${pairId}&requestId=${requestId}&timeoutSec=1`);
    assert.equal(res.status, 200, "the decision survived the repeat");
  });
});

test("one stream and one read cover every vault of a device", async () => {
  await withRelay(async (url) => {
    const a = newPairing(), b = newPairing();
    await post(url, "/api/hello", { pairId: a.pairId });
    await post(url, "/api/hello", { pairId: b.pairId });
    const events: string[] = [];
    const ctrl = new AbortController();
    const stream = await fetch(`${url}/api/events?pairIds=${a.pairId},${b.pairId}`, { signal: ctrl.signal });
    const reader = stream.body!.getReader();
    const reading = (async () => {
      const dec = new TextDecoder();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          events.push(dec.decode(value));
        }
      } catch {}
    })();
    await post(url, "/api/request", { pairId: b.pairId, requestId: "batch_000001", payload: { iv: "a", ct: "b" }, ttlSec: 60 });
    await new Promise((r) => setTimeout(r, 200));
    ctrl.abort();
    await reading;
    assert.match(events.join(""), new RegExp(`event: request\\ndata: \\{"pairId":"${b.pairId}"\\}`));

    const both = await (await fetch(`${url}/api/pending?pairIds=${a.pairId},${b.pairId}`)).json();
    assert.deepEqual(both.byPair[a.pairId], []);
    assert.equal(both.byPair[b.pairId].length, 1);
    const tooMany = Array.from({ length: 65 }, () => newPairing().pairId).join(",");
    assert.equal((await fetch(`${url}/api/pending?pairIds=${tooMany}`)).status, 400);
  });
});

test("removing a vault on a device stops that device ringing for it", async () => {
  await withRelay(async (url) => {
    const { pairId } = newPairing();
    const sub = { endpoint: "https://push.example/phone", keys: { p256dh: "x", auth: "y" } };
    await post(url, "/api/subscribe", { pairId, subscription: sub });
    assert.equal((await (await fetch(`${url}/api/pair-status?pairId=${pairId}`)).json()).subscribed, true);
    await post(url, "/api/unsubscribe", { pairId, endpoint: sub.endpoint });
    assert.equal((await (await fetch(`${url}/api/pair-status?pairId=${pairId}`)).json()).subscribed, false);
  });
});

/**
 * A relay that misbehaves the way a real network does: the first calls
 * fail (503 from a proxy, a retryable 429, a dropped connection), then it
 * works. The gateway must ride it out instead of refusing the login.
 */
test("a gateway rides out a flaky relay instead of refusing the login", async () => {
  await withRelay(async (relayUrl) => {
    const target = new URL(relayUrl);
    const faults = { request: ["503", "429"], decision: ["drop", "503", "429"] };
    const proxy = createServer((req, res) => {
      const path = req.url ?? "/";
      const queue = path.startsWith("/api/request") ? faults.request : path.startsWith("/api/decision") && req.method === "GET" ? faults.decision : [];
      const fault = queue.shift();
      if (fault === "drop") return req.socket.destroy();
      if (fault === "503") {
        res.writeHead(503, { "Content-Type": "text/html" });
        return res.end("<html>Bad gateway</html>");
      }
      if (fault === "429") {
        res.writeHead(429, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ error: "Too many requests from this address.", retryable: true }));
      }
      const upstream = httpRequest(
        { host: target.hostname, port: target.port, path, method: req.method, headers: req.headers },
        (up) => {
          res.writeHead(up.statusCode ?? 502, up.headers);
          up.pipe(res);
        }
      );
      req.pipe(upstream);
    });
    await new Promise<void>((r) => proxy.listen(0, r));
    const proxyUrl = `http://localhost:${(proxy.address() as any).port}`;
    try {
      const pairing = newPairing();
      const approver = new PwaApprover({ relayUrl: proxyUrl, ...pairing });
      const result = approver.request({ title: "flaky", timeoutSec: 30 });
      // The phone answers on the real relay.
      let items: any[] = [];
      for (let i = 0; i < 100 && !items.length; i++) {
        items = await (await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`)).json();
        if (!items.length) await new Promise((r) => setTimeout(r, 100));
      }
      const requestId = items[0].requestId;
      await post(relayUrl, "/api/decision", {
        pairId: pairing.pairId,
        requestId,
        payload: seal(deriveKey(pairing.secret), { requestId, approved: true, ts: Date.now() }, aadForDecision(requestId)),
      });
      assert.deepEqual(await result, { approved: true, decision: "approved" });
      assert.equal(faults.request.length + faults.decision.length, 0, "every fault was actually hit");
    } finally {
      proxy.close();
    }
  });
});

test("a pairing flooding the phone is still refused, not retried", async () => {
  await withRelay(async (url) => {
    const pairing = newPairing();
    for (let i = 0; i < 5; i++) {
      await post(url, "/api/request", { pairId: pairing.pairId, requestId: "flood_" + String(i).padStart(8, "0"), payload: { iv: "a", ct: "b" }, ttlSec: 60 });
    }
    const started = Date.now();
    await assert.rejects(
      new PwaApprover({ relayUrl: url, ...pairing }).request({ title: "sixth", timeoutSec: 5 }),
      /HTTP 429/
    );
    assert.ok(Date.now() - started < 1500, "a deliberate refusal is not retried");
  });
});
