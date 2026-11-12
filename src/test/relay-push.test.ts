import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import webpush from "web-push";
import { startRelay } from "../relay/server.js";
import { newPairing } from "../pwacrypto.js";

/**
 * Push delivery: every device of a vault rings, at high urgency, never
 * for longer than the request lives, and a device the push service has
 * forgotten stops being tried. web-push only speaks HTTPS, so the send
 * itself is replaced: what matters here is what the relay asks of it.
 */

type Sent = { endpoint: string; options: any };

async function withRelay(
  fn: (url: string, sent: Sent[], stateDir: string) => Promise<void>,
  opts: { failWith?: (endpoint: string) => number | null; stateDir?: string } = {}
) {
  const original = webpush.sendNotification;
  const sent: Sent[] = [];
  (webpush as any).sendNotification = async (sub: any, _payload: string, options: any) => {
    sent.push({ endpoint: sub.endpoint, options });
    const status = opts.failWith?.(sub.endpoint) ?? null;
    if (status) throw Object.assign(new Error("push refused"), { statusCode: status, body: "gone" });
    return { statusCode: 201 };
  };
  const stateDir = opts.stateDir ?? mkdtempSync(join(tmpdir(), "sg-push-"));
  const relay = await startRelay({ port: 0, stateDir });
  const errors = console.error;
  console.error = () => {};
  try {
    await fn(`http://localhost:${relay.port}`, sent, stateDir);
  } finally {
    console.error = errors;
    relay.close();
    (webpush as any).sendNotification = original;
  }
}

const sub = (name: string) => ({
  endpoint: `https://fcm.googleapis.com/fcm/send/${name}`,
  keys: { p256dh: "BP" + name, auth: "a" + name },
});

async function post(url: string, path: string, body: unknown) {
  return fetch(url + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

let n = 0;
async function request(url: string, pairId: string, extra: Record<string, unknown> = {}) {
  const res = await post(url, "/api/request", {
    pairId,
    requestId: "req_" + String(++n).padStart(12, "0"),
    payload: { iv: "a", ct: "b" },
    ...extra,
  });
  assert.equal(res.status, 200);
  await new Promise((r) => setTimeout(r, 30)); // let the sends settle
}

test("every device of a vault rings, not just the last one to subscribe", async () => {
  await withRelay(async (url, sent) => {
    const { pairId } = newPairing();
    await post(url, "/api/subscribe", { pairId, subscription: sub("phone") });
    await post(url, "/api/subscribe", { pairId, subscription: sub("tablet") });
    // The phone subscribing again is the same device, not a third one.
    await post(url, "/api/subscribe", { pairId, subscription: sub("phone") });
    await request(url, pairId);
    assert.deepEqual(sent.map((s) => s.endpoint).sort(), [sub("phone").endpoint, sub("tablet").endpoint]);
  });
});

test("pushes go out at high urgency, with the request's own lifetime", async () => {
  await withRelay(async (url, sent) => {
    const { pairId } = newPairing();
    await post(url, "/api/subscribe", { pairId, subscription: sub("phone") });
    await request(url, pairId, { ttlSec: 60 });
    assert.equal(sent[0]!.options.urgency, "high");
    assert.equal(sent[0]!.options.TTL, 60);
    // An older gateway sends no lifetime: ten minutes, never four weeks.
    await request(url, pairId);
    assert.equal(sent[1]!.options.TTL, 600);
    // Nonsense is clamped, not trusted.
    await request(url, pairId, { ttlSec: 999999 });
    assert.equal(sent[2]!.options.TTL, 3600);
  });
});

test("a device the push service forgot (410) is dropped, the others kept", async () => {
  await withRelay(
    async (url, sent, stateDir) => {
      const { pairId } = newPairing();
      await post(url, "/api/subscribe", { pairId, subscription: sub("gone") });
      await post(url, "/api/subscribe", { pairId, subscription: sub("phone") });
      await request(url, pairId);
      assert.equal(sent.length, 2);
      await request(url, pairId);
      assert.deepEqual(sent.slice(2).map((s) => s.endpoint), [sub("phone").endpoint]);
      const saved = JSON.parse(readFileSync(join(stateDir, "relay-state.json"), "utf8"));
      assert.deepEqual(saved.subscriptions[pairId].map((s: any) => s.endpoint), [sub("phone").endpoint]);
    },
    { failWith: (endpoint) => (endpoint.endsWith("/gone") ? 410 : null) }
  );
});

test("a temporary push failure keeps the device", async () => {
  await withRelay(
    async (url, sent) => {
      const { pairId } = newPairing();
      await post(url, "/api/subscribe", { pairId, subscription: sub("phone") });
      await request(url, pairId);
      await request(url, pairId);
      assert.equal(sent.length, 2, "a 503 is the push service's problem, not a dead device");
    },
    { failWith: () => 503 }
  );
});

test("a state file from before multi-device keeps ringing its device", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "sg-push-old-"));
  const { pairId } = newPairing();
  const keys = webpush.generateVAPIDKeys();
  writeFileSync(
    join(stateDir, "relay-state.json"),
    JSON.stringify({ vapid: keys, subscriptions: { [pairId]: sub("old-phone") } })
  );
  await withRelay(
    async (url, sent) => {
      const status = await (await fetch(`${url}/api/pair-status?pairId=${pairId}`)).json();
      assert.equal(status.subscribed, true);
      await post(url, "/api/subscribe", { pairId, subscription: sub("new-tablet") });
      await request(url, pairId);
      assert.deepEqual(sent.map((s) => s.endpoint).sort(), [sub("new-tablet").endpoint, sub("old-phone").endpoint]);
    },
    { stateDir }
  );
  // The VAPID keys survive: losing them silently ends every push.
  const saved = JSON.parse(readFileSync(join(stateDir, "relay-state.json"), "utf8"));
  assert.equal(saved.vapid.publicKey, keys.publicKey);
});

test("the page and the worker are never served from a cache", async () => {
  await withRelay(async (url) => {
    assert.equal((await fetch(url + "/")).headers.get("cache-control"), "no-cache");
    assert.equal((await fetch(url + "/sw.js")).headers.get("cache-control"), "no-cache");
  });
});
