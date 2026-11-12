import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import webpush from "web-push";
import { startRelay, pushEndpointAllowed, rateKey, quietAfterMs } from "../relay/server.js";
import { newPairing } from "../pwacrypto.js";

/**
 * What a stranger can make the relay do. It is a public server holding
 * no secret, so the question is never "can they read" but "can they make
 * it knock on something, fill its disk, or walk around its limits".
 */

type Relay = Awaited<ReturnType<typeof startRelay>>;

async function withRelay(fn: (url: string, relay: Relay, stateDir: string) => Promise<void>, stateDir?: string) {
  const dir = stateDir ?? mkdtempSync(join(tmpdir(), "sg-hard-"));
  const relay = await startRelay({ port: 0, stateDir: dir });
  try {
    await fn(`http://localhost:${relay.port}`, relay, dir);
  } finally {
    relay.close();
  }
}
const post = (url: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(url + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
const sub = (endpoint: string) => ({ endpoint, keys: { p256dh: "BPkey", auth: "authkey" } });

test("pushes go to browser push services only, never into the relay's own network", () => {
  for (const ok of [
    "https://fcm.googleapis.com/fcm/send/abc",
    "https://web.push.apple.com/QGx",
    "https://updates.push.services.mozilla.com/wpush/v2/gAAA",
    "https://wns2-par02p.notify.windows.com/w/?token=x",
  ]) {
    assert.ok(pushEndpointAllowed(ok), ok);
  }
  for (const bad of [
    "https://127.0.0.1/admin",
    "https://169.254.169.254/latest/meta-data/",
    "https://[::1]/x",
    "https://localhost:8787/api/metrics",
    "https://10.0.0.5/",
    "http://fcm.googleapis.com/fcm/send/abc", // not https
    "https://fcm.googleapis.com:8443/x", // another port
    "https://user:pw@fcm.googleapis.com/x",
    "https://fcm.googleapis.com.attacker.example/x",
    "https://evilfcm.googleapis.com/x",
    "https://attacker.example/?fcm.googleapis.com",
    "not a url",
    "",
    42,
    "https://fcm.googleapis.com/" + "a".repeat(3000),
  ]) {
    assert.ok(!pushEndpointAllowed(bad), String(bad).slice(0, 80));
  }
  // A self-hosted push service, named by the operator.
  assert.ok(pushEndpointAllowed("https://push.example.org/x", ["push.example.org"]));
});

test("a subscription pointing anywhere else is refused, and an old one in the state file is never used", async () => {
  await withRelay(async (url) => {
    const { pairId } = newPairing();
    const res = await post(url, "/api/subscribe", { pairId, subscription: sub("https://127.0.0.1:2375/containers/create") });
    assert.equal(res.status, 400);
    assert.equal((await (await fetch(`${url}/api/pair-status?pairId=${pairId}`)).json()).subscribed, false);
    // Malformed keys: refused before anything is stored.
    assert.equal((await post(url, "/api/subscribe", { pairId, subscription: { endpoint: "https://fcm.googleapis.com/x" } })).status, 400);
    assert.equal(
      (await post(url, "/api/subscribe", {
        pairId,
        subscription: { endpoint: "https://fcm.googleapis.com/x", keys: { p256dh: "x".repeat(300), auth: "y" } },
      })).status,
      400
    );
  });

  // A state file written before the check: the bad endpoint stays inert.
  const stateDir = mkdtempSync(join(tmpdir(), "sg-hard-"));
  const { pairId } = newPairing();
  writeFileSync(
    join(stateDir, "relay-state.json"),
    JSON.stringify({
      vapid: webpush.generateVAPIDKeys(),
      subscriptions: { [pairId]: [sub("https://10.0.0.5/internal"), sub("https://fcm.googleapis.com/fcm/send/phone")] },
    })
  );
  const original = webpush.sendNotification;
  const sent: string[] = [];
  (webpush as any).sendNotification = async (s: any) => {
    sent.push(s.endpoint);
    return { statusCode: 201 };
  };
  try {
    await withRelay(async (url) => {
      await post(url, "/api/request", { pairId, requestId: "req_hard_0001", payload: { iv: "a", ct: "b" } });
      assert.deepEqual(sent, ["https://fcm.googleapis.com/fcm/send/phone"]);
    }, stateDir);
  } finally {
    (webpush as any).sendNotification = original;
  }
});

test("only what a push needs is stored for a subscription", async () => {
  await withRelay(async (url, _relay, stateDir) => {
    const { pairId } = newPairing();
    const res = await post(url, "/api/subscribe", {
      pairId,
      subscription: { ...sub("https://fcm.googleapis.com/fcm/send/p"), junk: "z".repeat(50_000) },
    });
    assert.equal(res.status, 200);
    const saved = JSON.parse(readFileSync(join(stateDir, "relay-state.json"), "utf8"));
    assert.deepEqual(saved.subscriptions[pairId], [sub("https://fcm.googleapis.com/fcm/send/p")]);
  });
});

test("IPv6 counts per /64: changing the last bits is the same client", () => {
  assert.equal(rateKey("2001:db8:1:2::1"), rateKey("2001:db8:1:2:ffff:ffff:ffff:fffe"));
  assert.notEqual(rateKey("2001:db8:1:2::1"), rateKey("2001:db8:1:3::1"));
  assert.equal(rateKey("203.0.113.7"), "203.0.113.7");
  assert.equal(rateKey("::ffff:203.0.113.7"), "203.0.113.7");
  assert.equal(rateKey("?"), "?");
});

test("an IPv6 client cannot walk around the per-address limit by rotating its address", async () => {
  await withRelay(async (url) => {
    // Tests come from loopback, a local-proxy position: X-Forwarded-For
    // stands in for what a proxy would report.
    let limited = 0;
    for (let i = 0; i < 260; i++) {
      const res = await fetch(`${url}/api/pending?pairId=${newPairing().pairId}`, {
        headers: { "x-forwarded-for": `2001:db8:aa:bb::${(i + 1).toString(16)}` },
      });
      if (res.status === 429) limited++;
    }
    assert.ok(limited > 0, "260 addresses of one /64 are one client");
  });
});

test("one address cannot fill the state file with invented vaults", async () => {
  await withRelay(async (url) => {
    const headers = { "x-forwarded-for": "198.51.100.40" };
    let refused = 0;
    for (let i = 0; i < 70; i++) {
      const { pairId } = newPairing();
      const res = await post(url, "/api/subscribe", { pairId, subscription: sub(`https://fcm.googleapis.com/fcm/send/${i}`) }, headers);
      if (res.status === 429) {
        refused++;
        assert.equal((await res.json()).retryable, true);
      }
    }
    assert.equal(refused, 10, "sixty new vaults an hour, then no more");
    // Another address is not affected.
    const other = await post(url, "/api/subscribe", {
      pairId: newPairing().pairId,
      subscription: sub("https://fcm.googleapis.com/fcm/send/other"),
    }, { "x-forwarded-for": "198.51.100.41" });
    assert.equal(other.status, 200);
  });
});

test("a device already subscribed is never refused as new, and a server's status is forgotten after a month", async () => {
  await withRelay(async (url, relay) => {
    const headers = { "x-forwarded-for": "198.51.100.50" };
    const { pairId } = newPairing();
    assert.equal((await post(url, "/api/subscribe", { pairId, subscription: sub("https://fcm.googleapis.com/fcm/send/a") }, headers)).status, 200);
    for (let i = 0; i < 59; i++) {
      await post(url, "/api/subscribe", { pairId: newPairing().pairId, subscription: sub(`https://fcm.googleapis.com/fcm/send/f${i}`) }, headers);
    }
    // Budget spent; the same vault re-subscribing (every app load) still works.
    assert.equal((await post(url, "/api/subscribe", { pairId, subscription: sub("https://fcm.googleapis.com/fcm/send/a") }, headers)).status, 200);

    const server = newPairing();
    assert.equal((await post(url, "/api/status", { pairId: server.pairId, payload: { iv: "a", ct: "b" }, intervalSec: 300 })).status, 200);
    const before = await (await fetch(`${url}/api/status?pairId=${server.pairId}`)).json();
    assert.ok(before.status);
    // Two weeks: still shown as silent. A month and a day: gone.
    relay.sweep(Date.now() + 14 * 24 * 3600_000);
    assert.ok((await (await fetch(`${url}/api/status?pairId=${server.pairId}`)).json()).status);
    relay.sweep(Date.now() + 31 * 24 * 3600_000);
    assert.equal((await (await fetch(`${url}/api/status?pairId=${server.pairId}`)).json()).status, null);
    assert.ok(quietAfterMs(300) < 14 * 24 * 3600_000);
  });
});

test("the approval page cannot be framed by another site", async () => {
  await withRelay(async (url) => {
    for (const path of ["/", "/sw.js", "/api/health", "/api/vapid"]) {
      const res = await fetch(url + path);
      assert.equal(res.headers.get("x-frame-options"), "DENY", path);
      assert.match(res.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/, path);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff", path);
      assert.equal(res.headers.get("referrer-policy"), "no-referrer", path);
    }
  });
});
