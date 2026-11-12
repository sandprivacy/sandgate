import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import webpush from "web-push";
import { startRelay, quietAfterMs } from "../relay/server.js";
import { PWA_SW } from "../relay/pwa-page.js";
import { newPairing, deriveKey, open, aadForStatus } from "../pwacrypto.js";
import {
  parseOsRelease,
  parseOpensshVersion,
  serverAddresses,
  heartbeatUnits,
  collectStatus,
  sendHeartbeat,
  sendGoodbye,
} from "../ssh-guard-heartbeat.js";
import { SERVER_VERSION, VERSION } from "../version.js";
import { sshdUnreadableFinding } from "../ssh-guard-install.js";
import { loadPage, waitFor } from "./helpers/page.js";

/**
 * Heartbeats: a server tells the phone it is alive and how it is wired,
 * sealed so the relay reads nothing, and the relay — which only sees
 * *when* a pairing last spoke — warns the phone when one goes quiet.
 */

// --- what the server collects --------------------------------------------

test("os-release and OpenSSH versions are read in every format seen", () => {
  assert.equal(parseOsRelease('NAME="Ubuntu"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'), "Ubuntu 20.04.6 LTS");
  assert.equal(parseOsRelease("PRETTY_NAME=Alpine\n"), "Alpine");
  assert.equal(parseOsRelease("NAME=x\n"), undefined);
  // 8.2 rejects -V but still prints its version; 9.x accepts it.
  assert.equal(parseOpensshVersion("unknown option -- V\nOpenSSH_8.2p1 Ubuntu-4ubuntu0.11, OpenSSL 1.1.1f"), "8.2p1");
  assert.equal(parseOpensshVersion("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13"), "9.6p1");
  assert.equal(parseOpensshVersion("command not found"), undefined);
});

const iface = (address: string, family: "IPv4" | "IPv6" = "IPv4", internal = false) =>
  ({ address, family, internal, netmask: "", mac: "", cidr: null }) as any;

test("the addresses shown are the ones you would ssh to", () => {
  assert.deepEqual(
    serverAddresses({
      lo: [iface("127.0.0.1", "IPv4", true)],
      eth0: [iface("203.0.113.7"), iface("2001:db8::7", "IPv6"), iface("fe80::1", "IPv6")],
      docker0: [iface("172.17.0.1")],
      wg0: [iface("10.8.0.1")],
    }),
    ["203.0.113.7", "2001:db8::7"]
  );
  // Behind NAT: no public address, the private one is still better than nothing.
  assert.deepEqual(serverAddresses({ ens3: [iface("192.168.1.20"), iface("fe80::2", "IPv6")] }), ["192.168.1.20"]);
});

test("the timer runs the same binary as the hook, with the config it was given", () => {
  const plain = heartbeatUnits(["/usr/local/bin/sandgate"], "/etc/sandgate/ssh-guard.json", "/etc/sandgate/ssh-guard.json");
  assert.match(plain.service, /^ExecStart=\/usr\/local\/bin\/sandgate ssh-guard heartbeat$/m);
  assert.doesNotMatch(plain.service, /Environment=/);
  assert.match(plain.timer, /^OnUnitActiveSec=300s$/m);
  assert.match(plain.timer, /^WantedBy=timers.target$/m);
  const node = heartbeatUnits(["/usr/bin/node", "/opt/my apps/sandgate/dist/index.js"], "/srv/sg.json", "/etc/sandgate/ssh-guard.json");
  assert.match(node.service, /^ExecStart=\/usr\/bin\/node "\/opt\/my apps\/sandgate\/dist\/index.js" ssh-guard heartbeat$/m);
  assert.match(node.service, /^Environment=SANDGATE_SSH_GUARD_CONFIG=\/srv\/sg.json$/m);
});

test("the status carries doctor's problems, never its ok lines", () => {
  const { pairId, secret } = newPairing();
  const st = collectStatus(
    { relayUrl: "http://x", pairId, secret, serverName: "us4", failOpen: false, exemptUsers: [] },
    [
      { level: "ok", label: "pam hook (key-only)" },
      { level: "fail", label: "keyboard-interactive", detail: "ChallengeResponseAuthentication is no" },
    ],
    true
  );
  assert.equal(st.name, "us4");
  assert.equal(st.sandgate, VERSION);
  assert.equal(st.mode, "enforce");
  assert.equal(st.keyOnly, true);
  assert.equal(st.hatch, false);
  assert.equal(st.doctor!.ok, false);
  assert.deepEqual(st.doctor!.findings.map((f) => f.label), ["keyboard-interactive"]);
  assert.equal(collectStatus({ relayUrl: "http://x", pairId, secret }, null, false).doctor, null);
});

test("sshd refusing its own configuration is a problem, never 'All good'", () => {
  // Found on OpenSSH 9.6: with keyboard-interactive off, `sshd -T` fails
  // outright, and doctor used to skip every check and print All good.
  const asRoot = sshdUnreadableFinding(true, {
    ok: false,
    output: 'Disabled method "keyboard-interactive" in AuthenticationMethods list\nAuthenticationMethods cannot be satisfied by enabled authentication methods',
  });
  assert.equal(asRoot.level, "fail");
  assert.match(asRoot.detail!, /cannot be satisfied/);
  assert.match(asRoot.detail!, /will not start again/);
  // Not root: sshd -T cannot read the host keys; say so, do not cry wolf.
  assert.equal(sshdUnreadableFinding(false, { ok: false, output: "" }).level, "warn");
});

// --- the relay -------------------------------------------------------------

async function withRelay(
  fn: (url: string, relay: Awaited<ReturnType<typeof startRelay>>, pushes: any[]) => Promise<void>,
  stateDir = mkdtempSync(join(tmpdir(), "sg-hb-"))
) {
  const original = webpush.sendNotification;
  const pushes: any[] = [];
  (webpush as any).sendNotification = async (_sub: any, payload: string, options: any) => {
    pushes.push({ ...JSON.parse(payload), options });
    return { statusCode: 201 };
  };
  const relay = await startRelay({ port: 0, stateDir });
  try {
    await fn(`http://localhost:${relay.port}`, relay, pushes);
  } finally {
    relay.close();
    (webpush as any).sendNotification = original;
  }
}

const config = (pairId: string, secret: string, relayUrl: string) => ({
  relayUrl,
  pairId,
  secret,
  serverName: "us4",
  failOpen: false,
  exemptUsers: ["rescue"],
});

test("the relay keeps the sealed status, reads none of it, and refuses a flood", async () => {
  await withRelay(async (url) => {
    const { pairId, secret } = newPairing();
    const cfg = config(pairId, secret, url);
    const st = collectStatus(cfg, [], false);
    await sendHeartbeat(cfg, st);

    const got = await (await fetch(`${url}/api/status?pairId=${pairId}`)).json();
    assert.ok(got.status.receivedAt <= got.now);
    assert.equal(got.quietAfterMs, quietAfterMs(300));
    assert.ok(!JSON.stringify(got).includes("us4"), "the relay must hold a sealed blob, not the status");
    const opened = open<any>(deriveKey(secret), got.status.payload, aadForStatus(pairId));
    assert.equal(opened.name, "us4");
    // Sealed for this pairing only: another pairing's AAD does not open it.
    assert.throws(() => open(deriveKey(secret), got.status.payload, aadForStatus("other_pair_id")));

    // Twice within seconds (a timer firing around an install): skipped, not an error.
    assert.equal(await sendHeartbeat(cfg, st), "skipped");
    assert.equal((await (await fetch(`${url}/api/health`)).json()).version, VERSION);

    await sendGoodbye(cfg);
    assert.equal((await (await fetch(`${url}/api/status?pairId=${pairId}`)).json()).status, null);
  });
});

test("a quiet server rings the phone once, and again when it is back", async () => {
  const stateDir = mkdtempSync(join(tmpdir(), "sg-hb-quiet-"));
  const { pairId, secret } = newPairing();
  await withRelay(async (url, relay, pushes) => {
    await fetch(`${url}/api/subscribe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId, subscription: { endpoint: "https://fcm.googleapis.com/fcm/send/p", keys: { p256dh: "x", auth: "y" } } }),
    });
    await sendHeartbeat(config(pairId, secret, url), collectStatus(config(pairId, secret, url), [], false));
    relay.checkQuiet(Date.now() + 60_000);
    assert.equal(pushes.length, 0, "a minute of silence is not news");
    relay.checkQuiet(Date.now() + quietAfterMs(300) + 1000);
    relay.checkQuiet(Date.now() + quietAfterMs(300) + 120_000);
    assert.equal(pushes.length, 1, "told once, not every minute");
    assert.equal(pushes[0].type, "server");
    assert.equal(pushes[0].state, "offline");
    assert.equal(pushes[0].pairId, pairId);
    assert.equal(pushes[0].options.urgency, "high");
  }, stateDir);

  // The relay restarts in between: it still knows it already warned.
  await withRelay(async (url, relay, pushes) => {
    relay.checkQuiet(Date.now() + quietAfterMs(300) + 300_000);
    assert.equal(pushes.length, 0, "a restart must not ring again");
    await sendHeartbeat(config(pairId, secret, url), collectStatus(config(pairId, secret, url), [], false));
    assert.equal(pushes.length, 1);
    assert.equal(pushes[0].state, "online");
  }, stateDir);
});

test("an uninstalled server is not reported as dead", async () => {
  await withRelay(async (url, relay, pushes) => {
    const { pairId, secret } = newPairing();
    await fetch(`${url}/api/subscribe`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId, subscription: { endpoint: "https://fcm.googleapis.com/fcm/send/p", keys: { p256dh: "x", auth: "y" } } }),
    });
    const cfg = config(pairId, secret, url);
    await sendHeartbeat(cfg, collectStatus(cfg, [], false));
    await sendGoodbye(cfg);
    relay.checkQuiet(Date.now() + 24 * 3600_000);
    assert.equal(pushes.length, 0);
  });
});

// --- the phone ---------------------------------------------------------------

test("the app shows each server: online, addresses, versions, doctor's problems", async () => {
  await withRelay(async (url) => {
    const { pairId, secret } = newPairing();
    const cfg = config(pairId, secret, url);
    const st = collectStatus(
      cfg,
      [{ level: "fail", label: "keyboard-interactive", detail: "ChallengeResponseAuthentication is no" }],
      true
    );
    st.ips = ["203.0.113.7"];
    st.os = "Ubuntu 20.04.6 LTS";
    st.openssh = "8.2p1";
    st.sandgate = "0.9.0"; // older than the relay: an update is offered
    await sendHeartbeat(cfg, st);

    const { window, close } = await loadPage(url, {
      localStorage: { sandgate_pairs: JSON.stringify([{ name: "us4", pairId, secret }]) },
    });
    try {
      const row = await waitFor(() => window.document.querySelector(".srv"));
      const text = row.textContent as string;
      assert.match(text, /us4/);
      assert.match(text, /online · just now/);
      assert.match(text, /203\.0\.113\.7 · Ubuntu 20\.04\.6 LTS · OpenSSH 8\.2p1/);
      assert.match(text, /sandgate 0\.9\.0 · blocking · key \+ phone/);
      // Against the last release that changed servers, not the relay's own.
      assert.match(text, new RegExp(`update available.*0\\.9\\.0 → ${SERVER_VERSION.replace(/\./g, "\\.")}`));
      assert.match(text, /keyboard-interactive — ChallengeResponseAuthentication is no/);
      assert.ok(row.querySelector(".dot.up"));
      assert.ok(row.querySelector(".flag.fail"));
    } finally {
      close();
    }
  });
});

test("a server in trouble is first in the list, counted on the tab, and named on the Requests screen", async () => {
  await withRelay(async (url) => {
    const servers = [
      { name: "alpha", findings: [] as any[], silent: false },
      { name: "bravo", findings: [{ level: "fail", label: "keyboard-interactive", detail: "off" }], silent: false },
      { name: "zulu", findings: [] as any[], silent: true },
    ].map((s) => ({ ...s, ...newPairing() }));
    for (const s of servers) {
      const cfg = config(s.pairId, s.secret, url);
      const st = collectStatus(cfg, s.findings, true);
      // Sealed two hours ago: the page ages a heartbeat by its sealed time
      // when it is older than the relay claims, which is how it reads here.
      if (s.silent) st.ts = Date.now() - 2 * 3600_000;
      await sendHeartbeat(cfg, st);
    }
    const { window, close } = await loadPage(url, {
      localStorage: {
        sandgate_pairs: JSON.stringify(servers.map((s) => ({ name: s.name, pairId: s.pairId, secret: s.secret }))),
      },
    });
    try {
      const doc = window.document;
      await waitFor(() => doc.querySelectorAll(".srv").length === 3);
      const names = [...doc.querySelectorAll(".srv .name")].map((n: any) => n.textContent);
      assert.deepEqual(names, ["zulu", "bravo", "alpha"], "silent, then broken, then fine");
      assert.match(doc.querySelector(".srv .seen").textContent, /^silent since /);
      assert.match(doc.querySelector(".sum").textContent, /2 online.*1 silent.*1 with a problem/);
      assert.equal(doc.getElementById("b-srv").textContent, "2", "the Servers tab counts what needs you");

      // You land on Requests: the trouble is named there, one tap away.
      assert.ok(doc.getElementById("v-req").classList.contains("on"));
      const alert = doc.querySelector("#alerts .alert");
      assert.match(alert.textContent, /zulu silent since .* \+1 other/);
      alert.click();
      assert.ok(doc.getElementById("v-srv").classList.contains("on"));
      assert.ok(!doc.getElementById("v-req").classList.contains("on"));
      assert.equal(doc.querySelector('[data-tab="srv"]').getAttribute("aria-selected"), "true");

      // Details fold away; a tap opens them.
      const row = doc.querySelectorAll(".srv")[1];
      assert.ok(!row.classList.contains("open"));
      row.click();
      assert.ok(row.classList.contains("open"));
    } finally {
      close();
    }
  });
});

test("the lock screen names the server that went quiet, from this device's own list", async () => {
  const shown: any[] = [];
  const handlers: Record<string, (e: any) => void> = {};
  const { pairId, secret } = newPairing();
  const context: any = {
    self: {
      addEventListener: (type: string, fn: (e: any) => void) => (handlers[type] = fn),
      skipWaiting() {},
      registration: { showNotification: async (title: string, options: any) => shown.push({ title, options }) },
      clients: { matchAll: async () => [], claim: async () => {} },
    },
    caches: {
      open: async () => ({
        match: async () => new Response(JSON.stringify({ pairs: [{ name: "us4", pairId, secret }], details: true })),
      }),
    },
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    Response,
    console,
  };
  vm.createContext(context);
  vm.runInContext(PWA_SW, context);
  const push = async (data: unknown) => {
    const pending: Promise<unknown>[] = [];
    handlers.push!({ data: { json: () => data }, waitUntil: (p: Promise<unknown>) => pending.push(p) });
    await Promise.all(pending);
  };
  await push({ type: "server", pairId, state: "offline", since: Date.now() - 20 * 60_000 });
  await push({ type: "server", pairId, state: "online", since: Date.now() - 20 * 60_000 });
  await push({ type: "server", pairId: "unknown_pair_x", state: "offline", since: Date.now() });
  assert.equal(shown[0].title, "us4 stopped responding");
  assert.match(shown[0].options.body, /^No heartbeat since \d\d:\d\d/);
  assert.equal(shown[1].title, "us4 is back");
  assert.equal(shown[0].options.tag, shown[1].options.tag, "back replaces the warning");
  assert.equal(shown[2].title, "A server stopped responding");
});
