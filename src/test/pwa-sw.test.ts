import { test } from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import { webcrypto } from "node:crypto";
import { PWA_SW } from "../relay/pwa-page.js";
import {
  newPairing,
  deriveKey,
  seal,
  open,
  aadForRequest,
  aadForDecision,
} from "../pwacrypto.js";

/**
 * The service worker, run for real: it receives the sealed request inside
 * the push, decrypts it with the pairing key it finds in the device store,
 * shows the actual title, and can answer straight from the notification.
 * Web Push payloads are end-to-end encrypted, so none of this reaches
 * Apple or Google — but it does reach the lock screen, hence the switch.
 */

interface Shown {
  title: string;
  options: any;
}

function bootWorker(store: unknown, env: { ua?: string; windows?: { visibilityState: string; focused: boolean }[] } = {}) {
  const handlers: Record<string, (e: any) => void> = {};
  const shown: Shown[] = [];
  const closed: string[] = [];
  const posted: unknown[] = [];
  const opened: string[] = [];
  const fetches: { url: string; body: any }[] = [];
  const context: any = {
    self: {
      addEventListener: (type: string, fn: (e: any) => void) => (handlers[type] = fn),
      skipWaiting() {},
      registration: {
        showNotification: async (title: string, options: any) => {
          shown.push({ title, options });
        },
        getNotifications: async (filter: any) =>
          shown
            .filter((n) => !filter?.tag || n.options.tag === filter.tag)
            .map((n) => ({ close: () => closed.push(n.options.tag) })),
      },
      clients: {
        matchAll: async () =>
          (env.windows ?? []).map((w) => ({ ...w, postMessage: (m: unknown) => posted.push(m) })),
        openWindow: async (url: string) => opened.push(url),
        claim: async () => {},
      },
    },
    caches: {
      open: async () => ({
        match: async () => new Response(JSON.stringify(store)),
      }),
    },
    navigator: { userAgent: env.ua ?? "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1" },
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    atob,
    btoa,
    Response,
    console,
    fetch: async (url: string, init: any) => {
      fetches.push({ url, body: JSON.parse(init.body) });
      return { ok: true };
    },
  };
  vm.createContext(context);
  vm.runInContext(PWA_SW, context);

  const dispatch = async (type: string, event: any) => {
    const pending: Promise<unknown>[] = [];
    handlers[type]!({ ...event, waitUntil: (p: Promise<unknown>) => pending.push(p) });
    await Promise.all(pending);
  };
  return { dispatch, shown, opened, fetches, closed, posted };
}

function sealedRequest(secret: string, requestId: string, extra: Record<string, unknown> = {}) {
  return seal(
    deriveKey(secret),
    { kind: "approval", title: "Pay invoice #1042", body: "$42.00 to ACME", timeoutSec: 60, ts: Date.now(), ...extra },
    aadForRequest(requestId)
  );
}

test("the notification shows what is asked, and Approve answers from the lock screen", async () => {
  const pairing = newPairing();
  const requestId = "req_" + "a".repeat(12);
  const worker = bootWorker({
    pairs: [{ name: "laptop", pairId: pairing.pairId, secret: pairing.secret }],
    details: true,
    deviceId: "device-one",
  });

  await worker.dispatch("push", {
    data: {
      json: () => ({
        type: "approval",
        pairId: pairing.pairId,
        requestId,
        payload: sealedRequest(pairing.secret, requestId),
      }),
    },
  });

  assert.equal(worker.shown.length, 1);
  const { title, options } = worker.shown[0]!;
  assert.equal(title, "Pay invoice #1042", "the real title, decrypted on the device");
  assert.equal(options.body, "$42.00 to ACME");
  // Spread first: the array was born in the worker's realm.
  assert.deepEqual(
    [...options.actions].map((a: any) => a.action),
    ["approve", "deny"],
    "a plain approval offers both answers without opening the app"
  );

  await worker.dispatch("notificationclick", {
    action: "approve",
    notification: { close() {}, data: options.data },
  });

  assert.equal(worker.fetches.length, 1);
  const sent = worker.fetches[0]!;
  assert.equal(sent.url, "/api/decision");
  assert.equal(sent.body.pairId, pairing.pairId);
  // The gateway must be able to read it with its own key, and nothing
  // else: same sealing as the page, same AAD.
  const decision = open<any>(deriveKey(pairing.secret), sent.body.payload, aadForDecision(requestId));
  assert.equal(decision.approved, true);
  assert.equal(decision.requestId, requestId);
  assert.equal(decision.deviceId, "device-one", "decisions name the device, for quorums");
  assert.equal(worker.shown[1]!.title, "Approved");
});

test("a request that must be approved with Face ID offers no shortcut", async () => {
  const pairing = newPairing();
  const requestId = "req_" + "b".repeat(12);
  const worker = bootWorker({
    pairs: [{ name: "laptop", pairId: pairing.pairId, secret: pairing.secret }],
    details: true,
  });
  await worker.dispatch("push", {
    data: {
      json: () => ({
        pairId: pairing.pairId,
        requestId,
        payload: sealedRequest(pairing.secret, requestId, { requireBiometric: true, credentialId: "cred" }),
      }),
    },
  });
  const { title, options } = worker.shown[0]!;
  assert.equal(title, "Pay invoice #1042");
  assert.equal(options.actions, undefined, "only the page can produce the biometric assertion");

  // A tap without an action opens the app instead of answering.
  await worker.dispatch("notificationclick", {
    action: "",
    notification: { close() {}, data: options.data },
  });
  assert.equal(worker.fetches.length, 0);
  assert.deepEqual(worker.opened, ["/"]);
});

test("details switched off, or an unknown vault, fall back to the generic notification", async () => {
  const pairing = newPairing();
  const requestId = "req_" + "c".repeat(12);
  const payload = sealedRequest(pairing.secret, requestId);

  const quiet = bootWorker({
    pairs: [{ name: "laptop", pairId: pairing.pairId, secret: pairing.secret }],
    details: false,
  });
  await quiet.dispatch("push", { data: { json: () => ({ pairId: pairing.pairId, requestId, payload }) } });
  assert.equal(quiet.shown[0]!.title, "sandgate");
  assert.equal(quiet.shown[0]!.options.actions, undefined);
  assert.ok(!JSON.stringify(quiet.shown[0]).includes("invoice"), "nothing decrypted must leak");

  const stranger = bootWorker({ pairs: [], details: true });
  await stranger.dispatch("push", { data: { json: () => ({ pairId: pairing.pairId, requestId, payload }) } });
  assert.equal(stranger.shown[0]!.title, "sandgate");

  // A push with no payload at all (an older relay) still rings.
  const legacy = bootWorker({ pairs: [], details: true });
  await legacy.dispatch("push", { data: { json: () => ({ type: "approval" }) } });
  assert.equal(legacy.shown[0]!.options.body, "Approval requested — tap to answer");
});

test("the app open in front: nothing rings, and Safari keeps its subscription", async () => {
  const pairing = newPairing();
  const requestId = "req_" + "d".repeat(12);
  const store = { pairs: [{ name: "laptop", pairId: pairing.pairId, secret: pairing.secret }], details: true };
  const push = { data: { json: () => ({ pairId: pairing.pairId, requestId, payload: sealedRequest(pairing.secret, requestId) }) } };
  const visible = [{ visibilityState: "visible", focused: true }];

  // Chromium waives the notification while a page of the site is visible:
  // show nothing, just tell the page.
  const chrome = bootWorker(store, {
    ua: "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    windows: visible,
  });
  await chrome.dispatch("push", push);
  assert.equal(chrome.shown.length, 0, "no notification over the open app");
  assert.deepEqual(chrome.posted, ["refresh"], "the page still reads the request at once");

  // Safari cancels the subscription after three pushes that show nothing:
  // there it is shown, silent, and closed straight away.
  const safari = bootWorker(store, { windows: visible });
  await safari.dispatch("push", push);
  assert.equal(safari.shown.length, 1, "Safari must see a notification for every push");
  assert.equal(safari.shown[0]!.options.silent, true);
  assert.deepEqual(safari.closed, ["sandgate-" + requestId], "and it is gone at once");

  // In the background (or a window behind another), it rings as before.
  for (const windows of [[], [{ visibilityState: "hidden", focused: false }], [{ visibilityState: "visible", focused: false }]]) {
    for (const ua of [undefined, "Mozilla/5.0 (Linux; Android 14) Chrome/130.0.0.0 Mobile Safari/537.36"]) {
      const w = bootWorker(store, { ua, windows });
      await w.dispatch("push", push);
      assert.equal(w.shown.length, 1);
      assert.notEqual(w.shown[0]!.options.silent, true);
      assert.equal(w.closed.length, 0);
    }
  }
});
