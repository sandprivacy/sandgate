import { GLYPH_SVG_RECTS } from "./icons.js";

/**
 * The phone-side PWA, shipped as strings so the npm package stays
 * self-contained. The inline JS mirrors src/pwacrypto.ts byte-for-byte:
 * HKDF-SHA256(salt "sandgate-pwa-v1", info "approval-channel") -> AES-256-GCM,
 * AAD "req:<id>" / "dec:<id>". The pairing secret arrives once in the URL
 * fragment (never sent to the relay) and lives in localStorage.
 *
 * Live updates: SSE (/api/events) with a slow safety poll — no visible
 * refresh; the DOM is stable and only countdown text/bars mutate in place.
 * Onboarding is per-platform: iOS home-screen apps have storage separate
 * from Safari, so the install flow carries the pairing link by hand
 * (copy → install → paste); Android installs in place via
 * beforeinstallprompt and shares storage with the browser.
 */

/**
 * Two manifests on purpose. Chrome requires start_url for installability
 * and shares storage with the installed app, so Android gets "/". iOS home
 * -screen apps have isolated storage, but WITHOUT a manifest start_url iOS
 * captures the CURRENT page URL — fragment included. The page keeps the
 * pairing link in the address bar on iOS Safari, so Add to Home Screen
 * produces an app that opens already paired. No copy-paste.
 */
export function pwaManifest(opts: { includeStartUrl: boolean }): string {
  return JSON.stringify({
    name: "sandgate",
    short_name: "sandgate",
    ...(opts.includeStartUrl ? { start_url: "/" } : {}),
    display: "standalone",
    background_color: "#141210",
    theme_color: "#141210",
    icons: [
      { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
      { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
    ],
  });
}

/**
 * Crypto for the service worker: a mirror of pwacrypto.ts (and of the
 * page's inline copy). Kept as its own string so the worker can share it
 * without dragging the page along.
 */
export const PWA_CRYPTO_JS = `
function b64uToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  var bin = atob(s), out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64u(buf) {
  var bytes = new Uint8Array(buf), bin = "";
  for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
}
var enc = new TextEncoder(), dec = new TextDecoder();
async function deriveKeyFrom(secretB64u, info) {
  var raw = await crypto.subtle.importKey("raw", b64uToBytes(secretB64u), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("sandgate-pwa-v1"), info: enc.encode(info) },
    raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function openWith(key, sealed, aad) {
  var plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64uToBytes(sealed.iv), additionalData: enc.encode(aad) },
    key, b64uToBytes(sealed.ct)
  );
  return JSON.parse(dec.decode(plain));
}
async function sealWith(key, payload, aad) {
  var iv = crypto.getRandomValues(new Uint8Array(12));
  var ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv, additionalData: enc.encode(aad) },
    key, enc.encode(JSON.stringify(payload))
  );
  return { iv: bytesToB64u(iv), ct: bytesToB64u(ct) };
}
`;

/**
 * The page mirrors its pairings into the Cache API under this key so the
 * worker — which cannot read localStorage — can decrypt a push and show
 * what is actually being asked. Same origin, same device, same sandbox.
 */
export const PWA_STORE_URL = "/__sandgate/store";

export const PWA_SW = `
${PWA_CRYPTO_JS}
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
// A fetch handler is required for Chrome's install prompt. Handle ONLY
// same-origin GETs: on iOS 16.4+, respondWith(fetch(request)) on POSTs
// (bodies) throws Internal error and silently kills subscribe/decision
// calls — anything we return from lets the browser handle natively.
self.addEventListener("fetch", function (e) {
  if (e.request.method !== "GET") return;
  e.respondWith(fetch(e.request));
});

async function loadStore() {
  try {
    var cache = await caches.open("sandgate-store");
    var hit = await cache.match("${PWA_STORE_URL}");
    if (hit) return await hit.json();
  } catch (e) {}
  return { pairs: [], details: true };
}
async function refreshPages() {
  var list = await self.clients.matchAll({ type: "window" });
  list.forEach(function (c) { c.postMessage("refresh"); });
}

// What the notification says. Generic when the worker cannot read the
// request (unknown vault, details switched off, older relay): the phone
// then behaves exactly as before — a tap opens the app.
async function describePush(data, store) {
  var out = {
    title: "sandgate",
    options: {
      body: "Approval requested — tap to answer",
      tag: "sandgate-" + (data && data.requestId ? data.requestId : "approval"),
      renotify: true,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
      data: {},
    },
  };
  if (!data || !data.pairId || !data.payload || store.details === false) return out;
  var pair = null;
  for (var i = 0; i < store.pairs.length; i++) if (store.pairs[i].pairId === data.pairId) pair = store.pairs[i];
  if (!pair) return out;
  try {
    var key = await deriveKeyFrom(pair.secret, "approval-channel");
    var req = await openWith(key, data.payload, "req:" + data.requestId);
    out.title = ((store.pairs.length > 1 && pair.name ? pair.name + ": " : "") + String(req.title || "")).slice(0, 120);
    out.options.body = String(req.body || (req.kind === "input" ? "Tap to answer" : "Tap to decide")).slice(0, 240);
    out.options.data = {
      pairId: data.pairId,
      requestId: data.requestId,
      kind: req.kind,
      requireBiometric: !!req.requireBiometric,
    };
    // Yes/no straight from the lock screen — but never past a biometric
    // requirement, which only the page can satisfy.
    if (req.kind === "approval" && !req.requireBiometric) {
      out.options.actions = [
        { action: "approve", title: "Approve" },
        { action: "deny", title: "Deny" },
      ];
    }
  } catch (e) {}
  return out;
}

// A server that went quiet, or came back. The relay knows only the pair
// id; the name comes from this device's own list.
function describeServerPush(data, store) {
  var pair = null;
  for (var i = 0; i < store.pairs.length; i++) if (store.pairs[i].pairId === data.pairId) pair = store.pairs[i];
  var name = pair && pair.name ? pair.name : "A server";
  var d = new Date(data.since || Date.now());
  var hm = ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
  var back = data.state === "online";
  return {
    title: back ? name + " is back" : name + " stopped responding",
    options: {
      body: back ? "Heartbeat received again." : "No heartbeat since " + hm + ". Down, or cut off from the relay.",
      tag: "sandgate-server-" + data.pairId,
      renotify: true,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
      data: {},
    },
  };
}

// The app open and in front of you already shows the card (or the server
// alert): ringing on top of it is noise. How to stay quiet depends on the
// browser. Chromium waives the "every push shows a notification" rule
// while a page of the site is visible, so it shows nothing. Safari does
// not: a push that shows nothing counts as silent, and after three it
// cancels the subscription for good. There, the notification is shown,
// silent, and closed at once.
var UA = (typeof navigator !== "undefined" && navigator.userAgent) || "";
var CHROMIUM = /Chrome\\/|Chromium\\//.test(UA) && !/iPhone|iPad|iPod/.test(UA);
async function appInFront() {
  try {
    var list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    return list.some(function (c) { return c.visibilityState === "visible" && c.focused !== false; });
  } catch (e) { return false; }
}

self.addEventListener("push", function (e) {
  e.waitUntil((async function () {
    var data = null;
    try { data = e.data ? e.data.json() : null; } catch (err) {}
    var store = await loadStore();
    var desc = data && data.type === "server" ? describeServerPush(data, store) : await describePush(data, store);
    var front = await appInFront();
    if (front && CHROMIUM) { await refreshPages(); return; }
    if (front) desc.options.silent = true;
    await self.registration.showNotification(desc.title, desc.options);
    if (front && self.registration.getNotifications) {
      try {
        var shown = await self.registration.getNotifications({ tag: desc.options.tag });
        shown.forEach(function (n) { n.close(); });
      } catch (err) {}
    }
    await refreshPages();
  })());
});

async function answerFromNotification(d, approved) {
  var store = await loadStore();
  var pair = null;
  for (var i = 0; i < store.pairs.length; i++) if (store.pairs[i].pairId === d.pairId) pair = store.pairs[i];
  if (!pair) return self.clients.openWindow("/");
  var key = await deriveKeyFrom(pair.secret, "approval-channel");
  var payload = await sealWith(
    key,
    { requestId: d.requestId, approved: approved, ts: Date.now(), deviceId: store.deviceId },
    "dec:" + d.requestId
  );
  // Same patience as the page: a lock-screen tap often lands while the
  // phone's network is still waking up.
  var res = null;
  for (var attempt = 0; attempt < 4; attempt++) {
    if (attempt) await new Promise(function (r) { setTimeout(r, 700 * attempt); });
    try {
      res = await fetch("/api/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: d.pairId, requestId: d.requestId, payload: payload }),
      });
      if (res.ok || (res.status !== 429 && !(res.status >= 500))) break;
    } catch (e) { res = null; }
  }
  var ok = !!res && res.ok;
  var gone = !!res && res.status === 404;
  await self.registration.showNotification(
    ok ? (approved ? "Approved" : "Denied") : gone ? "Too late" : "Could not send your answer",
    {
      body: ok ? "" : gone ? "That request had already expired or been answered." : "Open the app to try again.",
      tag: "sandgate-" + d.requestId,
      icon: "/icon-192.png",
    }
  );
  await refreshPages();
}

self.addEventListener("notificationclick", function (e) {
  e.notification.close();
  var d = e.notification.data || {};
  if ((e.action === "approve" || e.action === "deny") && d.pairId && d.requestId) {
    e.waitUntil(answerFromNotification(d, e.action === "approve"));
    return;
  }
  e.waitUntil((async function () {
    var clientList = await self.clients.matchAll({ type: "window" });
    if (clientList.length) {
      // The page was asleep: tell it to read the requests now, not when
      // its next poll comes round.
      clientList[0].postMessage("open");
      return clientList[0].focus();
    }
    return self.clients.openWindow("/");
  })());
});
`;

const GATE_GLYPH = (size: number, className: string) =>
  `<svg class="${className}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${GLYPH_SVG_RECTS}</svg>`;

const CHECK_ICON =
  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4.5 12.5l5 5L19.5 6.5"/></svg>';
const CROSS_ICON =
  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" aria-hidden="true"><path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/></svg>';

const tabIcon = (paths: string) =>
  `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths}</svg>`;
const TAB_ICONS = {
  req: tabIcon('<path d="M4 13l2.5-7h11L20 13v5H4z"/><path d="M4 13h4.5l1 2h5l1-2H20"/>'),
  srv: tabIcon('<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M8 7h.01M8 17h.01"/>'),
  hist: tabIcon('<circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/>'),
  set: tabIcon('<path d="M5 7h9M18 7h1M5 17h1M10 17h9"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>'),
};

export const PWA_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="sandgate">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="theme-color" content="#141210">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/icon-180.png">
<title>sandgate</title>
<style>
  :root {
    color-scheme: dark;
    --ground: #141210;
    --panel: #1e1b16;
    --panel-raised: #262219;
    --line: #35301f;
    --ink: #efe9db;
    --soft: #a69c85;
    --accent: #d9a441;
    --ok: #3f9169;
    --ok-press: #337a57;
    --no: #c2563e;
    --no-press: #a64732;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--ground);
    color: var(--ink);
    font: 16px/1.5 -apple-system, "SF Pro Text", "Segoe UI", Roboto, system-ui, sans-serif;
    min-height: 100dvh;
  }
  header {
    position: sticky; top: 0; z-index: 2;
    display: flex; align-items: center; gap: 12px;
    padding: calc(env(safe-area-inset-top, 0px) + 10px) 18px 10px;
    background: color-mix(in srgb, var(--ground) 88%, transparent);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }
  .logo {
    width: 34px; height: 34px; border-radius: 10px;
    background: linear-gradient(145deg, #241f14, #1a1610);
    border: 1px solid #453a1e;
    display: grid; place-items: center;
    color: var(--accent);
    box-shadow: inset 0 1px 0 rgba(217,164,65,.12);
  }
  .title { flex: 1; }
  .title h1 { font-size: 17px; margin: 0; letter-spacing: .01em; }
  .title .sub { font-size: 11.5px; color: var(--soft); letter-spacing: .06em; text-transform: uppercase; }
  .pill {
    display: flex; align-items: center; gap: 6px;
    font-size: 11px; font-weight: 600; letter-spacing: .04em;
    padding: 5px 10px; border-radius: 999px; white-space: nowrap;
    background: #26311f; color: #9dc98a; border: 1px solid #3b4a30;
  }
  .pill::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
  .pill.warn { background: #332a17; color: var(--accent); border-color: #4a3d1f; }
  .pill.err  { background: #331d17; color: #d98a76; border-color: #4a2a1f; }

  main { max-width: 520px; margin: 0 auto; padding: 16px 16px calc(env(safe-area-inset-bottom, 0px) + 96px); }

  /* One screen per job, a tab bar at the thumb: requests never sit above
     a page of servers and history again. */
  .view { display: none; }
  .view.on { display: block; }
  .tabs {
    position: fixed; left: 0; right: 0; bottom: 0; z-index: 3;
    display: flex; justify-content: center;
    padding: 6px 8px calc(env(safe-area-inset-bottom, 0px) + 6px);
    background: color-mix(in srgb, var(--ground) 92%, transparent);
    backdrop-filter: blur(10px);
    border-top: 1px solid var(--line);
  }
  .tabs[hidden] { display: none; }
  .tabs button {
    position: relative; flex: 1; max-width: 130px;
    display: flex; flex-direction: column; align-items: center; gap: 2px;
    padding: 6px 0 4px; border: 0; background: none; cursor: pointer;
    color: var(--soft); font: 600 11px/1.2 inherit; font-family: inherit; letter-spacing: .02em;
  }
  .tabs button[aria-selected="true"] { color: var(--accent); }
  .tabs .badge {
    position: absolute; top: 0; left: calc(50% + 6px);
    min-width: 18px; height: 18px; padding: 0 5px; border-radius: 9px;
    background: var(--accent); color: #1a1508;
    font: 700 11px/18px inherit; font-family: inherit; font-style: normal; text-align: center;
  }
  .tabs .badge.red { background: var(--no); color: #fff; }
  .tabs .badge:empty { display: none; }

  .alert {
    display: flex; align-items: center; gap: 10px; width: 100%;
    margin: 0 0 14px; padding: 11px 14px; border-radius: 12px; cursor: pointer;
    background: rgba(194,86,62,.13); border: 1px solid #4a2a1f; color: #e8a28f;
    font: 600 14px/1.35 inherit; font-family: inherit; text-align: left;
  }
  .alert .txt { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .alert::before { content: ""; width: 8px; height: 8px; border-radius: 50%; background: var(--no); flex: none; }
  .section-h { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--soft); margin: 22px 0 6px; }
  .section-h:first-child { margin-top: 2px; }
  .note { color: var(--soft); font-size: 12.5px; margin: 10px 0 0; }

  .banner {
    background: var(--panel-raised); border: 1px solid #4a3d1f; border-radius: 14px;
    padding: 16px; margin-bottom: 16px;
  }
  .banner h2 { font-size: 15.5px; margin: 0 0 8px; color: var(--accent); }
  .banner ol { margin: 0 0 12px; padding-left: 20px; font-size: 14px; color: #cfc6b2; }
  .banner ol li { margin-bottom: 4px; }
  .banner .act {
    width: 100%; padding: 12px; border: 0; border-radius: 10px; cursor: pointer;
    background: var(--accent); color: #1a1508; font: 650 15px/1 inherit; font-family: inherit;
  }

  .card {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 16px 16px 14px;
    margin-bottom: 14px;
    scroll-margin-top: calc(env(safe-area-inset-top, 0px) + 72px);
    animation: rise .25s ease-out;
  }
  @keyframes rise { from { opacity: 0; transform: translateY(6px); } }
  @media (prefers-reduced-motion: reduce) { .card { animation: none; } }
  .card .who { font-size: 11px; color: var(--accent); letter-spacing: .08em; text-transform: uppercase; margin-bottom: 6px; }
  .card h2 { font-size: 18px; line-height: 1.3; margin: 0 0 6px; }
  .card p { margin: 0 0 12px; color: #cfc6b2; font-size: 14.5px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .timer { display: flex; align-items: center; gap: 10px; margin-bottom: 14px; }
  .timer .left { font-size: 12px; color: var(--soft); min-width: 96px; font-variant-numeric: tabular-nums; }
  .bar { flex: 1; height: 4px; border-radius: 2px; background: var(--line); overflow: hidden; }
  .bar i { display: block; height: 100%; background: var(--accent); border-radius: 2px; transition: width 1s linear; }
  .bar.low i { background: var(--no); }
  .row { display: flex; gap: 10px; }
  .card button {
    flex: 1; display: flex; align-items: center; justify-content: center; gap: 8px;
    padding: 13px; font-size: 15.5px; font-weight: 650;
    border: 0; border-radius: 10px; cursor: pointer; color: #fff;
    font-family: inherit; letter-spacing: .01em;
    transition: transform .06s ease;
  }
  .card button:active { transform: scale(.97); }
  .card button:disabled { opacity: .5; }
  .ok { background: var(--ok); } .ok:active { background: var(--ok-press); }
  .no { background: var(--no); } .no:active { background: var(--no-press); }
  .expired { opacity: .45; }
  .expired h2 { text-decoration: line-through; text-decoration-thickness: 1px; }

  .empty { text-align: center; padding: 56px 20px; color: var(--soft); }
  .empty .mark { color: var(--accent); opacity: .3; margin-bottom: 16px; }
  .empty .big { font-size: 16px; color: #cfc6b2; margin-bottom: 4px; }
  .empty .hint { font-size: 13px; }

  .setup { text-align: center; padding: 48px 8px; color: #cfc6b2; }
  .setup .mark { color: var(--accent); opacity: .5; margin-bottom: 16px; }
  .setup p { font-size: 14.5px; margin: 0 0 14px; }
  .setup code {
    display: inline-block; padding: 8px 14px; border-radius: 8px;
    background: var(--panel-raised); border: 1px solid var(--line);
    font: 14px ui-monospace, "Cascadia Mono", monospace; color: var(--accent);
  }
  .setup input {
    width: 100%; padding: 12px 14px; margin: 14px 0 10px;
    background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
    /* 16px minimum: below that, iOS Safari auto-zooms into focused inputs. */
    color: var(--ink); font: 16px ui-monospace, monospace;
  }
  .setup input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }

  .hrow { display: flex; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13.5px; }
  .hrow .time { color: var(--soft); font-variant-numeric: tabular-nums; font-size: 12px; min-width: 46px; }
  .hrow .t { flex: 1; color: #cfc6b2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hrow .d { font-weight: 650; font-size: 10.5px; letter-spacing: .05em; text-transform: uppercase; }
  .d.approved { color: #7fbf9a; }
  .d.answered { color: #7fbf9a; }
  .d.denied { color: #d98a76; }
  .d.expired { color: var(--soft); }
  .hrow.tap { cursor: pointer; }
  .hrow.open .t { white-space: normal; }
  .hmore {
    padding: 8px 10px 10px 56px; border-bottom: 1px solid var(--line);
    color: #cfc6b2; font-size: 13px; white-space: pre-wrap; overflow-wrap: anywhere;
  }
  .jump {
    position: fixed; left: 50%; bottom: calc(76px + env(safe-area-inset-bottom)); transform: translateX(-50%);
    z-index: 10; border: 0; border-radius: 999px; padding: 11px 18px;
    background: var(--accent); color: #1a1408; font: 650 14.5px/1 inherit; font-family: inherit;
    box-shadow: 0 6px 24px rgba(0,0,0,.45); cursor: pointer;
  }

  .sum { display: flex; gap: 14px; flex-wrap: wrap; font-size: 13px; color: var(--soft); margin: 2px 0 10px; }
  .sum b { color: var(--ink); font-weight: 650; }
  .sum .bad b { color: #e8a28f; }
  .srv { padding: 11px 2px; border-bottom: 1px solid var(--line); font-size: 13px; cursor: pointer; }
  .srv .top { display: flex; gap: 8px; align-items: center; }
  .srv .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--soft); flex: none; }
  .srv .dot.up { background: #7fbf9a; }
  .srv .dot.down { background: var(--no); }
  .srv .name { flex: 1; color: var(--ink); font-weight: 650; font-size: 14.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .srv .seen { color: var(--soft); font-size: 12px; font-variant-numeric: tabular-nums; white-space: nowrap; }
  .srv .seen.down { color: #d98a76; font-weight: 650; }
  .srv .chev { color: var(--soft); font-size: 12px; transition: transform .15s; }
  .srv.open .chev { transform: rotate(90deg); }
  .srv .line { margin: 3px 0 0 16px; color: var(--soft); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .srv .line.fail { color: #e8a28f; font-weight: 600; }
  .srv .line.warn { color: var(--accent); }
  .srv .more { display: none; margin-left: 16px; }
  .srv.open .more { display: block; }
  .srv.open .line { white-space: normal; }
  .srv .meta { color: var(--soft); margin-top: 4px; overflow-wrap: anywhere; }
  .srv .flag { margin-top: 6px; padding: 7px 9px; border-radius: 8px; font-size: 12.5px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .srv .flag.fail { background: rgba(217,138,118,.12); color: #e8a28f; }
  .srv .flag.warn { background: rgba(217,164,65,.12); color: var(--accent); }
  .srv .flag b { font-weight: 650; }

  .answer-input {
    width: 100%; box-sizing: border-box; padding: 12px 14px; margin: 0 0 12px;
    background: var(--panel-raised); border: 1px solid var(--line); border-radius: 10px;
    /* 16px minimum: below that, iOS Safari auto-zooms into focused inputs. */
    color: var(--ink); font: 16px ui-monospace, monospace;
  }
  .answer-input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
  .answer-input:disabled { opacity: .5; }
  .ghost {
    display: block; width: 100%; padding: 12px; margin-top: 10px;
    border-radius: 10px; cursor: pointer;
    background: transparent; border: 1px solid var(--line); color: #cfc6b2;
    font: 600 14.5px/1 inherit; font-family: inherit;
  }
  .ghost:active { background: var(--panel-raised); }
  .scan {
    position: fixed; inset: 0; z-index: 20;
    background: var(--ground);
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 18px; padding: 24px;
  }
  .scan .frame {
    position: relative; width: min(86vw, 420px); aspect-ratio: 1;
    border-radius: 18px; overflow: hidden; background: #000;
    border: 1px solid var(--line);
  }
  .scan video { display: block; width: 100%; height: 100%; object-fit: cover; }
  .scan .frame::after {
    content: ""; position: absolute; inset: 14%; border-radius: 14px;
    border: 2px solid rgba(217,164,65,.75); pointer-events: none;
  }
  .scan p { color: var(--soft); font-size: 14px; text-align: center; margin: 0; max-width: 320px; }
  .scan .ghost { width: auto; min-width: 180px; margin-top: 0; }
</style>
</head>
<body>
<header>
  <div class="logo">${GATE_GLYPH(22, "mark")}</div>
  <div class="title">
    <h1>sandgate</h1>
  </div>
  <div class="pill warn" id="status">starting</div>
</header>
<main>
  <section class="view on" id="v-req"><div id="banner"></div><div id="alerts"></div><div id="list"></div></section>
  <section class="view" id="v-srv"><div id="servers"></div></section>
  <section class="view" id="v-hist"><div id="hist"></div></section>
  <section class="view" id="v-set"><div id="vaults"></div></section>
</main>
<nav class="tabs" id="tabs" hidden>
  <button data-tab="req" aria-selected="true">${TAB_ICONS.req}<span>Requests</span><i class="badge" id="b-req"></i></button>
  <button data-tab="srv" aria-selected="false">${TAB_ICONS.srv}<span>Servers</span><i class="badge red" id="b-srv"></i></button>
  <button data-tab="hist" aria-selected="false">${TAB_ICONS.hist}<span>History</span></button>
  <button data-tab="set" aria-selected="false">${TAB_ICONS.set}<span>Settings</span></button>
</nav>
<script>
(function () {
  var PAIR_KEY = "sandgate_pair";
  var GLYPH = '${GATE_GLYPH(56, "mark").replace(/'/g, "\\'")}';
  var CHECK = '${CHECK_ICON.replace(/'/g, "\\'")}';
  var CROSS = '${CROSS_ICON.replace(/'/g, "\\'")}';

  function b64uToBytes(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function bytesToB64u(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  var enc = new TextEncoder(), dec = new TextDecoder();

  var statusEl = document.getElementById("status");
  var listEl = document.getElementById("list");
  var bannerEl = document.getElementById("banner");
  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "pill" + (cls ? " " + cls : "");
  }

  var standalone =
    (window.matchMedia && window.matchMedia("(display-mode: standalone)").matches) ||
    window.navigator.standalone === true;
  var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
  var isAndroid = /Android/.test(navigator.userAgent);

  // --- pairing -------------------------------------------------------------
  // Two link shapes. "c=" is a one-time claim: the channel secret is
  // collected from the relay exactly once, so the link dies after use.
  // "s=" carries the secret itself — older gateways, kept working.
  function parsePairing(text) {
    var str = String(text);
    var mm = str.match(/p=([A-Za-z0-9_-]{8,64})&(s|c)=([A-Za-z0-9_-]{8,})/);
    if (!mm) return null;
    var out = { pairId: mm[1] };
    if (mm[2] === "c") out.claim = mm[3]; else out.secret = mm[3];
    var nm = str.match(/[&#]n=([^&]+)/);
    if (nm) { try { out.name = decodeURIComponent(nm[1]).slice(0, 40); } catch (e) {} }
    return out;
  }
  // Several vaults can pair with this device (your laptop, your server…):
  // pairings are a list, requests from all of them show together.
  var PAIRS_KEY = "sandgate_pairs";
  function loadPairs() {
    try {
      var list = JSON.parse(localStorage.getItem(PAIRS_KEY));
      if (Array.isArray(list) && list.length) return list;
    } catch (e) {}
    // Migrate the single-pairing storage of earlier versions.
    try {
      var old = JSON.parse(localStorage.getItem(PAIR_KEY));
      if (old && old.pairId) {
        var migrated = [{ name: "Vault 1", pairId: old.pairId, secret: old.secret }];
        localStorage.setItem(PAIRS_KEY, JSON.stringify(migrated));
        localStorage.removeItem(PAIR_KEY);
        return migrated;
      }
    } catch (e) {}
    return [];
  }
  var pairs = loadPairs();
  // This device's identity in decisions: lets a gateway that wants several
  // approvals tell two phones apart. Random, local, never a person.
  var DEVICE_KEY = "sandgate_device";
  var deviceId = null;
  try { deviceId = localStorage.getItem(DEVICE_KEY); } catch (e) {}
  if (!deviceId) {
    deviceId = bytesToB64u(crypto.getRandomValues(new Uint8Array(12)));
    try { localStorage.setItem(DEVICE_KEY, deviceId); } catch (e) {}
  }
  var DETAILS_KEY = "sandgate_notif_details";
  function notifDetails() {
    try { return localStorage.getItem(DETAILS_KEY) !== "off"; } catch (e) { return true; }
  }
  // The worker cannot read localStorage; hand it what it needs to show a
  // real title on the lock screen and answer from there.
  function syncStore() {
    if (!("caches" in window)) return;
    caches.open("sandgate-store").then(function (cache) {
      return cache.put("${PWA_STORE_URL}", new Response(
        JSON.stringify({ pairs: pairs, details: notifDetails(), deviceId: deviceId }),
        { headers: { "Content-Type": "application/json" } }
      ));
    }).catch(function () {});
  }
  function savePairs() {
    try { localStorage.setItem(PAIRS_KEY, JSON.stringify(pairs)); } catch (e) {}
    syncStore();
  }
  // Requests this device already answered. With a quorum the relay keeps
  // showing a request until enough devices have spoken; this one is done.
  var ANSWERED_KEY = "sandgate_answered";
  var answered = [];
  try { answered = JSON.parse(localStorage.getItem(ANSWERED_KEY)) || []; } catch (e) {}
  function markAnswered(requestId) {
    answered.push(requestId);
    while (answered.length > 200) answered.shift();
    try { localStorage.setItem(ANSWERED_KEY, JSON.stringify(answered)); } catch (e) {}
  }
  syncStore();
  function addPairing(parsed) {
    for (var i = 0; i < pairs.length; i++) {
      if (pairs[i].pairId === parsed.pairId) return false;
    }
    pairs.push({
      name: parsed.name || ("Vault " + (pairs.length + 1)),
      pairId: parsed.pairId,
      secret: parsed.secret,
    });
    savePairs();
    return true;
  }
  /** Collect the channel secret behind a one-time claim link. */
  async function resolveClaim(parsed) {
    var res = await fetch("/api/claim?pairId=" + encodeURIComponent(parsed.pairId));
    if (res.status === 404) throw new Error("This pairing link has expired or was already used. Run sandgate pair again.");
    if (!res.ok) throw new Error("relay answered HTTP " + res.status);
    var sealed = (await res.json()).payload;
    var key = await deriveKeyFrom(parsed.claim, "pairing-claim");
    var plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uToBytes(sealed.iv), additionalData: enc.encode("claim:" + parsed.pairId) },
      key, b64uToBytes(sealed.ct)
    );
    var payload = JSON.parse(dec.decode(plain));
    return { pairId: parsed.pairId, secret: payload.secret, name: parsed.name || payload.name };
  }
  /** Any text that might be a pairing link: pasted, scanned, or from the URL. */
  async function acceptPairingText(text) {
    var parsed = parsePairing(text);
    if (!parsed) return false;
    if (parsed.claim) parsed = await resolveClaim(parsed);
    return addPairing(parsed);
  }
  function loadJsQr() {
    return new Promise(function (resolve, reject) {
      if (window.jsQR) return resolve(window.jsQR);
      var el = document.createElement("script");
      el.src = "/jsqr.js";
      el.onload = function () { window.jsQR ? resolve(window.jsQR) : reject(new Error("QR decoder did not load")); };
      el.onerror = function () { reject(new Error("QR decoder did not load")); };
      document.head.appendChild(el);
    });
  }
  /** Open the camera and hand back the first pairing link it sees. */
  async function scanPairing(onText) {
    var overlay = document.createElement("div");
    overlay.className = "scan";
    overlay.innerHTML =
      '<div class="frame"><video></video></div>' +
      '<p>Point the camera at the QR code printed by sandgate pair</p>' +
      '<button class="ghost">Cancel</button>';
    document.body.appendChild(overlay);
    var video = overlay.querySelector("video");
    // Set as properties, not attributes: Safari ignores muted/playsinline
    // that arrive through innerHTML, and a video that is not both stays
    // black on iPhone.
    video.muted = true;
    video.playsInline = true;
    video.setAttribute("playsinline", "");
    video.autoplay = true;
    var stream = null;
    function stop() {
      if (stream) stream.getTracks().forEach(function (t) { t.stop(); });
      overlay.remove();
    }
    overlay.querySelector("button").onclick = stop;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      video.srcObject = stream;
      await video.play();
      var detector = ("BarcodeDetector" in window) ? new BarcodeDetector({ formats: ["qr_code"] }) : null;
      var jsqr = detector ? null : await loadJsQr();
      var canvas = document.createElement("canvas");
      var ctx = canvas.getContext("2d", { willReadFrequently: true });
      var tick = async function () {
        if (!overlay.isConnected) return;
        var text = null;
        try {
          if (detector) {
            var codes = await detector.detect(video);
            if (codes.length) text = codes[0].rawValue;
          } else if (video.videoWidth) {
            canvas.width = video.videoWidth; canvas.height = video.videoHeight;
            ctx.drawImage(video, 0, 0);
            var img = ctx.getImageData(0, 0, canvas.width, canvas.height);
            var code = jsqr(img.data, img.width, img.height);
            if (code) text = code.data;
          }
        } catch (e) {}
        if (text && parsePairing(text)) { stop(); onText(text); return; }
        requestAnimationFrame(tick);
      };
      tick();
    } catch (err) {
      stop();
      alert("Camera unavailable: " + (err && err.message ? err.message : err) + "\\n\\nPaste the link instead.");
    }
  }
  /** What a scanned or pasted link leads to: add the vault, start over paired. */
  function takePairingText(text) {
    return acceptPairingText(text).then(function (added) {
      if (added) location.reload();
      return added;
    }).catch(function (err) { alert(err && err.message ? err.message : err); return false; });
  }
  function makeScanButton() {
    var b = document.createElement("button");
    b.className = "ghost";
    b.textContent = "Scan a QR code";
    b.onclick = function () { scanPairing(takePairingText); };
    return b;
  }
  window.sandgate = { acceptPairingText: acceptPairingText, parsePairing: parsePairing, takePairingText: takePairingText };
  var candidate = parsePairing(location.hash);
  if (candidate && candidate.claim) {
    // A claim needs the network: collect it, then start over paired.
    setStatus("pairing", "warn");
    acceptPairingText(location.hash).then(function () {
      location.replace(location.pathname);
    }).catch(function (err) {
      setStatus("not paired", "err");
      var box = document.createElement("div");
      box.className = "setup";
      box.innerHTML = '<div class="mark">' + GLYPH + '</div><p></p>';
      box.querySelector("p").textContent = err && err.message ? err.message : String(err);
      listEl.appendChild(box);
    });
    return;
  }
  if (candidate) {
    addPairing(candidate);
    // iOS Safari (not installed): KEEP the pairing link in the address bar.
    // With no start_url in the Apple manifest, Add to Home Screen captures
    // this exact URL — fragment included — so the installed app opens
    // already paired despite iOS's isolated storage.
    if (!(isIOS && !standalone)) {
      history.replaceState(null, "", location.pathname);
    }
  }

  if (!pairs.length) {
    setStatus("not paired", "err");
    var setup = document.createElement("div");
    setup.className = "setup";
    setup.innerHTML =
      '<div class="mark">' + GLYPH + '</div>' +
      '<p>Not paired yet. On your computer, run</p><code>sandgate pair</code>' +
      '<p style="margin-top:14px">then open the link it prints on this device —<br>or paste it here:</p>' +
      '<input id="pasteLink" placeholder="https://relay…/#p=…&c=…" autocomplete="off">';
    listEl.appendChild(setup);
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) setup.appendChild(makeScanButton());
    document.getElementById("pasteLink").addEventListener("input", function (e) {
      if (!parsePairing(e.target.value)) return;
      acceptPairingText(e.target.value).then(function (added) {
        if (added) location.replace(location.pathname);
      }).catch(function (err) { alert(err && err.message ? err.message : err); });
    });
    return;
  }

  // --- install guidance (mobile browser, not yet installed) ---------------
  var deferredInstall = null;
  window.addEventListener("beforeinstallprompt", function (e) {
    e.preventDefault();
    deferredInstall = e;
    renderBanner();
  });

  function renderBanner() {
    if (standalone || (!isIOS && !isAndroid)) { bannerEl.textContent = ""; return; }
    var b = document.createElement("div");
    b.className = "banner";
    if (isIOS) {
      b.innerHTML =
        '<h2>Install sandgate to get push notifications</h2>' +
        '<ol><li>Tap Share (the square with an arrow)</li>' +
        '<li>Choose "Add to Home Screen"</li>' +
        '<li>Open sandgate from your home screen — your pairing carries over</li></ol>';
      bannerEl.textContent = ""; bannerEl.appendChild(b);
    } else {
      b.innerHTML =
        '<h2>Install sandgate to get push notifications</h2>' +
        '<ol><li>Install the app (your pairing carries over automatically)</li>' +
        '<li>Open it from your home screen and allow notifications</li></ol>' +
        '<button class="act" id="installBtn">' + (deferredInstall ? "Install the app" : "Open browser menu → Install app") + '</button>';
      bannerEl.textContent = ""; bannerEl.appendChild(b);
      document.getElementById("installBtn").addEventListener("click", function () {
        if (deferredInstall) deferredInstall.prompt();
      });
    }
  }
  renderBanner();

  // --- tabs ----------------------------------------------------------------
  // Requests, servers, history and settings used to be one long page: a
  // card could land out of sight above a screenful of servers, and a
  // silent server sat somewhere below the history. One screen each now.
  var tabsEl = document.getElementById("tabs");
  var currentTab = "req";
  tabsEl.hidden = false;
  function showTab(name) {
    currentTab = name;
    ["req", "srv", "hist", "set"].forEach(function (t) {
      document.getElementById("v-" + t).className = "view" + (t === name ? " on" : "");
      tabsEl.querySelector('[data-tab="' + t + '"]').setAttribute("aria-selected", t === name ? "true" : "false");
    });
    window.scrollTo(0, 0);
    updateJumpPill();
  }
  Array.prototype.forEach.call(tabsEl.querySelectorAll("button"), function (b) {
    b.onclick = function () { showTab(b.getAttribute("data-tab")); };
  });
  function setBadge(id, n) {
    var el = document.getElementById(id);
    el.textContent = n > 0 ? String(n) : "";
  }

  // The app on screen is the notification: clear what the lock screen
  // still shows, it is all here (and some of it already answered).
  function clearNotifications() {
    swRegPromise
      .then(function (reg) { return reg && reg.getNotifications ? reg.getNotifications() : []; })
      .then(function (list) { list.forEach(function (n) { n.close(); }); })
      .catch(function () {});
  }

  // --- crypto (mirror of pwacrypto.ts), one derived key per vault ----------
  var keyCache = {};
  async function deriveKeyFrom(secretB64u, info) {
    var raw = await crypto.subtle.importKey("raw", b64uToBytes(secretB64u), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode("sandgate-pwa-v1"), info: enc.encode(info) },
      raw, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }
  function keyFor(p) {
    if (!keyCache[p.pairId]) keyCache[p.pairId] = deriveKeyFrom(p.secret, "approval-channel");
    return keyCache[p.pairId];
  }
  async function openSealed(p, sealed, aad) {
    var key = await keyFor(p);
    var pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uToBytes(sealed.iv), additionalData: enc.encode(aad) },
      key,
      b64uToBytes(sealed.ct)
    );
    return JSON.parse(dec.decode(pt));
  }
  async function sealPayload(p, payload, aad) {
    var key = await keyFor(p);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode(aad) },
      key,
      enc.encode(JSON.stringify(payload))
    );
    return { iv: bytesToB64u(iv), ct: bytesToB64u(ct) };
  }

  // --- WebAuthn ceremonies (Face ID / Touch ID) ---------------------------
  // The challenge is derived from the request id on both sides, so an
  // assertion is worthless on any other request. sandgate only ever sees
  // the public key: the private key never leaves the secure enclave.
  async function webauthnChallenge(requestId) {
    var digest = await crypto.subtle.digest(
      "SHA-256",
      enc.encode("sandgate-webauthn-v1:" + requestId)
    );
    return new Uint8Array(digest);
  }

  async function doEnroll(requestId) {
    if (!window.PublicKeyCredential) throw new Error("this device has no passkey support");
    var cred = await navigator.credentials.create({
      publicKey: {
        challenge: await webauthnChallenge(requestId),
        rp: { id: location.hostname, name: "sandgate" },
        user: {
          id: crypto.getRandomValues(new Uint8Array(16)),
          name: "sandgate",
          displayName: "sandgate",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "discouraged",
        },
        attestation: "none",
        timeout: 60000,
      },
    });
    var spki = cred.response.getPublicKey && cred.response.getPublicKey();
    if (!spki) throw new Error("this device did not expose the public key");
    return {
      credentialId: bytesToB64u(cred.rawId),
      publicKeySpki: bytesToB64u(spki),
      clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
    };
  }

  async function doAssert(requestId, credentialId) {
    if (!window.PublicKeyCredential) throw new Error("this device has no passkey support");
    var assertion = await navigator.credentials.get({
      publicKey: {
        challenge: await webauthnChallenge(requestId),
        rpId: location.hostname,
        allowCredentials: credentialId
          ? [{ type: "public-key", id: b64uToBytes(credentialId) }]
          : undefined,
        userVerification: "required",
        timeout: 60000,
      },
    });
    return {
      credentialId: bytesToB64u(assertion.rawId),
      authenticatorData: bytesToB64u(assertion.response.authenticatorData),
      clientDataJSON: bytesToB64u(assertion.response.clientDataJSON),
      signature: bytesToB64u(assertion.response.signature),
    };
  }

  // --- presence + push subscription ---------------------------------------
  // Announce this page to the relay immediately (push or not), so the
  // "sandgate pair" command can report "phone connected" without waiting
  // on notification permission.
  pairs.forEach(function (p) {
    fetch("/api/hello", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId: p.pairId }),
    }).catch(function () {});
  });

  var pushOn = false;
  var swRegPromise = "serviceWorker" in navigator
    ? navigator.serviceWorker.register("/sw.js").then(function (reg) {
        navigator.serviceWorker.addEventListener("message", function (e) {
          // From a tapped notification: go straight to the card it was about.
          // A push read in the background: refresh; the pill shows if the
          // card lands off-screen — no jumping under your thumb.
          if (e.data === "refresh") fetchPending();
          if (e.data === "open") { scrollToCards = true; fetchPending(); }
        });
        return reg;
      })
    : Promise.resolve(null);

  /** Tell the relay this device's push endpoint serves these vaults. */
  function registerSubscription(sub) {
    return Promise.all(
      pairs.map(function (p) {
        return fetch("/api/subscribe", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pairId: p.pairId, subscription: sub }),
        });
      })
    );
  }

  /**
   * Re-register the existing subscription for EVERY vault on every load.
   * Vaults are registered one by one against a device subscription, so a
   * vault added after notifications were switched on would otherwise
   * never ring — which is exactly what happened with the first server.
   * getSubscription needs no permission and no user gesture.
   */
  async function syncSubscription() {
    var reg = await swRegPromise;
    if (!reg || !("PushManager" in window)) return false;
    var existing = await reg.pushManager.getSubscription();
    if (!existing) return false;
    await registerSubscription(existing);
    pushOn = true;
    setStatus("push on");
    renderVaults();
    return true;
  }

  async function enablePush() {
    var reg = await swRegPromise;
    if (!reg || !("PushManager" in window)) return false;
    // Only ask when we actually need to: on iOS, requestPermission outside
    // a user gesture can fail even when permission was already granted.
    if (Notification.permission !== "granted") {
      var perm = await Notification.requestPermission();
      if (perm !== "granted") return false;
    }
    var vapid = await (await fetch("/api/vapid")).json();
    var sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64uToBytes(vapid.publicKey),
    });
    await registerSubscription(sub);
    pushOn = true;
    setStatus("push on");
    renderVaults();
    var btn = document.getElementById("pushBtn");
    if (btn && btn.parentElement) btn.parentElement.remove();
    return true;
  }

  function showPushError(err) {
    setStatus("push error", "err");
    alert(
      "Notifications could not be enabled: " +
        (err && err.message ? err.name + " — " + err.message : err) +
        "\\n\\nOn iPhone this requires iOS 16.4+, the app installed on the home screen, and Lockdown Mode off."
    );
  }

  (async function () {
    try {
      if (await syncSubscription()) return; // already on, every vault covered
    } catch (e) { /* fall through to the button */ }

    if (!("Notification" in window) || !("PushManager" in window)) {
      setStatus(sseOn ? "live" : "polling", "warn");
      return;
    }
    if (isIOS && !standalone) return; // impossible in a Safari tab; the banner explains
    if (Notification.permission === "denied") {
      setStatus("notifications blocked", "warn");
      return;
    }
    var b = document.createElement("div");
    b.className = "banner";
    b.innerHTML =
      '<h2>One tap left: notifications</h2>' +
      '<button class="act" id="pushBtn">Enable notifications</button>';
    bannerEl.appendChild(b);
    document.getElementById("pushBtn").addEventListener("click", function () {
      enablePush().catch(showPushError);
    });
  })();

  // --- live updates: SSE with a slow safety poll ---------------------------
  var sseOn = false;
  var streams = [];
  // Every vault of this device, for the batched calls: one stream and one
  // read per refresh, however many vaults. One per vault, with polls on
  // top, is what ran a phone into the relay's rate limit.
  function pairIdsParam() {
    return pairs.map(function (p) { return encodeURIComponent(p.pairId); }).join(",");
  }
  function connectEvents() {
    if (!("EventSource" in window) || !pairs.length) return;
    streams.forEach(function (es) { try { es.close(); } catch (e) {} });
    streams = [];
    var es = new EventSource("/api/events?pairIds=" + pairIdsParam());
    es.addEventListener("request", fetchPending);
    es.addEventListener("decision", fetchPending);
    es.addEventListener("status", function () { fetchStatuses(); });
    es.onopen = function () {
      sseOn = true;
      if (!pushOn) setStatus("live");
      // Whatever happened while the stream was down was never announced:
      // read it now, not at the next poll.
      fetchPending();
    };
    es.onerror = function () {
      // EventSource reconnects on its own (retry: 3000).
      sseOn = false;
      if (!pushOn) setStatus("polling", "warn");
    };
    streams.push(es);
  }
  connectEvents();
  // Polls stay on even with a live stream: a stream can look open while
  // the phone's network is long gone, and a missed card costs a login.
  setInterval(function () { if (!document.hidden && !sseOn) fetchPending(); }, 5000);
  setInterval(function () { if (!document.hidden) fetchPending(); }, 20000);
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    // Back from the background (a tap on a notification, usually): the
    // phone may have suspended the streams without closing them. Reopen
    // them, and read now — the retry covers a network still waking up.
    connectEvents();
    fetchPending();
  });
  window.addEventListener("pageshow", function (e) { if (e.persisted) { connectEvents(); fetchPending(); } });
  window.addEventListener("online", fetchPending);

  // --- local decision history (on-device only; synced history is a paid
  // --- gateway feature, not the PWA's business) ----------------------------
  var HIST_KEY = "sandgate_history";
  var histEl = document.getElementById("hist");
  function loadHist() {
    try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch (e) { return []; }
  }
  function recordHist(title, decision, body) {
    var entries = loadHist();
    // The body too: who, from where, which key. A row cut at the screen's
    // edge with no way to read the rest told you nothing afterwards.
    entries.unshift({ t: title, d: decision, ts: Date.now(), b: body ? String(body).slice(0, 600) : undefined });
    entries = entries.slice(0, 50);
    try { localStorage.setItem(HIST_KEY, JSON.stringify(entries)); } catch (e) {}
    renderHist();
  }
  function hhmm(d) { return ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2); }
  /** "14:05" today, "yesterday 14:05", "03/11 14:05" before. */
  function when(ts) {
    var d = new Date(ts);
    var label = dayLabel(ts);
    return label === "Today" ? hhmm(d) : (label === "Yesterday" ? "yesterday" : label) + " " + hhmm(d);
  }
  function dayLabel(ts) {
    var d = new Date(ts), now = new Date();
    if (d.toDateString() === now.toDateString()) return "Today";
    var y = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
    if (d.toDateString() === y.toDateString()) return "Yesterday";
    return ("0" + d.getDate()).slice(-2) + "/" + ("0" + (d.getMonth() + 1)).slice(-2);
  }
  function sectionHead(text) {
    var h = document.createElement("div"); h.className = "section-h"; h.textContent = text;
    return h;
  }
  function renderHist() {
    var entries = loadHist();
    histEl.textContent = "";
    if (!entries.length) {
      var none = document.createElement("div"); none.className = "empty";
      none.innerHTML = '<div class="big">Nothing decided yet.</div><div class="hint">What you approve or deny on this device is listed here.</div>';
      histEl.appendChild(none);
      return;
    }
    var section = document.createElement("div");
    var lastDay = null;
    entries.forEach(function (entry) {
      var day = dayLabel(entry.ts);
      if (day !== lastDay) { section.appendChild(sectionHead(day)); lastDay = day; }
      var row = document.createElement("div"); row.className = "hrow tap";
      var time = document.createElement("span"); time.className = "time"; time.textContent = hhmm(new Date(entry.ts));
      var t = document.createElement("span"); t.className = "t"; t.textContent = entry.t;
      var d = document.createElement("span"); d.className = "d " + entry.d; d.textContent = entry.d;
      row.appendChild(time); row.appendChild(t); row.appendChild(d);
      // Tap to unfold: the full title, the details, the exact time.
      row.onclick = function () {
        var open = row.nextSibling && row.nextSibling.className === "hmore";
        if (open) { row.nextSibling.remove(); row.classList.remove("open"); return; }
        var more = document.createElement("div"); more.className = "hmore";
        more.textContent =
          entry.t + (entry.b ? "\\n" + entry.b : "") + "\\n" + new Date(entry.ts).toLocaleString() + " — " + entry.d;
        row.parentNode.insertBefore(more, row.nextSibling);
        row.classList.add("open");
      };
      section.appendChild(row);
    });
    var note = document.createElement("p"); note.className = "note";
    note.textContent = "Kept on this device only, the last 50 at most. Tap a line for the details.";
    section.appendChild(note);
    histEl.appendChild(section);
  }
  renderHist();

  // --- approval cards: stable DOM, in-place countdowns ---------------------
  var cards = {}; // requestId -> {el, leftEl, fillEl, barEl, rowEl, req, done}
  var emptyEl = null;

  function ensureEmpty(show) {
    if (show && !emptyEl) {
      emptyEl = document.createElement("div");
      emptyEl.className = "empty";
      emptyEl.innerHTML = '<div class="mark">' + GLYPH + '</div><div class="big">All quiet.</div><div class="hint">When an agent needs you, it shows up here.</div>';
      listEl.appendChild(emptyEl);
    } else if (!show && emptyEl) {
      emptyEl.remove();
      emptyEl = null;
    }
  }

  // A request arriving while you are on another tab, or scrolled down a
  // list of cards, is out of sight. A pill says so and takes you there;
  // coming back to the app (a tap on a notification) goes there by itself.
  var jumpEl = null;
  var scrollToCards = false;
  function liveCards() {
    var list = [];
    for (var k in cards) if (cards[k] && !cards[k].done) list.push(cards[k]);
    return list;
  }
  function updateJumpPill() {
    var live = liveCards();
    setBadge("b-req", live.length);
    var first = live.length ? live[0].el : null;
    var r = first && currentTab === "req" ? first.getBoundingClientRect() : null;
    var offscreen = currentTab !== "req" || (!!r && (r.bottom < 120 || r.top > window.innerHeight - 140));
    if (live.length && offscreen) {
      if (!jumpEl) {
        jumpEl = document.createElement("button");
        jumpEl.className = "jump";
        jumpEl.onclick = function () { revealCards(); };
        document.body.appendChild(jumpEl);
      }
      jumpEl.textContent = "↑ " + live.length + (live.length > 1 ? " requests waiting" : " request waiting");
    } else if (jumpEl) {
      jumpEl.remove();
      jumpEl = null;
    }
  }
  // To the very top: the cards are the first thing on the Requests tab.
  // scrollIntoView put the card's top under the sticky header, so all you
  // saw was its buttons — not what you were approving.
  function revealCards() {
    if (!liveCards().length) return;
    if (currentTab !== "req") showTab("req");
    try { window.scrollTo({ top: 0, behavior: "smooth" }); }
    catch (e) { window.scrollTo(0, 0); }
    setTimeout(updateJumpPill, 600);
  }
  window.addEventListener("scroll", function () { updateJumpPill(); }, { passive: true });
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) return;
    scrollToCards = true;
    clearNotifications();
  });
  clearNotifications();

  // Push, SSE and the safety poll all trigger refreshes, and they arrive
  // together. Two of them used to race in the gap between "do I have this
  // card?" and adding it — decrypting is async — so one request could
  // render several times, and only the last copy stayed wired. One refresh
  // runs at a time now; overlapping triggers coalesce into one re-run.
  var refreshing = false;
  var refreshQueued = false;

  async function fetchPending() {
    if (refreshing) { refreshQueued = true; return; }
    refreshing = true;
    try {
      await refreshOnce();
    } finally {
      refreshing = false;
      if (refreshQueued) { refreshQueued = false; fetchPending(); }
    }
  }

  // A failed fetch says nothing about the cards: the network is waking up,
  // the relay restarting, an error page from the proxy. Treating it as "no
  // requests" made cards vanish and come back a refresh later; now only a
  // vault that actually answered can retire its cards, and a failure is
  // retried within seconds instead of waiting for the next poll.
  var retryTimer = null;
  var retryDelay = 1500;
  function scheduleRetry() {
    if (retryTimer) return;
    retryTimer = setTimeout(function () { retryTimer = null; fetchPending(); }, retryDelay);
    retryDelay = Math.min(15000, retryDelay * 2);
  }

  async function refreshOnce() {
    var seen = {};
    var answeredBy = {};
    var failed = false;
    var byPair = null;
    if (pairs.length) {
      try {
        var res = await fetch("/api/pending?pairIds=" + pairIdsParam());
        if (!res.ok) throw new Error("HTTP " + res.status);
        var body = await res.json();
        if (!body || typeof body.byPair !== "object" || body.byPair === null) throw new Error("not a list");
        byPair = body.byPair;
      } catch (e) { failed = true; }
    }
    await Promise.all(pairs.map(async function (p) {
      var raw = byPair && byPair[p.pairId];
      if (!Array.isArray(raw)) return; // no answer for this vault: keep its cards
      answeredBy[p.pairId] = true;
      for (var i = 0; i < raw.length; i++) {
        // Still open for the other devices of a quorum; done for this one.
        if (answered.indexOf(raw[i].requestId) >= 0) continue;
        var key = p.pairId + ":" + raw[i].requestId;
        seen[key] = true;
        if (cards[key]) continue;
        // Claim the key before awaiting: two vaults resolving at once must
        // not both decide the card is missing.
        cards[key] = null;
        try {
          var req = await openSealed(p, raw[i].payload, "req:" + raw[i].requestId);
          addCard(key, p, raw[i].requestId, req);
        } catch (e) {
          delete cards[key]; // not ours / tampered — release the claim
        }
      }
    }));
    var known = {};
    pairs.forEach(function (p) { known[p.pairId] = true; });
    for (var cid in cards) {
      // Retire a card when its vault answered without it — or is gone.
      var owner = cards[cid] && cards[cid].pair.pairId;
      if (!seen[cid] && cards[cid] && (answeredBy[owner] || !known[owner])) {
        cards[cid].el.remove(); delete cards[cid];
      }
    }
    ensureEmpty(activeCount() === 0);
    if (failed) scheduleRetry(); else retryDelay = 1500;
    if (scrollToCards && liveCards().length) { scrollToCards = false; revealCards(); }
    else if (!failed) scrollToCards = false;
    updateJumpPill();
  }

  function activeCount() {
    var n = 0;
    for (var k in cards) if (cards[k]) n++;
    return n;
  }

  function addCard(id, p, requestId, req) {
    var isInput = req.kind === "input";
    var isEnroll = req.kind === "enroll";
    var card = document.createElement("div");
    card.className = "card";

    var who = document.createElement("div"); who.className = "who";
    who.textContent =
      (pairs.length > 1 ? p.name + " · " : "") +
      (isEnroll
        ? "sandgate · setup"
        : isInput
          ? "agent · question"
          : req.requireBiometric
            ? "agent · approval · Face ID"
            : "agent · approval request");
    if (req.quorum > 1) who.textContent += " · " + req.quorum + " devices must approve";
    card.appendChild(who);
    var h = document.createElement("h2"); h.textContent = req.title; card.appendChild(h);
    // NOTE: never name this variable p — var is function-scoped and would
    // shadow the pairing parameter for the rest of addCard (real bug once).
    if (req.body) { var bodyP = document.createElement("p"); bodyP.textContent = req.body; card.appendChild(bodyP); }

    var input = null;
    if (isInput && !isEnroll) {
      input = document.createElement("input");
      input.className = "answer-input";
      input.placeholder = "Your answer";
      input.autocomplete = "off";
      card.appendChild(input);
    }

    var timer = document.createElement("div"); timer.className = "timer";
    var left = document.createElement("div"); left.className = "left";
    var bar = document.createElement("div"); bar.className = "bar";
    var fill = document.createElement("i");
    bar.appendChild(fill); timer.appendChild(left); timer.appendChild(bar);
    card.appendChild(timer);

    var row = document.createElement("div"); row.className = "row";
    if (isEnroll) {
      row.appendChild(makeActionBtn("Enable", "ok", CHECK, function (btn) {
        btn.disabled = true;
        doEnroll(requestId).then(function (enrollment) {
          submitDecision(id, { requestId: requestId, approved: true, ts: Date.now(), enrollment: enrollment }, "approved", btn);
        }).catch(function (e) {
          btn.disabled = false;
          alert("Could not enable Face ID: " + (e && e.message ? e.message : e));
        });
      }));
      row.appendChild(makeActionBtn("Not now", "no", CROSS, function (btn) {
        submitDecision(id, { requestId: requestId, approved: false, ts: Date.now() }, "denied", btn);
      }));
    } else if (isInput) {
      // A typed answer is at least as sensitive as a yes: when the gateway
      // requires a biometric, it is required here too — the gateway refuses
      // an answer without one, so sending it plain was a guaranteed failure.
      var sendBtn = makeActionBtn(req.requireBiometric ? "Send with Face ID" : "Send", "ok", CHECK, function (btn) {
        var value = input.value.trim();
        if (!value) { input.focus(); return; }
        if (!req.requireBiometric) {
          submitDecision(id, { requestId: requestId, approved: true, answer: value, ts: Date.now() }, "answered", btn);
          return;
        }
        btn.disabled = true;
        doAssert(requestId, req.credentialId).then(function (assertion) {
          submitDecision(id, { requestId: requestId, approved: true, answer: value, ts: Date.now(), assertion: assertion }, "answered", btn);
        }).catch(function (e) {
          btn.disabled = false;
          alert("Face ID check failed, answer not sent: " + (e && e.message ? e.message : e));
        });
      });
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter") sendBtn.click();
      });
      row.appendChild(sendBtn);
      row.appendChild(makeActionBtn("Deny", "no", CROSS, function (btn) {
        submitDecision(id, { requestId: requestId, approved: false, ts: Date.now() }, "denied", btn);
      }));
    } else {
      row.appendChild(makeActionBtn(req.requireBiometric ? "Approve with Face ID" : "Approve", "ok", CHECK, function (btn) {
        if (!req.requireBiometric) {
          submitDecision(id, { requestId: requestId, approved: true, ts: Date.now() }, "approved", btn);
          return;
        }
        btn.disabled = true;
        doAssert(requestId, req.credentialId).then(function (assertion) {
          submitDecision(id, { requestId: requestId, approved: true, ts: Date.now(), assertion: assertion }, "approved", btn);
        }).catch(function (e) {
          btn.disabled = false;
          alert("Face ID check failed, approval not sent: " + (e && e.message ? e.message : e));
        });
      }));
      row.appendChild(makeActionBtn("Deny", "no", CROSS, function (btn) {
        submitDecision(id, { requestId: requestId, approved: false, ts: Date.now() }, "denied", btn);
      }));
    }
    card.appendChild(row);

    ensureEmpty(false);
    listEl.appendChild(card);
    cards[id] = { el: card, leftEl: left, fillEl: fill, barEl: bar, rowEl: row, inputEl: input, req: req, pair: p, requestId: requestId, done: false };
    tickOne(cards[id]);
  }

  function tickOne(c) {
    var total = c.req.timeoutSec * 1000;
    var remaining = Math.max(0, c.req.ts + total - Date.now());
    if (remaining <= 0) {
      if (!c.done) {
        c.done = true;
        c.el.classList.add("expired");
        c.rowEl.remove();
        if (c.inputEl) c.inputEl.disabled = true;
        c.leftEl.textContent = "expired — denied";
        c.fillEl.style.width = "0%";
        recordHist(histLabel(c), "expired", c.req.body);
      }
      return;
    }
    c.leftEl.textContent = Math.ceil(remaining / 1000) + "s — then denied";
    c.fillEl.style.width = Math.min(100, (remaining / total) * 100) + "%";
    c.barEl.className = "bar" + (remaining < total * 0.25 ? " low" : "");
  }
  setInterval(function () {
    for (var id in cards) if (cards[id]) tickOne(cards[id]);
  }, 1000);

  function makeActionBtn(label, cls, icon, onTap) {
    var b = document.createElement("button");
    b.className = cls;
    b.innerHTML = icon + "<span></span>";
    b.querySelector("span").textContent = label;
    b.onclick = function () { onTap(b); };
    return b;
  }

  function sleepMs(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  /**
   * POST a decision, riding out what a phone's network does: a dropped
   * request, a relay restarting, a 429 or 5xx from the proxy. The same
   * sealed answer is sent again — the relay ignores a repeat once it has
   * enough. Returns the final response, or throws after the last try.
   */
  async function postDecision(pairId, requestId, payload) {
    var lastErr = null;
    for (var attempt = 0; attempt < 5; attempt++) {
      if (attempt) await sleepMs(Math.min(4000, 600 * Math.pow(2, attempt - 1)));
      try {
        var res = await fetch("/api/decision", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pairId: pairId, requestId: requestId, payload: payload }),
        });
        if (res.status === 429 || res.status >= 500) { lastErr = new Error("relay answered HTTP " + res.status); continue; }
        return res;
      } catch (e) { lastErr = e; }
    }
    throw lastErr || new Error("relay unreachable");
  }

  async function submitDecision(id, decisionBody, histDecision, btn) {
    var c = cards[id];
    if (!c || c.done || c.sending) return;
    // The whole card, not just the tapped button: tapping Deny while an
    // Approve is still in flight sent both.
    c.sending = true;
    c.el.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
    var label = btn.querySelector("span");
    var was = label ? label.textContent : "";
    if (label) label.textContent = "Sending…";
    function retire(outcome) {
      markAnswered(c.requestId);
      if (cards[id]) {
        recordHist(histLabel(c), outcome, c.req.body);
        cards[id].el.remove();
        delete cards[id];
      }
      ensureEmpty(activeCount() === 0);
      updateJumpPill();
    }
    try {
      decisionBody.deviceId = deviceId;
      var payload = await sealPayload(c.pair, decisionBody, "dec:" + c.requestId);
      var res = await postDecision(c.pair.pairId, c.requestId, payload);
      if (res.status === 404) {
        // Gone from the relay: it expired, the agent stopped waiting, or
        // another device answered. Nothing to send to — not an error.
        retire("expired");
        return;
      }
      if (!res.ok) throw new Error("relay answered HTTP " + res.status);
      retire(histDecision);
    } catch (err) {
      c.sending = false;
      if (label) label.textContent = was;
      c.el.querySelectorAll("button").forEach(function (b) { b.disabled = false; });
      alert("Could not send your decision (" + (err && err.message ? err.message : err) + "). Check your connection and tap again.");
    }
  }

  function histLabel(c) {
    return (pairs.length > 1 ? c.pair.name + ": " : "") + c.req.title;
  }

  // --- vault manager -------------------------------------------------------
  var vaultsEl = document.getElementById("vaults");
  function renderVaults() {
    vaultsEl.textContent = "";
    var section = document.createElement("div");
    section.appendChild(sectionHead("Vaults and servers paired with this device"));
    pairs.forEach(function (p, idx) {
      var row = document.createElement("div"); row.className = "hrow";
      var t = document.createElement("span"); t.className = "t"; t.textContent = p.name;
      t.style.cursor = "pointer";
      t.title = "Rename";
      t.onclick = function () {
        var next = prompt("Name for this vault", p.name);
        if (next && next.trim()) { p.name = next.trim().slice(0, 40); savePairs(); renderVaults(); }
      };
      var x = document.createElement("span"); x.className = "d expired"; x.textContent = "remove";
      x.style.cursor = "pointer";
      x.onclick = function () {
        if (!confirm("Remove " + p.name + " from this device?")) return;
        pairs.splice(idx, 1);
        savePairs();
        // Stop this device ringing for it: the relay kept pushing a removed
        // vault's requests (and its server alerts) to the lock screen.
        swRegPromise
          .then(function (reg) { return reg && reg.pushManager ? reg.pushManager.getSubscription() : null; })
          .then(function (sub) {
            if (!sub) return;
            return fetch("/api/unsubscribe", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ pairId: p.pairId, endpoint: sub.endpoint }),
            });
          })
          .catch(function () {})
          .then(function () { location.reload(); });
      };
      row.appendChild(t); row.appendChild(x);
      section.appendChild(row);
    });
    var addRow = document.createElement("div"); addRow.className = "hrow";
    var add = document.createElement("span"); add.className = "d approved"; add.textContent = "+ add a vault or a server";
    add.style.cursor = "pointer";
    add.onclick = function () {
      if (document.getElementById("addPaste")) return;
      var input = document.createElement("input");
      input.id = "addPaste";
      input.placeholder = "Paste a pairing link";
      input.autocomplete = "off";
      input.style.cssText = "width:100%;padding:10px 12px;margin-top:8px;background:var(--panel);border:1px solid var(--line);border-radius:8px;color:var(--ink);font:16px ui-monospace,monospace;box-sizing:border-box;";
      input.addEventListener("input", function (e) {
        if (!parsePairing(e.target.value)) return;
        acceptPairingText(e.target.value).then(function (added) {
          if (added) location.reload();
        }).catch(function (err) { alert(err && err.message ? err.message : err); });
      });
      section.appendChild(input);
      if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) section.appendChild(makeScanButton());
      input.focus();
    };
    addRow.appendChild(add);
    section.appendChild(addRow);
    var hint = document.createElement("p"); hint.className = "note";
    hint.textContent = "Tap a name to rename it.";
    section.appendChild(hint);
    section.appendChild(sectionHead("Notifications"));
    var detRow = document.createElement("div"); detRow.className = "hrow";
    var detLabel = document.createElement("span"); detLabel.className = "t";
    detLabel.textContent = "Show details in notifications";
    var detToggle = document.createElement("span"); detToggle.className = "d " + (notifDetails() ? "approved" : "denied");
    detToggle.textContent = notifDetails() ? "on" : "off";
    detToggle.style.cursor = "pointer";
    detToggle.onclick = function () {
      try { localStorage.setItem(DETAILS_KEY, notifDetails() ? "off" : "on"); } catch (e) {}
      syncStore();
      renderVaults();
    };
    detRow.appendChild(detLabel); detRow.appendChild(detToggle);
    section.appendChild(detRow);
    var pushRow = document.createElement("div"); pushRow.className = "hrow";
    var pushLabel = document.createElement("span"); pushLabel.className = "t";
    pushLabel.textContent = "Push on this device";
    var pushState = document.createElement("span"); pushState.className = "d " + (pushOn ? "approved" : "expired");
    pushState.textContent = pushOn ? "on" : "off";
    pushRow.appendChild(pushLabel); pushRow.appendChild(pushState);
    section.appendChild(pushRow);
    var ver = document.createElement("p"); ver.className = "note";
    ver.textContent = "While the app is open, nothing rings: requests appear here directly.";
    section.appendChild(ver);
    vaultsEl.appendChild(section);
  }
  renderVaults();

  // --- servers: sealed heartbeats from ssh-guard ---------------------------
  // Each server sends its status every few minutes, sealed with its own
  // pairing key; the relay hands back the latest blob and when it came.
  var serversEl = document.getElementById("servers");
  var statuses = {}; // pairId -> { st, ageAt, fetchedAt, quietAfterMs }
  var latestVersion = null;

  function versionLess(a, b) {
    var x = String(a || "").split("."), y = String(b || "").split(".");
    for (var i = 0; i < 3; i++) {
      var m = parseInt(x[i], 10) || 0, n = parseInt(y[i], 10) || 0;
      if (m !== n) return m < n;
    }
    return false;
  }
  function ago(ms) {
    var s = Math.max(0, Math.round(ms / 1000));
    if (s < 60) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  }
  function bytesPct(used, total) { return total ? Math.round((used / total) * 100) + "%" : "?"; }
  function upFor(sec) {
    if (sec < 3600) return Math.round(sec / 60) + " min";
    if (sec < 86400) return Math.round(sec / 3600) + " h";
    return Math.round(sec / 86400) + " d";
  }

  var statusBusy = false;
  var statusQueued = false;
  async function fetchStatuses() {
    // A "status" event during a read must not be lost: read again after.
    if (statusBusy) { statusQueued = true; return; }
    statusBusy = true;
    try {
      if (!latestVersion) {
        // "server": the last release that changed what a server runs. A
        // release that only touches this app must not tell every server
        // to update.
        try { var hb = await (await fetch("/api/health")).json(); latestVersion = hb.server || hb.version || null; } catch (e) {}
      }
      if (!pairs.length) return;
      var all;
      try {
        var res = await fetch("/api/status?pairIds=" + pairIdsParam());
        if (!res.ok) return; // keep what we had: a failed read is not news
        all = await res.json();
      } catch (e) { return; }
      if (!all || !all.byPair) return;
      await Promise.all(pairs.map(async function (p) {
        var entry = all.byPair[p.pairId];
        if (!entry) return;
        var data = { status: entry.status, quietAfterMs: entry.quietAfterMs, now: all.now };
        if (!data.status) { delete statuses[p.pairId]; return; }
        try {
          var st = await openSealed(p, data.status.payload, "status:" + p.pairId);
          if (!st || st.v !== 1) return;
          // Age by the relay's clock (the phone's may be off), unless the
          // sealed timestamp says the blob is older than the relay claims:
          // an old heartbeat replayed must not pass for a live server.
          var age = Math.max(0, (data.now || 0) - data.status.receivedAt);
          var sealedAge = Date.now() - st.ts;
          if (st.ts < data.status.receivedAt - 10 * 60 * 1000) age = Math.max(age, sealedAge);
          statuses[p.pairId] = { st: st, age: age, fetchedAt: Date.now(), quietAfterMs: data.quietAfterMs || 15 * 60 * 1000 };
        } catch (e) { /* not sealed with this vault's key: ignore it */ }
      }));
    } finally {
      statusBusy = false;
      renderServers();
      if (statusQueued) { statusQueued = false; fetchStatuses(); }
    }
  }

  // One line per server, the ones that need you first: silent, then broken,
  // then a warning, then the rest. A tap unfolds the details.
  var openSrv = {};
  function serverView(p) {
    var entry = statuses[p.pairId], st = entry.st;
    var age = entry.age + (Date.now() - entry.fetchedAt);
    var down = age > entry.quietAfterMs;
    var flags = [];
    if (latestVersion && versionLess(st.sandgate, latestVersion)) {
      flags.push({ level: "warn", label: "update available", detail: st.sandgate + " → " + latestVersion + " (replace the binary with mv, see the docs)" });
    }
    if (!st.doctor) {
      flags.push({ level: "warn", label: "doctor not run", detail: "the heartbeat could not read the sshd configuration" });
    } else {
      (st.doctor.findings || []).forEach(function (f) { flags.push({ level: f.level === "fail" ? "fail" : "warn", label: f.label, detail: f.detail }); });
    }
    if (!st.hatch) flags.push({ level: "warn", label: "no escape hatch", detail: "no exempt user and not in notify mode: a flat phone means no SSH" });
    var used = st.disk ? st.disk.total - st.disk.free : 0;
    if (st.disk && st.disk.total && st.disk.free / st.disk.total < 0.1) flags.push({ level: "warn", label: "disk almost full", detail: bytesPct(used, st.disk.total) + " used" });
    var fails = flags.filter(function (f) { return f.level === "fail"; });
    var rank = down ? 0 : fails.length ? 1 : flags.length ? 2 : 3;
    return { p: p, st: st, age: age, down: down, flags: flags, fails: fails, rank: rank, used: used };
  }

  function renderServers() {
    serversEl.textContent = "";
    var views = pairs.filter(function (p) { return statuses[p.pairId]; }).map(serverView);
    views.sort(function (a, b) { return a.rank - b.rank || String(a.p.name).localeCompare(String(b.p.name)); });
    renderAlerts(views.filter(function (v) { return v.rank <= 1; }));
    if (!views.length) {
      var none = document.createElement("div"); none.className = "empty";
      none.innerHTML = '<div class="big">No server reports yet.</div><div class="hint">A server running sandgate ssh-guard reports here every five minutes.</div>';
      serversEl.appendChild(none);
      return;
    }
    var nDown = views.filter(function (v) { return v.down; }).length;
    var nFail = views.filter(function (v) { return !v.down && v.fails.length; }).length;
    var sum = document.createElement("div"); sum.className = "sum";
    function part(n, label, bad) {
      var s = document.createElement("span"); if (bad) s.className = "bad";
      var b = document.createElement("b"); b.textContent = String(n);
      s.appendChild(b); s.appendChild(document.createTextNode(" " + label));
      sum.appendChild(s);
    }
    part(views.length - nDown, "online");
    if (nDown) part(nDown, "silent", true);
    if (nFail) part(nFail, nFail > 1 ? "with problems" : "with a problem", true);
    serversEl.appendChild(sum);

    views.forEach(function (v) {
      var st = v.st, p = v.p;
      var row = document.createElement("div");
      row.className = "srv" + (openSrv[p.pairId] ? " open" : "");
      row.onclick = function () {
        openSrv[p.pairId] = !openSrv[p.pairId];
        row.classList.toggle("open", !!openSrv[p.pairId]);
      };

      var top = document.createElement("div"); top.className = "top";
      var dot = document.createElement("span"); dot.className = "dot " + (v.down ? "down" : "up");
      var name = document.createElement("span"); name.className = "name"; name.textContent = p.name;
      var seen = document.createElement("span"); seen.className = "seen" + (v.down ? " down" : "");
      seen.textContent = v.down ? "silent since " + when(Date.now() - v.age) : "online · " + ago(v.age);
      var chev = document.createElement("span"); chev.className = "chev"; chev.textContent = "›";
      top.appendChild(dot); top.appendChild(name); top.appendChild(seen); top.appendChild(chev);
      row.appendChild(top);

      // The one line you read without opening it: what is wrong, or where it is.
      var line = document.createElement("div");
      if (v.down) {
        line.className = "line fail";
        line.textContent = "Down, or cut off from the relay";
      } else if (v.fails.length) {
        line.className = "line fail";
        line.textContent = v.fails.map(function (f) { return f.label; }).join(", ");
      } else if (v.flags.length) {
        line.className = "line warn";
        line.textContent = v.flags.map(function (f) { return f.label; }).join(", ");
      } else {
        line.className = "line";
        line.textContent = [(st.ips || [])[0], st.mode === "notify" ? "notify only" : "blocking"].filter(Boolean).join(" · ");
      }
      row.appendChild(line);

      var more = document.createElement("div"); more.className = "more";
      if (v.down) {
        var last = document.createElement("div"); last.className = "meta";
        last.textContent = "At its last heartbeat:";
        more.appendChild(last);
      }
      var meta1 = document.createElement("div"); meta1.className = "meta";
      meta1.textContent = [
        (st.ips || []).join(", "),
        st.os,
        st.openssh ? "OpenSSH " + st.openssh : null,
      ].filter(Boolean).join(" · ");
      more.appendChild(meta1);
      var meta2 = document.createElement("div"); meta2.className = "meta";
      meta2.textContent = [
        "sandgate " + st.sandgate,
        st.mode === "notify" ? "notify only" : "blocking",
        st.keyOnly ? "key + phone" : "password + phone",
        "load " + (st.load && st.load.length ? st.load[0] : "?") + (st.cpus ? "/" + st.cpus : ""),
        st.mem ? "mem " + bytesPct(st.mem.total - st.mem.free, st.mem.total) : null,
        st.disk ? "disk " + bytesPct(v.used, st.disk.total) : null,
        "up " + upFor(st.uptimeSec || 0),
      ].filter(Boolean).join(" · ");
      more.appendChild(meta2);
      v.flags.forEach(function (f) {
        var el = document.createElement("div"); el.className = "flag " + f.level;
        var b = document.createElement("b"); b.textContent = f.label;
        el.appendChild(b);
        if (f.detail) el.appendChild(document.createTextNode(" — " + f.detail));
        more.appendChild(el);
      });
      row.appendChild(more);
      serversEl.appendChild(row);
    });
  }

  // Requests is where you land: a server in trouble is named there, not
  // two screens away.
  var alertsEl = document.getElementById("alerts");
  function renderAlerts(bad) {
    alertsEl.textContent = "";
    setBadge("b-srv", bad.length);
    if (!bad.length) return;
    var b = document.createElement("button"); b.className = "alert";
    var t = document.createElement("span"); t.className = "txt";
    var first = bad[0];
    t.textContent = first.down
      ? first.p.name + " silent since " + when(Date.now() - first.age)
      : first.p.name + ": " + first.fails.map(function (f) { return f.label; }).join(", ");
    if (bad.length > 1) t.textContent += " · +" + (bad.length - 1) + " other" + (bad.length > 2 ? "s" : "");
    b.appendChild(t);
    var go = document.createElement("span"); go.textContent = "›";
    b.appendChild(go);
    b.onclick = function () { showTab("srv"); };
    alertsEl.appendChild(b);
  }

  fetchStatuses();
  setInterval(function () { if (!document.hidden) fetchStatuses(); }, 60000);
  setInterval(function () { if (!document.hidden) renderServers(); }, 30000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) fetchStatuses(); });

  fetchPending();
})();
</script>
</body>
</html>
`;
