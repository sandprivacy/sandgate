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

self.addEventListener("push", function (e) {
  e.waitUntil((async function () {
    var data = null;
    try { data = e.data ? e.data.json() : null; } catch (err) {}
    var store = await loadStore();
    var desc = await describePush(data, store);
    await self.registration.showNotification(desc.title, desc.options);
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
  var res = await fetch("/api/decision", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairId: d.pairId, requestId: d.requestId, payload: payload }),
  });
  await self.registration.showNotification(
    res.ok ? (approved ? "Approved" : "Denied") : "Could not send your answer",
    { body: res.ok ? "" : "Open the app to try again.", tag: "sandgate-" + d.requestId, icon: "/icon-192.png" }
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
    if (clientList.length) return clientList[0].focus();
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
    padding: calc(env(safe-area-inset-top, 0px) + 14px) 18px 14px;
    background: color-mix(in srgb, var(--ground) 88%, transparent);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
  }
  .logo {
    width: 38px; height: 38px; border-radius: 10px;
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

  main { max-width: 520px; margin: 0 auto; padding: 18px 16px calc(env(safe-area-inset-bottom, 0px) + 40px); }

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

  .empty { text-align: center; padding: 72px 20px; color: var(--soft); }
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

  .hist { margin-top: 30px; }
  .hist h3 { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--soft); margin: 0 0 8px; }
  .hrow { display: flex; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13.5px; }
  .hrow .time { color: var(--soft); font-variant-numeric: tabular-nums; font-size: 12px; min-width: 74px; }
  .hrow .t { flex: 1; color: #cfc6b2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hrow .d { font-weight: 650; font-size: 10.5px; letter-spacing: .05em; text-transform: uppercase; }
  .d.approved { color: #7fbf9a; }
  .d.answered { color: #7fbf9a; }
  .d.denied { color: #d98a76; }
  .d.expired { color: var(--soft); }

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
    <div class="sub">your agents ask. you decide.</div>
  </div>
  <div class="pill warn" id="status">starting</div>
</header>
<main><div id="banner"></div><div id="list"></div><div id="hist"></div></main>
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
          if (e.data === "refresh") fetchPending();
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
  function connectEvents() {
    if (!("EventSource" in window)) return;
    pairs.forEach(function (p) {
      var es = new EventSource("/api/events?pairId=" + encodeURIComponent(p.pairId));
      es.addEventListener("request", fetchPending);
      es.addEventListener("decision", fetchPending);
      es.onopen = function () {
        sseOn = true;
        if (!pushOn) setStatus("live");
      };
      es.onerror = function () {
        // EventSource reconnects on its own (retry: 3000).
        if (!pushOn) setStatus("polling", "warn");
      };
    });
  }
  connectEvents();
  setInterval(function () { if (!document.hidden && !sseOn) fetchPending(); }, 8000);
  setInterval(function () { if (!document.hidden) fetchPending(); }, 45000); // safety net
  document.addEventListener("visibilitychange", function () { if (!document.hidden) fetchPending(); });

  // --- local decision history (on-device only; synced history is a paid
  // --- gateway feature, not the PWA's business) ----------------------------
  var HIST_KEY = "sandgate_history";
  var histEl = document.getElementById("hist");
  function loadHist() {
    try { return JSON.parse(localStorage.getItem(HIST_KEY)) || []; } catch (e) { return []; }
  }
  function recordHist(title, decision) {
    var entries = loadHist();
    entries.unshift({ t: title, d: decision, ts: Date.now() });
    entries = entries.slice(0, 30);
    try { localStorage.setItem(HIST_KEY, JSON.stringify(entries)); } catch (e) {}
    renderHist();
  }
  function histTime(ts) {
    var d = new Date(ts), now = new Date();
    var hm = ("0" + d.getHours()).slice(-2) + ":" + ("0" + d.getMinutes()).slice(-2);
    if (d.toDateString() === now.toDateString()) return hm;
    return ("0" + d.getDate()).slice(-2) + "/" + ("0" + (d.getMonth() + 1)).slice(-2) + " " + hm;
  }
  function renderHist() {
    var entries = loadHist();
    histEl.textContent = "";
    if (!entries.length) return;
    var section = document.createElement("div");
    section.className = "hist";
    var h = document.createElement("h3");
    h.textContent = "Recent — this device";
    section.appendChild(h);
    entries.forEach(function (entry) {
      var row = document.createElement("div"); row.className = "hrow";
      var time = document.createElement("span"); time.className = "time"; time.textContent = histTime(entry.ts);
      var t = document.createElement("span"); t.className = "t"; t.textContent = entry.t;
      var d = document.createElement("span"); d.className = "d " + entry.d; d.textContent = entry.d;
      row.appendChild(time); row.appendChild(t); row.appendChild(d);
      section.appendChild(row);
    });
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

  async function refreshOnce() {
    var seen = {};
    await Promise.all(pairs.map(async function (p) {
      var raw;
      try {
        raw = await (await fetch("/api/pending?pairId=" + encodeURIComponent(p.pairId))).json();
      } catch (e) { return; }
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
    for (var cid in cards) {
      if (!seen[cid] && cards[cid]) { cards[cid].el.remove(); delete cards[cid]; }
    }
    ensureEmpty(activeCount() === 0);
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
        recordHist(histLabel(c), "expired");
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

  async function submitDecision(id, decisionBody, histDecision, btn) {
    var c = cards[id];
    if (!c || c.done) return;
    btn.disabled = true;
    try {
      decisionBody.deviceId = deviceId;
      var payload = await sealPayload(c.pair, decisionBody, "dec:" + c.requestId);
      var res = await fetch("/api/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: c.pair.pairId, requestId: c.requestId, payload: payload }),
      });
      if (!res.ok) throw new Error("relay answered HTTP " + res.status);
      markAnswered(c.requestId);
      if (cards[id]) {
        recordHist(histLabel(c), histDecision);
        cards[id].el.remove();
        delete cards[id];
      }
      ensureEmpty(activeCount() === 0);
    } catch (err) {
      btn.disabled = false;
      alert("Could not send your decision: " + (err && err.message ? err.message : err));
    }
  }

  function histLabel(c) {
    return (pairs.length > 1 ? c.pair.name + ": " : "") + c.req.title;
  }

  // --- vault manager -------------------------------------------------------
  var vaultsEl = document.createElement("div");
  histEl.parentElement.appendChild(vaultsEl);
  function renderVaults() {
    vaultsEl.textContent = "";
    var section = document.createElement("div");
    section.className = "hist";
    var h = document.createElement("h3");
    h.textContent = "Vaults";
    section.appendChild(h);
    pairs.forEach(function (p, idx) {
      var row = document.createElement("div"); row.className = "hrow";
      var t = document.createElement("span"); t.className = "t"; t.textContent = p.name;
      t.style.cursor = "pointer";
      t.title = "Rename";
      t.onclick = function () {
        var next = prompt("Name for this vault", p.name);
        if (next && next.trim()) { p.name = next.trim().slice(0, 40); savePairs(); renderVaults(); }
      };
      var x = document.createElement("span"); x.className = "d denied"; x.textContent = "remove";
      x.style.cursor = "pointer";
      x.onclick = function () {
        if (!confirm("Remove " + p.name + " from this device?")) return;
        pairs.splice(idx, 1);
        savePairs();
        location.reload();
      };
      row.appendChild(t); row.appendChild(x);
      section.appendChild(row);
    });
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
    var addRow = document.createElement("div"); addRow.className = "hrow";
    var add = document.createElement("span"); add.className = "d approved"; add.textContent = "+ add a vault";
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
    vaultsEl.appendChild(section);
  }
  renderVaults();

  fetchPending();
})();
</script>
</body>
</html>
`;
