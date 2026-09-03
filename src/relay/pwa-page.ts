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

export const PWA_SW = `
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
// A fetch handler is required for Chrome's install prompt; plain passthrough.
self.addEventListener("fetch", function (e) { e.respondWith(fetch(e.request)); });
self.addEventListener("push", function (e) {
  e.waitUntil((async function () {
    await self.registration.showNotification("sandgate", {
      body: "Approval requested — tap to answer",
      tag: "sandgate-approval",
      renotify: true,
      icon: "/icon-192.png",
      badge: "/icon-192.png",
    });
    var clientList = await self.clients.matchAll({ type: "window" });
    clientList.forEach(function (c) { c.postMessage("refresh"); });
  })());
});
self.addEventListener("notificationclick", function (e) {
  e.notification.close();
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
    color: var(--ink); font: 14px ui-monospace, monospace;
  }
  .setup input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }

  .hist { margin-top: 30px; }
  .hist h3 { font-size: 11px; letter-spacing: .08em; text-transform: uppercase; color: var(--soft); margin: 0 0 8px; }
  .hrow { display: flex; gap: 10px; align-items: baseline; padding: 8px 0; border-bottom: 1px solid var(--line); font-size: 13.5px; }
  .hrow .time { color: var(--soft); font-variant-numeric: tabular-nums; font-size: 12px; min-width: 74px; }
  .hrow .t { flex: 1; color: #cfc6b2; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hrow .d { font-weight: 650; font-size: 10.5px; letter-spacing: .05em; text-transform: uppercase; }
  .d.approved { color: #7fbf9a; }
  .d.denied { color: #d98a76; }
  .d.expired { color: var(--soft); }
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
  function parsePairing(text) {
    var mm = String(text).match(/p=([A-Za-z0-9_-]{8,64})&s=([A-Za-z0-9_-]{8,})/);
    return mm ? { pairId: mm[1], secret: mm[2] } : null;
  }
  var pair = parsePairing(location.hash);
  if (pair) {
    try { localStorage.setItem(PAIR_KEY, JSON.stringify(pair)); } catch (e) {}
    // iOS Safari (not installed): KEEP the pairing link in the address bar.
    // With no start_url in the Apple manifest, Add to Home Screen captures
    // this exact URL — fragment included — so the installed app opens
    // already paired despite iOS's isolated storage.
    if (!(isIOS && !standalone)) {
      history.replaceState(null, "", location.pathname);
    }
  } else {
    try { pair = JSON.parse(localStorage.getItem(PAIR_KEY)); } catch (e) {}
  }

  if (!pair) {
    setStatus("not paired", "err");
    var setup = document.createElement("div");
    setup.className = "setup";
    setup.innerHTML =
      '<div class="mark">' + GLYPH + '</div>' +
      '<p>Not paired yet. On your computer, run</p><code>sandgate pair</code>' +
      '<p style="margin-top:14px">then open the link it prints on this device —<br>or paste it here:</p>' +
      '<input id="pasteLink" placeholder="https://relay…/#p=…&s=…" autocomplete="off">';
    listEl.appendChild(setup);
    document.getElementById("pasteLink").addEventListener("input", function (e) {
      var parsed = parsePairing(e.target.value);
      if (parsed) {
        try { localStorage.setItem(PAIR_KEY, JSON.stringify(parsed)); } catch (err) {}
        location.replace(location.pathname);
      }
    });
    return;
  }

  var pairLink = location.origin + "/#p=" + pair.pairId + "&s=" + pair.secret;

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

  // --- crypto (mirror of pwacrypto.ts) ------------------------------------
  var keyPromise = (async function () {
    var raw = await crypto.subtle.importKey("raw", b64uToBytes(pair.secret), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: enc.encode("sandgate-pwa-v1"), info: enc.encode("approval-channel") },
      raw,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  })();

  async function openSealed(sealed, aad) {
    var key = await keyPromise;
    var pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64uToBytes(sealed.iv), additionalData: enc.encode(aad) },
      key,
      b64uToBytes(sealed.ct)
    );
    return JSON.parse(dec.decode(pt));
  }
  async function sealPayload(payload, aad) {
    var key = await keyPromise;
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode(aad) },
      key,
      enc.encode(JSON.stringify(payload))
    );
    return { iv: bytesToB64u(iv), ct: bytesToB64u(ct) };
  }

  // --- presence + push subscription ---------------------------------------
  // Announce this page to the relay immediately (push or not), so the
  // "sandgate pair" command can report "phone connected" without waiting
  // on notification permission.
  fetch("/api/hello", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairId: pair.pairId }),
  }).catch(function () {});

  var pushOn = false;
  var swRegPromise = "serviceWorker" in navigator
    ? navigator.serviceWorker.register("/sw.js").then(function (reg) {
        navigator.serviceWorker.addEventListener("message", function (e) {
          if (e.data === "refresh") fetchPending();
        });
        return reg;
      })
    : Promise.resolve(null);

  async function enablePush() {
    var reg = await swRegPromise;
    if (!reg || !("PushManager" in window)) return false;
    // iOS only shows the permission prompt inside a user gesture, and only
    // in the installed app — never in Safari tabs.
    var perm = await Notification.requestPermission();
    if (perm !== "granted") return false;
    var vapid = await (await fetch("/api/vapid")).json();
    var sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: b64uToBytes(vapid.publicKey),
    });
    await fetch("/api/subscribe", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId: pair.pairId, subscription: sub }),
    });
    pushOn = true;
    setStatus("push on");
    var btn = document.getElementById("pushBtn");
    if (btn) btn.parentElement.remove();
    return true;
  }

  function offerPush() {
    if (!("Notification" in window) || !("PushManager" in window)) return;
    if (isIOS && !standalone) return; // impossible in Safari tabs; banner handles install
    if (Notification.permission === "granted") {
      enablePush().catch(function () {});
      return;
    }
    if (Notification.permission === "denied") return;
    var b = document.createElement("div");
    b.className = "banner";
    b.innerHTML =
      '<h2>One tap left: notifications</h2>' +
      '<button class="act" id="pushBtn">Enable notifications</button>';
    bannerEl.appendChild(b);
    document.getElementById("pushBtn").addEventListener("click", function () {
      enablePush().catch(function () {});
    });
  }
  offerPush();

  // --- live updates: SSE with a slow safety poll ---------------------------
  var sseOn = false;
  function connectEvents() {
    if (!("EventSource" in window)) return;
    var es = new EventSource("/api/events?pairId=" + encodeURIComponent(pair.pairId));
    es.addEventListener("request", fetchPending);
    es.addEventListener("decision", fetchPending);
    es.onopen = function () {
      sseOn = true;
      if (!pushOn) setStatus("live");
    };
    es.onerror = function () {
      sseOn = false;
      if (!pushOn) setStatus("polling", "warn");
      // EventSource reconnects on its own (retry: 3000).
    };
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

  async function fetchPending() {
    var raw;
    try {
      raw = await (await fetch("/api/pending?pairId=" + encodeURIComponent(pair.pairId))).json();
    } catch (e) { return; }
    var seen = {};
    for (var i = 0; i < raw.length; i++) {
      var id = raw[i].requestId;
      seen[id] = true;
      if (cards[id]) continue;
      try {
        var req = await openSealed(raw[i].payload, "req:" + id);
        addCard(id, req);
      } catch (e) { /* not ours / tampered */ }
    }
    for (var cid in cards) {
      if (!seen[cid]) { cards[cid].el.remove(); delete cards[cid]; }
    }
    ensureEmpty(Object.keys(cards).length === 0);
  }

  function addCard(id, req) {
    var card = document.createElement("div");
    card.className = "card";

    var who = document.createElement("div"); who.className = "who";
    who.textContent = "agent · approval request"; card.appendChild(who);
    var h = document.createElement("h2"); h.textContent = req.title; card.appendChild(h);
    if (req.body) { var p = document.createElement("p"); p.textContent = req.body; card.appendChild(p); }

    var timer = document.createElement("div"); timer.className = "timer";
    var left = document.createElement("div"); left.className = "left";
    var bar = document.createElement("div"); bar.className = "bar";
    var fill = document.createElement("i");
    bar.appendChild(fill); timer.appendChild(left); timer.appendChild(bar);
    card.appendChild(timer);

    var row = document.createElement("div"); row.className = "row";
    row.appendChild(makeBtn("Approve", "ok", CHECK, id));
    row.appendChild(makeBtn("Deny", "no", CROSS, id));
    card.appendChild(row);

    ensureEmpty(false);
    listEl.appendChild(card);
    cards[id] = { el: card, leftEl: left, fillEl: fill, barEl: bar, rowEl: row, req: req, done: false };
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
        c.leftEl.textContent = "expired — denied";
        c.fillEl.style.width = "0%";
        recordHist(c.req.title, "expired");
      }
      return;
    }
    c.leftEl.textContent = Math.ceil(remaining / 1000) + "s — then denied";
    c.fillEl.style.width = Math.min(100, (remaining / total) * 100) + "%";
    c.barEl.className = "bar" + (remaining < total * 0.25 ? " low" : "");
  }
  setInterval(function () {
    for (var id in cards) tickOne(cards[id]);
  }, 1000);

  function makeBtn(label, cls, icon, id) {
    var b = document.createElement("button");
    b.className = cls;
    b.innerHTML = icon + "<span></span>";
    b.querySelector("span").textContent = label;
    b.onclick = async function () {
      var c = cards[id];
      if (!c || c.done) return;
      b.disabled = true;
      var payload = await sealPayload(
        { requestId: id, approved: cls === "ok", ts: Date.now() },
        "dec:" + id
      );
      await fetch("/api/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: pair.pairId, requestId: id, payload: payload }),
      });
      if (cards[id]) {
        recordHist(cards[id].req.title, cls === "ok" ? "approved" : "denied");
        cards[id].el.remove();
        delete cards[id];
      }
      ensureEmpty(Object.keys(cards).length === 0);
    };
    return b;
  }

  fetchPending();
})();
</script>
</body>
</html>
`;
