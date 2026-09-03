import { GLYPH_SVG_RECTS } from "./icons.js";

/**
 * The phone-side PWA, shipped as strings so the npm package stays
 * self-contained. The inline JS mirrors src/pwacrypto.ts byte-for-byte:
 * HKDF-SHA256(salt "sandgate-pwa-v1", info "approval-channel") -> AES-256-GCM,
 * AAD "req:<id>" / "dec:<id>". The pairing secret arrives once in the URL
 * fragment (never sent to the relay) and lives in localStorage.
 * No emoji anywhere: the identity is the geometric gate mark from icons.ts.
 */

export const PWA_MANIFEST = JSON.stringify({
  name: "sandgate",
  short_name: "sandgate",
  start_url: "/",
  display: "standalone",
  background_color: "#141210",
  theme_color: "#141210",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
  ],
});

export const PWA_SW = `
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
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
  button {
    flex: 1; display: flex; align-items: center; justify-content: center; gap: 8px;
    padding: 13px; font-size: 15.5px; font-weight: 650;
    border: 0; border-radius: 10px; cursor: pointer; color: #fff;
    font-family: inherit; letter-spacing: .01em;
    transition: transform .06s ease;
  }
  button:active { transform: scale(.97); }
  button:disabled { opacity: .5; }
  .ok { background: var(--ok); } .ok:active { background: var(--ok-press); }
  .no { background: var(--no); } .no:active { background: var(--no-press); }
  .expired { opacity: .45; }
  .expired h2 { text-decoration: line-through; text-decoration-thickness: 1px; }

  .empty { text-align: center; padding: 72px 20px; color: var(--soft); }
  .empty .mark { color: var(--accent); opacity: .3; margin-bottom: 16px; }
  .empty .big { font-size: 16px; color: #cfc6b2; margin-bottom: 4px; }
  .empty .hint { font-size: 13px; }

  .setup { text-align: center; padding: 60px 24px; color: #cfc6b2; }
  .setup .mark { color: var(--accent); opacity: .5; margin-bottom: 16px; }
  .setup code {
    display: inline-block; margin-top: 10px; padding: 8px 14px; border-radius: 8px;
    background: var(--panel-raised); border: 1px solid var(--line);
    font: 14px ui-monospace, "Cascadia Mono", monospace; color: var(--accent);
  }
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
<main><div id="list"></div></main>
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
  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = "pill" + (cls ? " " + cls : "");
  }

  // --- pairing -------------------------------------------------------------
  var pair = null;
  var m = location.hash.match(/p=([A-Za-z0-9_-]+)&s=([A-Za-z0-9_-]+)/);
  if (m) {
    pair = { pairId: m[1], secret: m[2] };
    try { localStorage.setItem(PAIR_KEY, JSON.stringify(pair)); } catch (e) {}
    history.replaceState(null, "", location.pathname);
  } else {
    try { pair = JSON.parse(localStorage.getItem(PAIR_KEY)); } catch (e) {}
  }
  if (!pair) {
    setStatus("not paired", "err");
    listEl.innerHTML = '<div class="setup"><div class="mark">' + GLYPH + '</div>Not paired yet.<br>On your computer, run<br><code>sandgate pair</code><br><br>then open the link it prints on this device.</div>';
    return;
  }

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

  // --- push subscription ---------------------------------------------------
  (async function () {
    try {
      if ("serviceWorker" in navigator) {
        var reg = await navigator.serviceWorker.register("/sw.js");
        navigator.serviceWorker.addEventListener("message", function (e) {
          if (e.data === "refresh") fetchPending();
        });
        if ("PushManager" in window) {
          var perm = await Notification.requestPermission();
          if (perm === "granted") {
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
            setStatus("push on");
            return;
          }
        }
      }
      setStatus("polling — keep open", "warn");
    } catch (e) {
      setStatus("polling — keep open", "warn");
    }
  })();

  // --- approval list -------------------------------------------------------
  var items = []; // [{requestId, req:{title,body,timeoutSec,ts}, decided}]

  async function fetchPending() {
    var res, raw;
    try {
      res = await fetch("/api/pending?pairId=" + encodeURIComponent(pair.pairId));
      raw = await res.json();
    } catch (e) { return; }
    var next = [];
    for (var i = 0; i < raw.length; i++) {
      var existing = items.find(function (x) { return x.requestId === raw[i].requestId; });
      if (existing) { next.push(existing); continue; }
      try {
        var req = await openSealed(raw[i].payload, "req:" + raw[i].requestId);
        next.push({ requestId: raw[i].requestId, req: req, decided: false });
      } catch (e) { /* not ours / tampered */ }
    }
    items = next;
    render();
  }

  function render() {
    listEl.textContent = "";
    var active = items.filter(function (x) { return !x.decided; });
    if (!active.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.innerHTML = '<div class="mark">' + GLYPH + '</div><div class="big">All quiet.</div><div class="hint">When an agent needs you, it shows up here.</div>';
      listEl.appendChild(empty);
      return;
    }
    active.forEach(function (item) {
      var req = item.req;
      var total = req.timeoutSec * 1000;
      var remaining = Math.max(0, req.ts + total - Date.now());
      var card = document.createElement("div");
      card.className = "card" + (remaining <= 0 ? " expired" : "");

      var who = document.createElement("div"); who.className = "who";
      who.textContent = "agent · approval request"; card.appendChild(who);
      var h = document.createElement("h2"); h.textContent = req.title; card.appendChild(h);
      if (req.body) { var p = document.createElement("p"); p.textContent = req.body; card.appendChild(p); }

      var timer = document.createElement("div"); timer.className = "timer";
      var left = document.createElement("div"); left.className = "left";
      var secs = Math.ceil(remaining / 1000);
      left.textContent = remaining > 0 ? secs + "s — then denied" : "expired — denied";
      var bar = document.createElement("div"); bar.className = "bar" + (remaining > 0 && remaining < total * .25 ? " low" : "");
      var fill = document.createElement("i");
      fill.style.width = Math.max(0, Math.min(100, (remaining / total) * 100)) + "%";
      bar.appendChild(fill); timer.appendChild(left); timer.appendChild(bar);
      card.appendChild(timer);

      if (remaining > 0) {
        var row = document.createElement("div"); row.className = "row";
        row.appendChild(makeBtn("Approve", "ok", CHECK, item));
        row.appendChild(makeBtn("Deny", "no", CROSS, item));
        card.appendChild(row);
      }
      listEl.appendChild(card);
    });
  }

  function makeBtn(label, cls, icon, item) {
    var b = document.createElement("button");
    b.className = cls;
    b.innerHTML = icon + "<span></span>";
    b.querySelector("span").textContent = label;
    b.onclick = async function () {
      b.disabled = true;
      var payload = await sealPayload(
        { requestId: item.requestId, approved: cls === "ok", ts: Date.now() },
        "dec:" + item.requestId
      );
      await fetch("/api/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: pair.pairId, requestId: item.requestId, payload: payload }),
      });
      item.decided = true;
      render();
    };
    return b;
  }

  fetchPending();
  setInterval(function () { if (!document.hidden) fetchPending(); }, 4000);
  setInterval(function () { if (!document.hidden) render(); }, 1000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) fetchPending(); });
})();
</script>
</body>
</html>
`;
