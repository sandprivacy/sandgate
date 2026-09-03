/**
 * The phone-side PWA, shipped as strings so the npm package stays
 * self-contained. The inline JS mirrors src/pwacrypto.ts byte-for-byte:
 * HKDF-SHA256(salt "sandgate-pwa-v1", info "approval-channel") -> AES-256-GCM,
 * AAD "req:<id>" / "dec:<id>". The pairing secret arrives once in the URL
 * fragment (never sent to the relay) and lives in localStorage.
 */

export const PWA_MANIFEST = JSON.stringify({
  name: "sandgate",
  short_name: "sandgate",
  start_url: "/",
  display: "standalone",
  background_color: "#14120d",
  theme_color: "#14120d",
});

export const PWA_SW = `
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener("push", function (e) {
  e.waitUntil((async function () {
    await self.registration.showNotification("sandgate", {
      body: "🚪 Approval requested — tap to answer",
      tag: "sandgate-approval",
      renotify: true,
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

export const PWA_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<link rel="manifest" href="/manifest.webmanifest">
<title>sandgate</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; background: #14120d; color: #ece7da; font: 16px/1.5 system-ui, sans-serif; }
  .wrap { max-width: 480px; margin: 0 auto; padding: 24px 16px 48px; }
  h1 { font-size: 22px; margin: 0 0 4px; } h1 span { color: #d29b3d; }
  .status { font-size: 13px; color: #a89f8c; margin-bottom: 20px; }
  .card { background: #24211a; border: 1px solid #3a352a; border-radius: 10px; padding: 16px; margin-bottom: 14px; }
  .card h2 { font-size: 17px; margin: 0 0 6px; }
  .card p { margin: 0 0 12px; color: #cfc8b8; font-size: 14px; white-space: pre-wrap; overflow-wrap: anywhere; }
  .meta { font-size: 12px; color: #a89f8c; margin-bottom: 12px; }
  .row { display: flex; gap: 10px; }
  button { flex: 1; padding: 12px; font-size: 16px; font-weight: 600; border: 0; border-radius: 8px; cursor: pointer; }
  .ok { background: #2f6b4f; color: #fff; } .no { background: #9c3f2e; color: #fff; }
  .expired { opacity: 0.45; }
  .empty { text-align: center; color: #a89f8c; padding: 40px 0; }
</style>
</head>
<body>
<div class="wrap">
  <h1><span>🚪</span> sandgate</h1>
  <div class="status" id="status">starting…</div>
  <div id="list"></div>
</div>
<script>
(function () {
  var PAIR_KEY = "sandgate_pair";

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
  var statusEl = document.getElementById("status");
  var listEl = document.getElementById("list");
  if (!pair) {
    statusEl.textContent = "Not paired. On your computer, run: sandgate pair — then open the link it prints on this phone.";
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
          if (e.data === "refresh") refresh();
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
            statusEl.textContent = "Paired — push notifications on.";
            return;
          }
        }
      }
      statusEl.textContent = "Paired — keep this tab open (no push permission).";
    } catch (e) {
      statusEl.textContent = "Paired — push unavailable (" + e.message + "). Polling instead.";
    }
  })();

  // --- approval list -------------------------------------------------------
  async function refresh() {
    var res, items;
    try {
      res = await fetch("/api/pending?pairId=" + encodeURIComponent(pair.pairId));
      items = await res.json();
    } catch (e) { return; }
    var frag = document.createDocumentFragment();
    var shown = 0;
    for (var i = 0; i < items.length; i++) {
      var item = items[i];
      var req;
      try { req = await openSealed(item.payload, "req:" + item.requestId); }
      catch (e) { continue; } // not for this pairing / tampered
      var remaining = Math.round((req.ts + req.timeoutSec * 1000 - Date.now()) / 1000);
      var card = document.createElement("div");
      card.className = "card" + (remaining <= 0 ? " expired" : "");
      var h = document.createElement("h2"); h.textContent = req.title; card.appendChild(h);
      if (req.body) { var p = document.createElement("p"); p.textContent = req.body; card.appendChild(p); }
      var meta = document.createElement("div"); meta.className = "meta";
      meta.textContent = remaining > 0 ? remaining + "s left — no answer = denied" : "expired — denied";
      card.appendChild(meta);
      if (remaining > 0) {
        var row = document.createElement("div"); row.className = "row";
        row.appendChild(makeBtn("✅ Approve", "ok", item.requestId, true));
        row.appendChild(makeBtn("❌ Deny", "no", item.requestId, false));
        card.appendChild(row);
      }
      frag.appendChild(card);
      shown++;
    }
    listEl.textContent = "";
    if (!shown) {
      var empty = document.createElement("div"); empty.className = "empty";
      empty.textContent = "Nothing waiting for you. 🎉";
      listEl.appendChild(empty);
    } else {
      listEl.appendChild(frag);
    }
  }

  function makeBtn(label, cls, requestId, approved) {
    var b = document.createElement("button");
    b.className = cls; b.textContent = label;
    b.onclick = async function () {
      b.disabled = true;
      var payload = await sealPayload(
        { requestId: requestId, approved: approved, ts: Date.now() },
        "dec:" + requestId
      );
      await fetch("/api/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: pair.pairId, requestId: requestId, payload: payload }),
      });
      refresh();
    };
    return b;
  }

  refresh();
  setInterval(function () { if (!document.hidden) refresh(); }, 4000);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });
})();
</script>
</body>
</html>
`;
