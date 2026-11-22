import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newPairing } from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import { PwaApprover } from "../pwa-approver.js";
import { loadPage, waitFor } from "./helpers/page.js";

/**
 * Browser-level tests: the REAL page script, executed in a DOM, against a
 * REAL relay — pairing via URL fragment, card rendering, a click on
 * Approve/Deny, and the legacy-storage migration. This is the layer that
 * caught nothing while it didn't exist; it exists now.
 */

for (const scenario of ["fragment", "legacy-storage"] as const) {
  test(`page pairs (${scenario}), renders the card, and Approve round-trips`, async () => {
    const relay = await startRelay({
      port: 0,
      stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
    });
    const relayUrl = `http://localhost:${relay.port}`;
    try {
      const pairing = newPairing();
      const { window, alerts, close } = await loadPage(relayUrl, {
        hash: scenario === "fragment" ? `#p=${pairing.pairId}&s=${pairing.secret}` : undefined,
        localStorage:
          scenario === "legacy-storage"
            ? { sandgate_pair: JSON.stringify({ pairId: pairing.pairId, secret: pairing.secret }) }
            : undefined,
      });
      try {

      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
      });
      const decision = approver.request({
        title: "Browser-level test",
        body: "Click approve",
        timeoutSec: 15,
      });

      const okButton = await waitFor(() =>
        window.document.querySelector(".card button.ok")
      );
      assert.match(
        window.document.querySelector(".card h2").textContent,
        /Browser-level test/
      );
      okButton.click();

      const result = await decision;
      assert.deepEqual(alerts, [], `page alerted: ${alerts.join(" | ")}`);
      assert.deepEqual(result, { approved: true, decision: "approved" });
      await waitFor(() => window.document.querySelector(".hrow .d.approved"));
      } finally {
        close();
      }
    } finally {
      relay.close();
    }
  });
}

test("ask_human: the input card round-trips a typed answer", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const { window, alerts, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
    });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
      });
      const asked = approver.ask!({
        title: "What is the SMS code?",
        body: "Sent to your real number",
        timeoutSec: 15,
      });

      const input = await waitFor(() => window.document.querySelector(".card .answer-input"));
      assert.match(window.document.querySelector(".card .who").textContent, /question/);
      input.value = "  847291 ";
      const sendBtn = window.document.querySelector(".card button.ok");
      sendBtn.click();

      const result = await asked;
      assert.deepEqual(alerts, [], `page alerted: ${alerts.join(" | ")}`);
      assert.deepEqual(result, { answer: "847291", decision: "answered" });
      await waitFor(() => window.document.querySelector(".hrow .d.answered"));
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

test("ask_human: denying returns no answer", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const { window, alerts, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
    });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
      });
      const asked = approver.ask!({ title: "Secret question", timeoutSec: 15 });
      const denyBtn = await waitFor(() => window.document.querySelector(".card button.no"));
      denyBtn.click();
      const result = await asked;
      assert.deepEqual(result, { answer: null, decision: "denied" });
      assert.deepEqual(alerts, [], `page alerted: ${alerts.join(" | ")}`);
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

test("a request arriving on another tab is counted, and the pill goes to it, at the top", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const { window, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
    });
    try {
      const doc = window.document;
      assert.equal(doc.getElementById("tabs").hidden, false, "paired: the tab bar is there");
      doc.querySelector('[data-tab="hist"]').click();
      assert.ok(doc.getElementById("v-hist").classList.contains("on"));

      const approver = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
      const decision = approver.request({ title: "Deploy to prod", timeoutSec: 15 });
      const pill = await waitFor(() => doc.querySelector(".jump"));
      assert.match(pill.textContent, /1 request waiting/);
      assert.equal(doc.getElementById("b-req").textContent, "1");
      assert.ok(doc.getElementById("v-hist").classList.contains("on"), "never yanked away under your thumb");

      window.scrolls.length = 0;
      pill.click();
      assert.ok(doc.getElementById("v-req").classList.contains("on"));
      // The very top, title included: not scrolled to the card's buttons.
      assert.ok(window.scrolls.length > 0);
      assert.ok(window.scrolls.every((s: any) => s.top === 0), JSON.stringify(window.scrolls));

      doc.querySelector(".card button.ok").click();
      assert.equal((await decision).approved, true);
      await waitFor(() => doc.getElementById("b-req").textContent === "");
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

test("Deny works and corrupt stored pairings do not break the page", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    const { window, alerts, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
      // A broken entry left over from older versions must be ignored, not fatal.
      localStorage: {
        sandgate_pairs: JSON.stringify([{ name: "Broken", pairId: "brokenbroken" }]),
      },
    });
    try {
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
      });
      const decision = approver.request({ title: "Deny me", timeoutSec: 15 });

      const noButton = await waitFor(() => window.document.querySelector(".card button.no"));
      noButton.click();
      const result = await decision;
      assert.deepEqual(result, { approved: false, decision: "denied" });
      assert.deepEqual(alerts, [], `page alerted: ${alerts.join(" | ")}`);
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

test("a vault added later is registered for push as well", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const laptop = newPairing();
    const server = newPairing();
    const subscription = {
      endpoint: "https://fcm.googleapis.com/fcm/send/abc",
      keys: { p256dh: "x", auth: "y" },
    };

    const { close } = await loadPage(relayUrl, {
      // A phone that already had one vault and just added a second.
      localStorage: {
        sandgate_pairs: JSON.stringify([
          { name: "Laptop", pairId: laptop.pairId, secret: laptop.secret },
          { name: "vps-prod", pairId: server.pairId, secret: server.secret },
        ]),
      },
      beforeScript: (window) => {
        // Notifications were switched on long ago: the subscription
        // already exists, and no permission prompt happens.
        Object.defineProperty(window.navigator, "serviceWorker", {
          configurable: true,
          value: {
            register: async () => ({
              pushManager: {
                getSubscription: async () => subscription,
                subscribe: async () => subscription,
              },
            }),
            addEventListener: () => {},
          },
        });
        window.PushManager = function () {};
        window.Notification = { permission: "granted", requestPermission: async () => "granted" };
      },
    });

    try {
      // Registering only at enable-time left vaults added afterwards
      // silent — a real server never rang.
      const isSubscribed = async (pairId: string) => {
        const status = (await (
          await fetch(`${relayUrl}/api/pair-status?pairId=${pairId}`)
        ).json()) as { subscribed: boolean };
        return status.subscribed;
      };
      for (const pairing of [laptop, server]) {
        let subscribed = false;
        for (let i = 0; i < 100 && !subscribed; i++) {
          subscribed = await isSubscribed(pairing.pairId);
          if (!subscribed) await new Promise((r) => setTimeout(r, 50));
        }
        assert.equal(subscribed, true, "every paired vault must be reachable by push");
      }
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

test("a one-time pairing link pairs once, names the vault, then dies", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const { newClaimSecret, sealClaim, publishClaim, pairingLink } = await import("../pwacrypto.js");
    const pairing = newPairing();
    const claim = newClaimSecret();
    await publishClaim(relayUrl, pairing.pairId, sealClaim(claim, pairing.pairId, { secret: pairing.secret, name: "vps-prod" }));
    const link = pairingLink(relayUrl, pairing.pairId, claim, "vps-prod");
    const hash = link.slice(link.indexOf("#"));

    // First open: the phone collects the channel secret and remembers
    // the vault under the name the gateway gave it.
    const first = await loadPage(relayUrl, { hash });
    try {
      const stored = await waitFor(() => {
        const raw = first.window.localStorage.getItem("sandgate_pairs");
        return raw ? (JSON.parse(raw) as { name: string; pairId: string; secret: string }[]) : null;
      });
      assert.deepEqual(stored, [{ name: "vps-prod", pairId: pairing.pairId, secret: pairing.secret }]);
      assert.ok(!first.window.location.hash.includes(pairing.secret), "the secret never appears in a URL");
    } finally {
      first.close();
    }

    // Same link, found later by someone else: nothing to collect.
    const second = await loadPage(relayUrl, { hash });
    try {
      const message = await waitFor(() => {
        const p = second.window.document.querySelector(".setup p");
        return p && /expired or was already used/.test(p.textContent) ? p : null;
      });
      assert.ok(message);
      assert.equal(second.window.localStorage.getItem("sandgate_pairs"), null, "no vault must be added");
    } finally {
      second.close();
    }
  } finally {
    relay.close();
  }
});

test("the app offers to scan a pairing code when it has a camera", async () => {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const { window, close } = await loadPage(relayUrl, {
      beforeScript: (w) => {
        Object.defineProperty(w.navigator, "mediaDevices", {
          configurable: true,
          value: { getUserMedia: async () => ({ getTracks: () => [] }) },
        });
      },
    });
    try {
      const buttons = [...window.document.querySelectorAll("button")].map((b: any) => b.textContent);
      assert.ok(buttons.includes("Scan a QR code"), `expected a scan button, got ${buttons.join(", ")}`);

      // What a scan hands over is exactly what a paste would: a link.
      const { newClaimSecret, sealClaim, publishClaim, pairingLink } = await import("../pwacrypto.js");
      const pairing = newPairing();
      const claim = newClaimSecret();
      await publishClaim(relayUrl, pairing.pairId, sealClaim(claim, pairing.pairId, { secret: pairing.secret, name: "scanned" }));
      const added = await window.sandgate.takePairingText(pairingLink(relayUrl, pairing.pairId, claim, "scanned"));
      assert.equal(added, true);
      const stored = JSON.parse(window.localStorage.getItem("sandgate_pairs"));
      assert.deepEqual(stored, [{ name: "scanned", pairId: pairing.pairId, secret: pairing.secret }]);
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});

/** Let a page's first reads (requests, servers) land before closing it. */
const settle = () => new Promise((r) => setTimeout(r, 1500));

test("450 pairings: the app asks in slices, shows every vault's requests, and says so when the relay refuses", async () => {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")) });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const all = Array.from({ length: 450 }, (_, i) => ({ name: `srv-${i}`, ...newPairing() }));
    const calls: { url: string; body?: string }[] = [];
    const { window, close } = await loadPage(relayUrl, {
      localStorage: { sandgate_pairs: JSON.stringify(all.map((p) => ({ name: p.name, pairId: p.pairId, secret: p.secret }))) },
      beforeScript: (w) => {
        const real = w.fetch;
        w.fetch = (input: string, init?: any) => {
          calls.push({ url: String(input), body: init?.body });
          return real(input, init);
        };
      },
    });
    try {
      const far = all[420]!; // far beyond the old limit of 64, in the last slice
      const approver = new PwaApprover({ relayUrl, pairId: far.pairId, secret: far.secret });
      const decision = approver.request({ title: "From the 421st pairing", timeoutSec: 15 });
      const btn = await waitFor(() => window.document.querySelector(".card button.ok"));
      assert.equal(window.document.querySelector(".card h2").textContent, "From the 421st pairing");
      btn.click();
      assert.equal((await decision).approved, true);

      const pending = calls.filter((c) => c.url.startsWith("/api/pending"));
      assert.ok(pending.length >= 3, "three slices of 200 at most");
      for (const c of pending) assert.ok(new URL(c.url, relayUrl).searchParams.get("pairIds")!.split(",").length <= 200);
      // One hello per slice, not one per pairing: 450 calls at every load
      // is a burst nginx cuts into.
      const hellos = calls.filter((c) => c.url === "/api/hello");
      assert.equal(hellos.length, 3);
      assert.deepEqual(hellos.flatMap((c) => JSON.parse(c.body!).pairIds).sort(), all.map((p) => p.pairId).sort());
      assert.equal(window.document.getElementById("readerr").textContent, "");
      assert.equal(window.document.querySelector(".section-h").textContent, "Vaults and servers paired with this device (450)");
    } finally {
      close();
    }

    // A relay that refuses (the 64-id limit of 0.9.2): an error, not an empty screen.
    const refused = await loadPage(relayUrl, {
      localStorage: { sandgate_pairs: JSON.stringify([{ name: "a", pairId: all[0]!.pairId, secret: all[0]!.secret }]) },
      beforeScript: (w) => {
        const real = w.fetch;
        w.fetch = (input: string, init?: any) =>
          String(input).startsWith("/api/pending")
            ? Promise.resolve(new Response(JSON.stringify({ error: "bad pairId" }), { status: 400 }))
            : real(input, init);
      },
    });
    try {
      const err = await waitFor(() => refused.window.document.querySelector("#readerr .alert"));
      assert.match(err.textContent, /could not be read from the relay \(HTTP 400\)/);
      await settle();
    } finally {
      refused.close();
    }
  } finally {
    relay.close();
  }
});

test("pairing a server again under its name offers to replace the old pairing", async () => {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")) });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const old = newPairing();
    const { window, close } = await loadPage(relayUrl, {
      localStorage: { sandgate_pairs: JSON.stringify([{ name: "us4", pairId: old.pairId, secret: old.secret }]) },
    });
    try {
      const stored = () => JSON.parse(window.localStorage.getItem("sandgate_pairs")).map((p: any) => p.pairId);
      const again = newPairing();
      window.confirm = () => true;
      assert.equal(await window.sandgate.acceptPairingText(`${relayUrl}/#p=${again.pairId}&s=${again.secret}&n=us4`), true);
      assert.deepEqual(stored(), [again.pairId], "replaced");

      const other = newPairing();
      window.confirm = () => false;
      await window.sandgate.acceptPairingText(`${relayUrl}/#p=${other.pairId}&s=${other.secret}&n=us4`);
      assert.deepEqual(stored(), [again.pairId, other.pairId], "kept both when asked to");
      await settle();
    } finally {
      close();
    }

    // Duplicates already on a phone: the older one says so in Settings.
    const a = newPairing(), b = newPairing();
    const page = await loadPage(relayUrl, {
      localStorage: { sandgate_pairs: JSON.stringify([{ name: "us2", ...a }, { name: "us2", ...b }]) },
    });
    try {
      const rows = [...page.window.document.querySelectorAll("#vaults .hrow .t")].slice(0, 2).map((t: any) => t.textContent);
      assert.deepEqual(rows, ["us2 · older duplicate", "us2"]);
      await settle();
    } finally {
      page.close();
    }
  } finally {
    relay.close();
  }
});
