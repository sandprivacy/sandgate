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
      endpoint: "https://push.example/abc",
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
