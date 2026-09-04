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
