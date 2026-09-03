import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";
import { newPairing } from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import { PWA_HTML } from "../relay/pwa-page.js";
import { PwaApprover } from "../pwa-approver.js";

/**
 * Browser-level tests: the REAL page script, executed in a DOM, against a
 * REAL relay — pairing via URL fragment, card rendering, a click on
 * Approve/Deny, and the legacy-storage migration. This is the layer that
 * caught nothing while it didn't exist; it exists now.
 */

async function loadPage(
  relayUrl: string,
  opts: {
    hash?: string;
    localStorage?: Record<string, string>;
  }
): Promise<{ window: any; alerts: string[]; close: () => void }> {
  const alerts: string[] = [];
  const dom = new JSDOM(PWA_HTML, {
    url: relayUrl + "/" + (opts.hash ?? ""),
    runScripts: "outside-only",
    pretendToBeVisual: true,
  });
  const w = dom.window as any;
  // The pieces jsdom doesn't ship, wired to the real relay / real crypto.
  w.fetch = (input: string, init?: any) => fetch(new URL(input, relayUrl), init);
  Object.defineProperty(w, "crypto", { value: webcrypto });
  w.alert = (message: string) => alerts.push(String(message));
  w.confirm = () => true;
  if (opts.localStorage) {
    for (const [key, value] of Object.entries(opts.localStorage)) {
      w.localStorage.setItem(key, value);
    }
  }
  // Execute the page's inline script exactly as a browser would. The
  // decision alert is instrumented to carry the full stack: a one-line
  // message told us nothing the day this layer was missing.
  let script = dom.window.document.querySelector("script")!.textContent!;
  script = script.replace(
    'alert("Could not send your decision: " + (err && err.message ? err.message : err));',
    'alert("Could not send your decision: " + (err && err.stack ? err.stack : err));'
  );
  dom.window.eval(script);
  // window.close() tears down the page's setIntervals so the test process
  // can exit; without it the suite hangs forever.
  return { window: w, alerts, close: () => dom.window.close() };
}

// Without EventSource in jsdom the page falls back to its 8s poll, so give
// waits comfortable room past that boundary.
function waitFor<T>(fn: () => T | null | undefined, ms = 15000): Promise<T> {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    const timer = setInterval(() => {
      const value = fn();
      if (value) {
        clearInterval(timer);
        resolve(value);
      } else if (Date.now() - started > ms) {
        clearInterval(timer);
        reject(new Error("waitFor timed out"));
      }
    }, 50);
  });
}

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
