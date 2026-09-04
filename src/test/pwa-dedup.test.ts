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
 * One request must never render twice. Concurrent refreshes (an SSE event,
 * the safety poll and a visibility change can all land together) used to
 * race in the async gap between "do I already have this card?" and adding
 * it, leaving a duplicate whose buttons pointed at nothing.
 */
test("concurrent refreshes render a single card per request", async () => {
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
      const approver = new PwaApprover({
        relayUrl,
        pairId: pairing.pairId,
        secret: pairing.secret,
      });
      const deciding = approver.request({ title: "Only once", timeoutSec: 25 }).catch(() => {});

      // Wait until the relay actually holds the request, otherwise the
      // burst below races an empty queue and proves nothing.
      for (let i = 0; i < 60; i++) {
        const items = (await (
          await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`)
        ).json()) as unknown[];
        if (items.length) break;
        await new Promise((r) => setTimeout(r, 50));
      }

      // Every visibilitychange kicks a refresh; firing a burst reproduces
      // the overlap that a real phone hits when push, SSE and poll agree.
      for (let i = 0; i < 8; i++) {
        window.document.dispatchEvent(new window.Event("visibilitychange"));
      }
      await waitFor(() => window.document.querySelector(".card"));
      await new Promise((r) => setTimeout(r, 1500)); // let every racer land

      const cards = window.document.querySelectorAll(".card");
      assert.equal(cards.length, 1, `rendered ${cards.length} cards for one request`);
      assert.equal(
        window.document.querySelectorAll(".card button.ok").length,
        1,
        "a duplicate card left dead buttons behind"
      );

      // And the surviving card must still work.
      window.document.querySelector(".card button.ok").click();
      await waitFor(() => (window.document.querySelectorAll(".card").length === 0 ? true : null));
      await deciding;
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});
