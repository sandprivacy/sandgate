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
 * A phone's network is flaky by nature: it wakes up after the page does,
 * the relay restarts, a proxy answers with an error page, the relay says
 * 429. None of that means "the request is gone". The page used to treat
 * every failed read as an empty list — the card vanished, then came back
 * a refresh later: the "shows for a second, disappears, reappears" bug.
 */
test("a failed read never removes a card; the card still works after", async () => {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-flaky-")) });
  const relayUrl = `http://localhost:${relay.port}`;
  try {
    const pairing = newPairing();
    let mode: "ok" | "throw" | "502" | "429" = "ok";
    const { window, close } = await loadPage(relayUrl, {
      hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
      beforeScript: (w) => {
        const real = w.fetch;
        w.fetch = (input: string, init?: any) => {
          if (String(input).includes("/api/pending") && mode !== "ok") {
            if (mode === "throw") return Promise.reject(new TypeError("Load failed"));
            if (mode === "502") {
              return Promise.resolve(new Response("<html>Bad gateway</html>", { status: 502 }));
            }
            return Promise.resolve(
              new Response(JSON.stringify({ error: "Too many requests" }), {
                status: 429,
                headers: { "Content-Type": "application/json" },
              })
            );
          }
          return real(input, init);
        };
      },
    });
    try {
      const approver = new PwaApprover({ relayUrl, pairId: pairing.pairId, secret: pairing.secret });
      const deciding = approver.request({ title: "Stay put", timeoutSec: 40 });
      await waitFor(() => window.document.querySelector(".card"));

      for (const failure of ["throw", "502", "429"] as const) {
        mode = failure;
        for (let i = 0; i < 3; i++) window.document.dispatchEvent(new window.Event("visibilitychange"));
        await new Promise((r) => setTimeout(r, 700));
        assert.equal(
          window.document.querySelectorAll(".card").length,
          1,
          `a ${failure} on /api/pending removed the card`
        );
      }

      mode = "ok";
      window.document.querySelector(".card button.ok").click();
      const decision = await deciding;
      assert.equal(decision.approved, true);
      // And a successful read does retire the answered card.
      await waitFor(() => (window.document.querySelectorAll(".card").length === 0 ? true : null));
    } finally {
      close();
    }
  } finally {
    relay.close();
  }
});
