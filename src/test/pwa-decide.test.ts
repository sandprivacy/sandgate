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
 * Answering on the phone, the way it went wrong for real: a 429 or a
 * dropped request turned an Approve into an alert and a refused login;
 * tapping Deny while Approve was in flight sent both; a request that had
 * already expired showed as an error; with several requests, the ones
 * below the fold went unseen; the history cut every line at the edge.
 */

async function setup(faults: { decision: Array<number | "drop"> }) {
  const relay = await startRelay({ port: 0, stateDir: mkdtempSync(join(tmpdir(), "sg-decide-")) });
  const relayUrl = `http://localhost:${relay.port}`;
  const pairing = newPairing();
  const posted: string[] = [];
  const page = await loadPage(relayUrl, {
    hash: `#p=${pairing.pairId}&s=${pairing.secret}`,
    beforeScript: (w) => {
      const real = w.fetch;
      w.fetch = (input: string, init?: any) => {
        if (String(input).includes("/api/decision") && init?.method === "POST") {
          posted.push(JSON.parse(init.body).requestId);
          const fault = faults.decision.shift();
          if (fault === "drop") return Promise.reject(new TypeError("Load failed"));
          if (typeof fault === "number") {
            return Promise.resolve(new Response(JSON.stringify({ error: "x" }), { status: fault }));
          }
        }
        return real(input, init);
      };
    },
  });
  const approver = new PwaApprover({ relayUrl, ...pairing });
  return {
    page,
    approver,
    posted,
    close: () => {
      page.close();
      relay.close();
    },
  };
}

const cardCount = (w: any) => w.document.querySelectorAll(".card").length;

test("a 429 or a dropped request on Approve is retried, not thrown at you", async () => {
  const s = await setup({ decision: [429, "drop", 503] });
  try {
    const deciding = s.approver.request({ title: "SSH login: root@us4", body: "From 203.0.113.7\nKey: baltha@MSI", timeoutSec: 30 });
    await waitFor(() => s.page.window.document.querySelector(".card button.ok"));
    s.page.window.document.querySelector(".card button.ok").click();
    assert.deepEqual(await deciding, { approved: true, decision: "approved" });
    await waitFor(() => (cardCount(s.page.window) === 0 ? true : null));
    assert.deepEqual(s.page.alerts, [], "no alert: the retries were silent");
    assert.equal(s.posted.length, 4, "three faults, then the answer");

    // History keeps the details, one tap away.
    const row = s.page.window.document.querySelector(".hrow.tap");
    assert.match(row.textContent, /approved/);
    row.click();
    const more = s.page.window.document.querySelector(".hmore");
    assert.match(more.textContent, /From 203\.0\.113\.7\nKey: baltha@MSI/);
    row.click();
    assert.equal(s.page.window.document.querySelector(".hmore"), null, "a second tap folds it");
  } finally {
    s.close();
  }
});

test("Deny tapped while Approve is in flight sends nothing more", async () => {
  const s = await setup({ decision: [503] }); // the first send stalls on a retry
  try {
    const deciding = s.approver.request({ title: "double tap", timeoutSec: 30 });
    await waitFor(() => s.page.window.document.querySelector(".card button.ok"));
    s.page.window.document.querySelector(".card button.ok").click();
    s.page.window.document.querySelector(".card button.no").click();
    assert.deepEqual(await deciding, { approved: true, decision: "approved" });
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(new Set(s.posted).size, 1);
    assert.equal(s.posted.length, 2, "the 503, then the one retry — no Deny");
  } finally {
    s.close();
  }
});

test("answering a request that is already gone is not an error", async () => {
  const s = await setup({ decision: [404] });
  try {
    const deciding = s.approver.request({ title: "too late", timeoutSec: 30 }).catch(() => null);
    await waitFor(() => s.page.window.document.querySelector(".card button.ok"));
    s.page.window.document.querySelector(".card button.ok").click();
    await waitFor(() => (cardCount(s.page.window) === 0 ? true : null));
    assert.deepEqual(s.page.alerts, []);
    assert.match(s.page.window.document.querySelector(".hrow").textContent, /expired/);
    void deciding;
  } finally {
    s.close();
  }
});

test("several requests at once: each its own card, each answered on its own", async () => {
  const s = await setup({ decision: [] });
  try {
    const a = s.approver.request({ title: "first", timeoutSec: 30 });
    const b = s.approver.request({ title: "second", timeoutSec: 30 });
    const c = s.approver.request({ title: "third", timeoutSec: 30 });
    await waitFor(() => (cardCount(s.page.window) === 3 ? true : null));
    // Below the fold (jsdom has no layout, so every card counts as off-screen):
    const pill = await waitFor(() => s.page.window.document.querySelector(".jump"));
    assert.equal(pill.textContent, "↑ 3 requests waiting");
    const byTitle = (t: string) =>
      [...s.page.window.document.querySelectorAll(".card")].find((el: any) => el.querySelector("h2").textContent === t) as any;
    byTitle("second").querySelector("button.no").click();
    byTitle("first").querySelector("button.ok").click();
    byTitle("third").querySelector("button.ok").click();
    assert.deepEqual(await a, { approved: true, decision: "approved" });
    assert.deepEqual(await b, { approved: false, decision: "denied" });
    assert.deepEqual(await c, { approved: true, decision: "approved" });
    await waitFor(() => (cardCount(s.page.window) === 0 ? true : null));
    assert.equal(s.page.window.document.querySelector(".jump"), null, "nothing waiting, no pill");
    assert.deepEqual(s.page.alerts, []);
  } finally {
    s.close();
  }
});
