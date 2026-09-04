import { webcrypto } from "node:crypto";
import { JSDOM } from "jsdom";
import { PWA_HTML } from "../../relay/pwa-page.js";

/**
 * Loads the REAL page script into a DOM wired to a REAL relay: this is the
 * layer that caught nothing while it didn't exist, and now gates releases.
 */
export async function loadPage(
  relayUrl: string,
  opts: {
    hash?: string;
    localStorage?: Record<string, string>;
    /** Prepare the window (stub APIs jsdom lacks) before the page runs. */
    beforeScript?: (window: any) => void;
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
  opts.beforeScript?.(w);
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

/**
 * Without EventSource in jsdom the page falls back to its 8s poll, so give
 * waits comfortable room past that boundary.
 */
export function waitFor<T>(fn: () => T | null | undefined, ms = 15000): Promise<T> {
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
