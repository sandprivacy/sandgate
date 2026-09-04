import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import webpush from "web-push";
import { PWA_HTML, PWA_SW, pwaManifest } from "./pwa-page.js";
import { ICON_SVG, iconPng } from "./icons.js";

/**
 * The sandgate relay: bridges a gateway (on a computer) and the paired
 * phone's PWA. It stores push subscriptions and forwards *sealed* blobs in
 * both directions — it holds no key and can read nothing. Self-host it
 * (`sandgate relay`) behind TLS, or use a hosted one. State (VAPID keys,
 * subscriptions) persists to a small JSON file; queues are in-memory.
 */

interface RelayRequestEntry {
  requestId: string;
  payload: unknown;
  ts: number;
  decision?: unknown;
  waiters: ((decision: unknown) => void)[];
}

interface Pairing {
  subscription?: webpush.PushSubscription;
  requests: Map<string, RelayRequestEntry>;
  /** Timestamps of recent requests, for the per-pairing rate limit. */
  recent: number[];
  /** Open SSE responses from PWA pages; notified on new requests/decisions. */
  listeners: Set<ServerResponse>;
  /** Last time a PWA page with this pairing said hello (push or not). */
  lastSeen?: number;
}

const MAX_BODY = 64 * 1024;
const REQUEST_TTL_MS = 30 * 60 * 1000;

/**
 * Per-pairing limits. Notification fatigue is a real attack: a
 * compromised gateway or server could bury the phone under approval
 * requests until someone taps yes out of reflex. A pairing that exceeds
 * these is told to stop, and the gateway treats that as a refusal.
 */
const RATE_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 12;
const MAX_UNDECIDED = 5;
/** Open event streams kept per pairing; a phone needs one, maybe two. */
const MAX_LISTENERS = 8;

export async function startRelay(opts: {
  port: number;
  stateDir: string;
}): Promise<{ close: () => void; port: number }> {
  mkdirSync(opts.stateDir, { recursive: true });
  const statePath = join(opts.stateDir, "relay-state.json");

  let state: {
    vapid: { publicKey: string; privateKey: string };
    subscriptions: Record<string, webpush.PushSubscription>;
  };
  if (existsSync(statePath)) {
    state = JSON.parse(readFileSync(statePath, "utf8"));
  } else {
    const keys = webpush.generateVAPIDKeys();
    state = { vapid: keys, subscriptions: {} };
    writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  }
  const persist = () => writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  // Apple's push service rejects invalid VAPID subjects (a .local mailto
  // qualifies); use a real https URL and log delivery failures instead of
  // swallowing them.
  webpush.setVapidDetails("https://sandgate.dev", state.vapid.publicKey, state.vapid.privateKey);

  const pairings = new Map<string, Pairing>();
  const getPairing = (pairId: string): Pairing => {
    let p = pairings.get(pairId);
    if (!p) {
      p = {
        subscription: state.subscriptions[pairId],
        requests: new Map(),
        listeners: new Set(),
        recent: [],
      };
      pairings.set(pairId, p);
    }
    return p;
  };

  const notifyListeners = (pairing: Pairing, event: string) => {
    for (const listener of pairing.listeners) {
      listener.write(`event: ${event}\ndata: {}\n\n`);
    }
  };

  const gc = setInterval(() => {
    const cutoff = Date.now() - REQUEST_TTL_MS;
    for (const p of pairings.values()) {
      for (const [id, entry] of p.requests) {
        if (entry.ts < cutoff) p.requests.delete(id);
      }
    }
  }, 60_000);
  gc.unref();

  function json(res: ServerResponse, status: number, body: unknown): void {
    const data = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(data);
  }

  function readBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_BODY) {
          reject(new Error("body too large"));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch {
          reject(new Error("invalid JSON"));
        }
      });
      req.on("error", reject);
    });
  }

  const validId = (s: unknown): s is string =>
    typeof s === "string" && /^[A-Za-z0-9_-]{8,64}$/.test(s);

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    try {
      // --- static PWA ---
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(PWA_HTML);
      }
      if (req.method === "GET" && url.pathname === "/sw.js") {
        res.writeHead(200, { "Content-Type": "application/javascript" });
        return res.end(PWA_SW);
      }
      if (req.method === "GET" && url.pathname === "/manifest.webmanifest") {
        const isApple = /iPhone|iPad|iPod/.test(req.headers["user-agent"] ?? "");
        res.writeHead(200, {
          "Content-Type": "application/manifest+json",
          Vary: "User-Agent",
        });
        return res.end(pwaManifest({ includeStartUrl: !isApple }));
      }
      if (req.method === "GET" && url.pathname === "/icon.svg") {
        res.writeHead(200, { "Content-Type": "image/svg+xml", "Cache-Control": "max-age=86400" });
        return res.end(ICON_SVG);
      }
      const iconMatch = url.pathname.match(/^\/icon-(180|192|512)\.png$/);
      if (req.method === "GET" && iconMatch) {
        res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "max-age=86400" });
        return res.end(iconPng(parseInt(iconMatch[1]!, 10)));
      }

      // --- API ---
      if (req.method === "GET" && url.pathname === "/api/health") {
        let activeRequests = 0;
        for (const p of pairings.values()) {
          for (const e of p.requests.values()) if (e.decision === undefined) activeRequests++;
        }
        return json(res, 200, {
          ok: true,
          uptime_sec: Math.round(process.uptime()),
          pairings: Object.keys(state.subscriptions).length,
          active_requests: activeRequests,
        });
      }
      if (req.method === "GET" && url.pathname === "/api/vapid") {
        return json(res, 200, { publicKey: state.vapid.publicKey });
      }

      if (req.method === "POST" && url.pathname === "/api/subscribe") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !body.subscription?.endpoint) {
          return json(res, 400, { error: "pairId and subscription required" });
        }
        getPairing(body.pairId).subscription = body.subscription;
        state.subscriptions[body.pairId] = body.subscription;
        persist();
        return json(res, 200, { ok: true });
      }

      // The page announces itself on load, push or not — this is what lets
      // `sandgate pair` say "phone connected" even before notifications.
      if (req.method === "POST" && url.pathname === "/api/hello") {
        const body = await readBody(req);
        if (!validId(body.pairId)) return json(res, 400, { error: "bad pairId" });
        getPairing(body.pairId).lastSeen = Date.now();
        return json(res, 200, { ok: true });
      }

      if (req.method === "GET" && url.pathname === "/api/pair-status") {
        const pairId = url.searchParams.get("pairId") ?? "";
        if (!validId(pairId)) return json(res, 400, { error: "bad pairId" });
        const pairing = getPairing(pairId);
        return json(res, 200, {
          subscribed: !!pairing.subscription,
          seen: !!pairing.lastSeen || !!pairing.subscription,
        });
      }

      if (req.method === "POST" && url.pathname === "/api/request") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validId(body.requestId) || !body.payload) {
          return json(res, 400, { error: "pairId, requestId, payload required" });
        }
        const pairing = getPairing(body.pairId);

        const now = Date.now();
        pairing.recent = pairing.recent.filter((t) => now - t < RATE_WINDOW_MS);
        let undecided = 0;
        for (const entry of pairing.requests.values()) {
          if (entry.decision === undefined && now - entry.ts < REQUEST_TTL_MS) undecided++;
        }
        if (pairing.recent.length >= MAX_REQUESTS_PER_WINDOW || undecided >= MAX_UNDECIDED) {
          return json(res, 429, {
            error:
              "Too many approval requests for this pairing. The phone is being flooded; " +
              "answer or let the pending ones expire.",
          });
        }
        pairing.recent.push(now);

        pairing.requests.set(body.requestId, {
          requestId: body.requestId,
          payload: body.payload,
          ts: Date.now(),
          waiters: [],
        });
        if (pairing.subscription) {
          webpush
            .sendNotification(pairing.subscription, JSON.stringify({ type: "approval" }))
            .catch((err: any) => {
              // Phone offline / stale sub is normal (PWA polls anyway), but
              // ops must be able to SEE a push service rejecting us.
              console.error(
                `[push] delivery failed (HTTP ${err?.statusCode ?? "?"}): ${String(err?.body ?? err).slice(0, 200)}`
              );
            });
        }
        notifyListeners(pairing, "request");
        return json(res, 200, { ok: true });
      }

      // SSE stream for open PWA pages: instant updates instead of polling.
      if (req.method === "GET" && url.pathname === "/api/events") {
        const pairId = url.searchParams.get("pairId") ?? "";
        if (!validId(pairId)) return json(res, 400, { error: "bad pairId" });
        const pairing = getPairing(pairId);
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        res.write("retry: 3000\n\n");
        pairing.listeners.add(res);
        // Heartbeat keeps proxies (and our own 90s read timeout) from
        // cutting an idle stream; EventSource ignores comment lines.
        const heartbeat = setInterval(() => res.write(": hb\n\n"), 25_000);
        req.on("close", () => {
          clearInterval(heartbeat);
          pairing.listeners.delete(res);
        });
        return;
      }

      if (req.method === "GET" && url.pathname === "/api/pending") {
        const pairId = url.searchParams.get("pairId") ?? "";
        if (!validId(pairId)) return json(res, 400, { error: "bad pairId" });
        const items = [...getPairing(pairId).requests.values()]
          .filter((e) => e.decision === undefined)
          .map((e) => ({ requestId: e.requestId, payload: e.payload, ts: e.ts }));
        return json(res, 200, items);
      }

      if (req.method === "POST" && url.pathname === "/api/decision") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validId(body.requestId) || !body.payload) {
          return json(res, 400, { error: "pairId, requestId, payload required" });
        }
        const entry = getPairing(body.pairId).requests.get(body.requestId);
        if (!entry) return json(res, 404, { error: "unknown request" });
        if (entry.decision !== undefined) return json(res, 200, { ok: true }); // first tap wins
        entry.decision = body.payload;
        for (const waiter of entry.waiters.splice(0)) waiter(body.payload);
        notifyListeners(getPairing(body.pairId), "decision");
        return json(res, 200, { ok: true });
      }

      if (req.method === "GET" && url.pathname === "/api/decision") {
        const pairId = url.searchParams.get("pairId") ?? "";
        const requestId = url.searchParams.get("requestId") ?? "";
        const timeoutSec = Math.min(30, parseInt(url.searchParams.get("timeoutSec") ?? "25", 10) || 25);
        if (!validId(pairId) || !validId(requestId)) return json(res, 400, { error: "bad ids" });
        const entry = getPairing(pairId).requests.get(requestId);
        if (!entry) return json(res, 404, { error: "unknown request" });
        if (entry.decision !== undefined) return json(res, 200, { payload: entry.decision });
        const timer = setTimeout(() => {
          const idx = entry.waiters.indexOf(waiter);
          if (idx >= 0) entry.waiters.splice(idx, 1);
          res.writeHead(204);
          res.end();
        }, timeoutSec * 1000);
        const waiter = (decision: unknown) => {
          clearTimeout(timer);
          json(res, 200, { payload: decision });
        };
        entry.waiters.push(waiter);
        return;
      }

      json(res, 404, { error: "not found" });
    } catch (err) {
      json(res, 400, { error: err instanceof Error ? err.message : "bad request" });
    }
  });

  await new Promise<void>((resolve) => server.listen(opts.port, resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  return { close: () => server.close(), port };
}
