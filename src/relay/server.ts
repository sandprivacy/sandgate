import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { createRequire } from "node:module";
import { createHash, timingSafeEqual } from "node:crypto";
import webpush from "web-push";
import { PWA_HTML, PWA_SW, pwaManifest } from "./pwa-page.js";
import { ICON_SVG, iconPng } from "./icons.js";
import { SERVER_VERSION, VERSION } from "../version.js";

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
  /**
   * Every sealed decision received, in order. A gateway that wants more
   * than one device to agree reads them all; the first one is also
   * exposed as `payload` for gateways that predate quorums.
   */
  decisions: unknown[];
  /** How many decisions the gateway wants before the phones stop showing it. */
  needed: number;
  /**
   * When the gateway stops waiting (its ttlSec). A gateway killed mid-wait
   * — sshd dropping a login, a Ctrl-C — never says goodbye; without this
   * its request counted as "undecided" for 30 minutes, and five of them
   * locked the pairing out of new requests.
   */
  expiresAt: number;
  waiters: ((decisions: unknown[]) => void)[];
}

interface Pairing {
  /**
   * Every device that switched notifications on for this vault. One per
   * pairing used to be the rule, so a second device silently took the
   * pushes away from the first.
   */
  subscriptions: webpush.PushSubscription[];
  requests: Map<string, RelayRequestEntry>;
  /** Timestamps of recent requests, for the per-pairing rate limit. */
  recent: number[];
  /** Open SSE responses from PWA pages; notified on new requests/decisions. */
  listeners: Set<ServerResponse>;
  /** Last time a PWA page with this pairing said hello (push or not). */
  lastSeen?: number;
  /** The one-time pairing blob, until a phone collects it or it expires. */
  claim?: { payload: unknown; ts: number };
  /** When a phone collected the claim — the pairing is spoken for. */
  claimedAt?: number;
  /** The server's last heartbeat, sealed. */
  status?: StoredStatus;
}

/**
 * What the relay keeps of a heartbeat: the sealed blob it cannot read,
 * and the one thing it can see — when it arrived. That is enough to tell
 * the phone "this pairing went quiet" without knowing what it is.
 */
interface StoredStatus {
  payload: unknown;
  receivedAt: number;
  intervalSec: number;
  /** The phone was told this server went quiet; tell it when it is back. */
  offlineAlerted?: boolean;
}

const MAX_BODY = 64 * 1024;
const REQUEST_TTL_MS = 30 * 60 * 1000;
/**
 * A pairing link lives this long, then the sealed secret it points at is
 * gone. Long enough to walk to your phone; short enough that a link in a
 * chat log is worthless by the time anyone reads it.
 */
export const CLAIM_TTL_MS = 10 * 60 * 1000;

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
/** Devices that can receive pushes for one pairing; the oldest goes first. */
const MAX_SUBSCRIPTIONS = 8;
/**
 * How long a push service keeps trying to deliver. Without it web-push
 * asks for four weeks, and a phone back online hours later rings for a
 * request that died long ago. Gateways send the request's own timeout.
 */
const PUSH_TTL_DEFAULT_SEC = 600;
/** Heartbeats closer together than this are refused. */
const MIN_STATUS_GAP_MS = 20 * 1000;
/** Statuses kept at most: invented pair ids must not fill the disk. */
const MAX_STATUSES = 5000;
/** A server is "quiet" after missing this many heartbeats in a row… */
const MISSED_BEATS = 3;
/** …and never sooner than this, whatever interval it announces. */
const MIN_QUIET_MS = 10 * 60 * 1000;
export const quietAfterMs = (intervalSec: number) => Math.max(MIN_QUIET_MS, MISSED_BEATS * intervalSec * 1000 + 60_000);

/**
 * Per-address limit, on top of the per-pairing one: the pairing limit
 * does nothing against invented pair ids. A phone polls every few
 * seconds and a gateway long-polls every 25s, so this is generous for
 * anyone real and a wall for a loop.
 */
const IP_WINDOW_MS = 60 * 1000;
const MAX_PER_IP = 240;
/** Calls for pairings in use: a ceiling against a runaway loop, not a quota. */
const MAX_KNOWN_PER_IP = 3000;
/** Pairings one batched call (pending, events, status) may cover. */
const MAX_BATCH = 64;
/**
 * New entries the relay stores on disk for someone (a device subscribing
 * to a vault it was not subscribed to, a server's first heartbeat), per
 * address and hour. A phone pairing a dozen servers is far below it; a
 * script inventing pair ids to fill the state file is not.
 */
const NEW_WINDOW_MS = 60 * 60 * 1000;
const MAX_NEW_PER_HOUR = 60;
/** Pairings with push subscriptions kept at most, like MAX_STATUSES. */
const MAX_SUBSCRIBED = 20000;
/** A server silent this long is forgotten: its status was a month old. */
const STATUS_FORGET_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * Cloudflare's published ranges (cloudflare.com/ips). A connection from
 * one of them is Cloudflare speaking, and CF-Connecting-IP is the client:
 * Cloudflare sets it itself, so a client cannot forge it through them.
 * Without this, every phone and server behind Cloudflare had the same
 * address — a handful of edge IPs — and shared one rate limit.
 */
const CLOUDFLARE_RANGES = [
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
  "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
  "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
  "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
  "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
];

function ipToBigInt(addr: string): { v6: boolean; n: bigint } | null {
  const a = addr.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, "");
  if (/^\d+\.\d+\.\d+\.\d+$/.test(a)) {
    const parts = a.split(".").map(Number);
    if (parts.some((p) => p > 255)) return null;
    return { v6: false, n: parts.reduce((acc, p) => (acc << 8n) | BigInt(p), 0n) };
  }
  if (!a.includes(":")) return null;
  const [head, tail] = a.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  if (tail === undefined && h.length !== 8) return null;
  const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  return { v6: true, n: groups.reduce((acc, g) => (acc << 16n) | BigInt(parseInt(g, 16)), 0n) };
}

export function inRange(addr: string, cidr: string): boolean {
  const [base, bitsText] = cidr.split("/");
  const ip = ipToBigInt(addr);
  const net = ipToBigInt(base!);
  if (!ip || !net || ip.v6 !== net.v6) return false;
  const width = ip.v6 ? 128n : 32n;
  const shift = width - BigInt(bitsText!);
  return ip.n >> shift === net.n >> shift;
}

/** A proxy on this host or this network may speak for the client. */
const fromLocalProxy = (addr: string): boolean =>
  /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|::ffff:(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|f[cd][0-9a-f]{2}:)/i.test(addr);

const fromCloudflare = (addr: string): boolean => CLOUDFLARE_RANGES.some((r) => inRange(addr, r));

/** A literal address, or nothing: header junk never becomes a rate-limit key. */
const literalIp = (s: unknown): string | null => {
  const t = typeof s === "string" ? s.trim() : "";
  return t && ipToBigInt(t) ? t : null;
};

/**
 * Who is calling. A stranger connecting straight to the port is who it
 * is: their forged headers would be a free pass around the limit.
 *
 * Cloudflare's edge names the client in CF-Connecting-IP, which it sets
 * itself. A proxy on this host or network (nginx, Caddy, cloudflared)
 * APPENDS the address it saw to X-Forwarded-For, after whatever the
 * client wrote there: only the right end is the proxy's word, so the
 * header is read from the right, past our own proxies. Reading it from
 * the left let any client pick its address. Behind such a proxy,
 * CF-Connecting-IP counts only when the proxy itself was reached by
 * Cloudflare — someone reaching nginx directly cannot claim it.
 *
 * Not covered: a TCP-level forwarder that rewrites nothing (socat,
 * docker's userland proxy on loopback) makes every client local, headers
 * and all. Put an HTTP proxy in front, or let clients reach the port.
 */
export function clientAddress(peer: string, headers: IncomingMessage["headers"]): string {
  const cf = literalIp(headers["cf-connecting-ip"]);
  if (fromCloudflare(peer)) return cf ?? peer;
  if (!fromLocalProxy(peer)) return peer;

  const xff = headers["x-forwarded-for"];
  const hops = (Array.isArray(xff) ? xff.join(",") : xff ?? "").split(",");
  let hop: string | null = null;
  for (let i = hops.length - 1; i >= 0; i--) {
    const h = literalIp(hops[i]);
    if (!h) break; // not something a proxy wrote: trust nothing further left
    if (!fromLocalProxy(h)) {
      hop = h;
      break;
    }
  }
  if (hop) return fromCloudflare(hop) ? (cf ?? hop) : hop;
  // No outside hop recorded: cloudflared without the header, or a client
  // on this very network.
  return cf ?? peer;
}

/**
 * The bucket a client's calls are counted in. An IPv6 subscriber is
 * handed a whole /64 — 2^64 addresses — so counting per address let one
 * client step around every limit by changing its last bits. IPv6 counts
 * per /64, IPv4 per address.
 */
export function rateKey(addr: string): string {
  const ip = ipToBigInt(addr);
  if (!ip) return addr;
  if (!ip.v6) return addr.replace(/^::ffff:/i, "");
  return `${(ip.n >> 64n).toString(16).padStart(16, "0")}::/64`;
}

/**
 * Where the relay may send a push: the browsers' push services, nothing
 * else. A subscription is just a URL the client hands over, and the relay
 * POSTs to it — without this, anyone could point it at an address inside
 * the relay's own network (an admin port, a cloud metadata service) and
 * have the relay knock on it every time a request arrives.
 * SANDGATE_PUSH_HOSTS adds hosts (comma-separated) for a self-hosted push
 * service.
 */
const PUSH_SERVICES = [
  "fcm.googleapis.com", // Chrome, Android, Edge on Android, Samsung, Opera, Brave
  "android.googleapis.com", // older Chrome
  "push.services.mozilla.com", // Firefox
  "push.apple.com", // Safari, iOS and macOS (web.push.apple.com)
  "notify.windows.com", // Edge on Windows (*.notify.windows.com)
];
export function pushEndpointAllowed(endpoint: unknown, extraHosts: string[] = []): boolean {
  if (typeof endpoint !== "string" || endpoint.length > 2048) return false;
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    return false;
  }
  // https on its default port, no credentials, a name (not an address).
  if (u.protocol !== "https:" || u.port !== "" || u.username || u.password) return false;
  const host = u.hostname.toLowerCase();
  return [...PUSH_SERVICES, ...extraHosts].some((s) => host === s || host.endsWith("." + s));
}
const extraPushHosts = (): string[] =>
  (process.env.SANDGATE_PUSH_HOSTS ?? "")
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);

/** A subscription as a browser hands it over, and nothing bigger. */
const validSubscription = (sub: any): sub is webpush.PushSubscription =>
  !!sub &&
  typeof sub === "object" &&
  typeof sub.keys?.p256dh === "string" &&
  typeof sub.keys?.auth === "string" &&
  sub.keys.p256dh.length > 0 &&
  sub.keys.p256dh.length <= 256 &&
  sub.keys.auth.length > 0 &&
  sub.keys.auth.length <= 256;

/**
 * Headers on everything the relay serves. The approval page must never be
 * framed by another site (a page laid over it could steer a tap onto
 * Approve); nothing is to be sniffed into another type; no address leaks
 * to a link's target.
 */
const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
  "Referrer-Policy": "no-referrer",
};

/**
 * The operator's metrics token, if any. Too short to resist guessing
 * means no metrics at all rather than weak ones.
 */
const MIN_METRICS_TOKEN = 24;
function metricsTokenDigest(raw: string | undefined): Buffer | null {
  // A token read from a file or a compose list often carries a newline.
  const token = raw?.trim();
  if (!token) return null;
  if (token.length < MIN_METRICS_TOKEN) {
    console.error(
      `sandgate relay: SANDGATE_METRICS_TOKEN is shorter than ${MIN_METRICS_TOKEN} characters; /api/metrics stays off. ` +
        "Generate one with: openssl rand -hex 32"
    );
    return null;
  }
  return createHash("sha256").update(token).digest();
}

/**
 * The QR decoder the app loads on demand for "scan a pairing code".
 * Served from our own origin (no CDN, no CSP surprises); absent from the
 * bundle it simply is not offered.
 */
const require = createRequire(import.meta.url);
let JSQR_JS: string | null = null;
try {
  JSQR_JS = readFileSync(require.resolve("jsqr/dist/jsQR.js"), "utf8");
} catch {
  JSQR_JS = null;
}

export async function startRelay(opts: {
  port: number;
  stateDir: string;
  /** Tests only: shorten the pairing-link lifetime. */
  claimTtlMs?: number;
  /** Bearer token for /api/metrics; defaults to SANDGATE_METRICS_TOKEN. Unset: no metrics. */
  metricsToken?: string;
  /** Address to listen on; defaults to SANDGATE_RELAY_HOST, else every interface. */
  host?: string;
}): Promise<{
  close: () => void;
  port: number;
  checkQuiet: (now?: number) => void;
  sweep: (now?: number) => void;
  metricsEnabled: boolean;
}> {
  const claimTtl = opts.claimTtlMs ?? CLAIM_TTL_MS;
  const metricsDigest = metricsTokenDigest(opts.metricsToken ?? process.env.SANDGATE_METRICS_TOKEN);
  /** Constant time, and on digests so the token's length leaks nothing either. */
  const metricsAuthorized = (req: IncomingMessage): boolean => {
    if (!metricsDigest) return false;
    const m = /^Bearer\s+(\S+)\s*$/i.exec(req.headers.authorization ?? "");
    if (!m) return false;
    return timingSafeEqual(createHash("sha256").update(m[1]!).digest(), metricsDigest);
  };
  mkdirSync(opts.stateDir, { recursive: true });
  const statePath = join(opts.stateDir, "relay-state.json");

  let state: {
    vapid: { publicKey: string; privateKey: string };
    /** One device per pairing in older state files, a list since. */
    subscriptions: Record<string, webpush.PushSubscription | webpush.PushSubscription[]>;
    /** Last heartbeat per pairing — kept so a restart does not forget who went quiet. */
    statuses?: Record<string, StoredStatus>;
  };
  if (existsSync(statePath)) {
    state = JSON.parse(readFileSync(statePath, "utf8"));
    state.subscriptions ??= {};
    state.statuses ??= {};
  } else {
    const keys = webpush.generateVAPIDKeys();
    state = { vapid: keys, subscriptions: {}, statuses: {} };
    writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  }
  const persist = () => writeFileSync(statePath, JSON.stringify(state), { mode: 0o600 });
  // Apple's push service rejects invalid VAPID subjects (a .local mailto
  // qualifies); use a real https URL and log delivery failures instead of
  // swallowing them.
  webpush.setVapidDetails("https://sandgate.dev", state.vapid.publicKey, state.vapid.privateKey);

  // Counters for /api/metrics. Nothing per user, nothing that identifies
  // anyone — enough to see the relay breathe, and to see it choke.
  const metrics = {
    requests: 0,
    decisions: 0,
    pushSent: 0,
    pushFailed: 0,
    claimsIssued: 0,
    claimsCollected: 0,
    rateLimited: 0,
  };

  const ipHits = new Map<string, number[]>();
  const knownHits = new Map<string, number[]>();
  const newHits = new Map<string, number[]>();
  const pushHosts = extraPushHosts();
  const clientIp = (req: IncomingMessage): string =>
    rateKey(clientAddress(req.socket.remoteAddress ?? "?", req.headers));
  const hit = (table: Map<string, number[]>, ip: string, max: number, windowMs = IP_WINDOW_MS): boolean => {
    const now = Date.now();
    const hits = (table.get(ip) ?? []).filter((t) => now - t < windowMs);
    if (hits.length >= max) {
      table.set(ip, hits);
      metrics.rateLimited++;
      return true;
    }
    hits.push(now);
    table.set(ip, hits);
    return false;
  };
  const ipLimited = (req: IncomingMessage): boolean => hit(ipHits, clientIp(req), MAX_PER_IP);
  /** One more entry stored on disk for this address (see MAX_NEW_PER_HOUR). */
  const newLimited = (req: IncomingMessage): boolean =>
    hit(newHits, clientIp(req), MAX_NEW_PER_HOUR, NEW_WINDOW_MS);
  /**
   * Is this a pairing someone actually uses? Traffic for those is not what
   * the per-address limit is for (invented pair ids), and counting it
   * there refused real approvals: behind one proxy address, a phone, its
   * gateways and its servers shared 240 calls a minute.
   */
  const known = (pairId: string): boolean => {
    if (state.subscriptions[pairId] || state.statuses?.[pairId]) return true;
    const p = pairings.get(pairId);
    return !!p && (p.requests.size > 0 || p.listeners.size > 0 || !!p.claim || !!p.lastSeen || !!p.claimedAt);
  };

  const pairings = new Map<string, Pairing>();
  const getPairing = (pairId: string): Pairing => {
    let p = pairings.get(pairId);
    if (!p) {
      const stored = state.subscriptions[pairId];
      p = {
        subscriptions: !stored ? [] : Array.isArray(stored) ? [...stored] : [stored],
        requests: new Map(),
        listeners: new Set(),
        recent: [],
        status: state.statuses?.[pairId],
      };
      pairings.set(pairId, p);
    }
    return p;
  };

  /** Push to every device of a pairing. */
  const pushAll = (pairId: string, message: string, ttl: number) => {
    const pairing = getPairing(pairId);
    for (const sub of [...pairing.subscriptions]) {
      // State written by an older relay was never checked.
      if (!pushEndpointAllowed(sub.endpoint, pushHosts)) continue;
      webpush
        // urgency high: someone is waiting on the other end. At the
        // default "normal", Apple delivers at low priority and an
        // iPhone saving battery holds it back or drops it.
        .sendNotification(sub, message, { TTL: ttl, urgency: "high" })
        .then(() => {
          metrics.pushSent++;
        })
        .catch((err: any) => {
          metrics.pushFailed++;
          // 404/410: the push service forgot this device (app removed,
          // notifications switched off). Stop sending into the void.
          if (err?.statusCode === 404 || err?.statusCode === 410) {
            pairing.subscriptions = pairing.subscriptions.filter((s) => s.endpoint !== sub.endpoint);
            if (pairing.subscriptions.length) state.subscriptions[pairId] = pairing.subscriptions;
            else delete state.subscriptions[pairId];
            persist();
          }
          // Phone offline is normal (the PWA polls anyway), but ops must
          // be able to SEE a push service rejecting us.
          console.error(
            `[push] delivery failed (HTTP ${err?.statusCode ?? "?"}): ${String(err?.body ?? err).slice(0, 200)}`
          );
        });
    }
  };

  /**
   * Servers that went quiet: tell their phones once, and again when they
   * come back. Checked against the relay's own clock — the one thing
   * about a heartbeat it can see.
   */
  const checkQuiet = (now = Date.now()) => {
    let changed = false;
    for (const [pairId, st] of Object.entries(state.statuses ?? {})) {
      if (st.offlineAlerted || now - st.receivedAt < quietAfterMs(st.intervalSec)) continue;
      st.offlineAlerted = true;
      changed = true;
      pushAll(pairId, JSON.stringify({ type: "server", pairId, state: "offline", since: st.receivedAt }), 3600);
      notifyListeners(getPairing(pairId), "status", pairId);
    }
    if (changed) persist();
  };

  const notifyListeners = (pairing: Pairing, event: string, pairId?: string) => {
    // A batched stream covers several pairings: say which one changed.
    const data = pairId ? JSON.stringify({ pairId }) : "{}";
    for (const listener of pairing.listeners) {
      listener.write(`event: ${event}\ndata: ${data}\n\n`);
    }
  };

  /** Housekeeping, every minute; `now` is for tests. */
  const sweep = (now = Date.now()) => {
    const cutoff = now - REQUEST_TTL_MS;
    const claimCutoff = now - claimTtl;
    for (const p of pairings.values()) {
      for (const [id, entry] of p.requests) {
        // Two minutes past its expiry: room for a gateway's last long-poll.
        if (entry.ts < cutoff || now > entry.expiresAt + 2 * 60_000) p.requests.delete(id);
      }
      if (p.claim && p.claim.ts < claimCutoff) p.claim = undefined;
    }
    // A pairing nobody uses is just a map entry that an attacker with a
    // random-id generator can multiply. Forget the empty, idle ones.
    const idleCutoff = now - 60 * 60 * 1000;
    for (const [id, p] of pairings) {
      const empty =
        !p.subscriptions.length && !p.status && !p.claim && p.requests.size === 0 && p.listeners.size === 0;
      const idle = !p.lastSeen || p.lastSeen < idleCutoff;
      if (empty && idle && !(p.claimedAt && p.claimedAt > idleCutoff)) pairings.delete(id);
    }
    // A server silent for a month is not news any more, and a status an
    // invented id posted once must not sit on disk forever.
    let forgot = false;
    for (const [id, st] of Object.entries(state.statuses ?? {})) {
      if (now - st.receivedAt < STATUS_FORGET_MS) continue;
      delete state.statuses![id];
      const p = pairings.get(id);
      if (p) p.status = undefined;
      forgot = true;
    }
    if (forgot) persist();
    checkQuiet(now);
    for (const [table, windowMs] of [
      [ipHits, IP_WINDOW_MS],
      [knownHits, IP_WINDOW_MS],
      [newHits, NEW_WINDOW_MS],
    ] as const) {
      const since = now - windowMs;
      for (const [ip, hits] of table) {
        const live = hits.filter((t) => t > since);
        if (live.length) table.set(ip, live);
        else table.delete(ip);
      }
    }
  };
  const gc = setInterval(() => sweep(), Math.min(60_000, claimTtl));
  gc.unref();

  function json(res: ServerResponse, status: number, body: unknown): void {
    const data = JSON.stringify(body);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(data);
  }

  // Read once: the rate limit looks at the body before the route does.
  const bodies = new WeakMap<IncomingMessage, Promise<any>>();
  function readBody(req: IncomingMessage): Promise<any> {
    let pending = bodies.get(req);
    if (!pending) {
      pending = readBodyOnce(req);
      bodies.set(req, pending);
    }
    return pending;
  }
  function readBodyOnce(req: IncomingMessage): Promise<any> {
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
    for (const [name, value] of Object.entries(BASE_HEADERS)) res.setHeader(name, value);
    try {
      // --- static PWA ---
      // no-cache: a fix to the page or the worker must reach the phone on
      // its next load, not whenever a cache in between decides.
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
        return res.end(PWA_HTML);
      }
      if (req.method === "GET" && url.pathname === "/sw.js") {
        res.writeHead(200, { "Content-Type": "application/javascript", "Cache-Control": "no-cache" });
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
      // Apple's associated-domains file. A native app can only use the
      // passkeys already registered for this relay's domain if Apple can
      // read this — which is what lets the iOS app produce assertions the
      // gateway verifies with no second code path. Set SANDGATE_APPLE_APP
      // to "<TEAMID>.<bundle id>"; absent, the endpoint simply is not there.
      if (req.method === "GET" && url.pathname === "/.well-known/apple-app-site-association") {
        const apps = (process.env.SANDGATE_APPLE_APP ?? "")
          .split(",")
          .map((a) => a.trim())
          .filter(Boolean);
        if (!apps.length) return json(res, 404, { error: "no associated app configured" });
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ webcredentials: { apps } }));
      }

      if (req.method === "GET" && url.pathname === "/jsqr.js") {
        if (!JSQR_JS) return json(res, 404, { error: "QR decoder not bundled" });
        res.writeHead(200, {
          "Content-Type": "application/javascript",
          "Cache-Control": "max-age=86400",
        });
        return res.end(JSQR_JS);
      }
      const iconMatch = url.pathname.match(/^\/icon-(180|192|512)\.png$/);
      if (req.method === "GET" && iconMatch) {
        res.writeHead(200, { "Content-Type": "image/png", "Cache-Control": "max-age=86400" });
        return res.end(iconPng(parseInt(iconMatch[1]!, 10)));
      }

      // --- API ---
      if (url.pathname === "/api/metrics") {
        // Operator only. Public counters told an attacker whether their
        // flood was being refused, and anyone how much the relay is used.
        // Not allowed looks exactly like not there; a wrong token costs the
        // caller against the per-address limit, so guessing goes nowhere.
        if (req.method !== "GET" || !metricsAuthorized(req)) {
          ipLimited(req);
          return json(res, 404, { error: "Not found" });
        }
        let activeRequests = 0;
        for (const p of pairings.values()) {
          for (const e of p.requests.values()) if (e.decisions.length < e.needed) activeRequests++;
        }
        const lines = [
          "# TYPE sandgate_relay_requests_total counter",
          `sandgate_relay_requests_total ${metrics.requests}`,
          "# TYPE sandgate_relay_decisions_total counter",
          `sandgate_relay_decisions_total ${metrics.decisions}`,
          "# TYPE sandgate_relay_push_sent_total counter",
          `sandgate_relay_push_sent_total ${metrics.pushSent}`,
          "# TYPE sandgate_relay_push_failed_total counter",
          `sandgate_relay_push_failed_total ${metrics.pushFailed}`,
          "# TYPE sandgate_relay_claims_issued_total counter",
          `sandgate_relay_claims_issued_total ${metrics.claimsIssued}`,
          "# TYPE sandgate_relay_claims_collected_total counter",
          `sandgate_relay_claims_collected_total ${metrics.claimsCollected}`,
          "# TYPE sandgate_relay_rate_limited_total counter",
          `sandgate_relay_rate_limited_total ${metrics.rateLimited}`,
          "# TYPE sandgate_relay_active_requests gauge",
          `sandgate_relay_active_requests ${activeRequests}`,
          "# TYPE sandgate_relay_pairings gauge",
          `sandgate_relay_pairings ${Object.keys(state.subscriptions).length}`,
          "# TYPE sandgate_relay_uptime_seconds gauge",
          `sandgate_relay_uptime_seconds ${Math.round(process.uptime())}`,
          "",
        ];
        // no-store: a CDN in front must never hand these to the next caller.
        res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4", "Cache-Control": "no-store" });
        return res.end(lines.join("\n"));
      }
      if (url.pathname.startsWith("/api/") && url.pathname !== "/api/health") {
        // Which pairings is this call about? Bodies are read once and kept.
        let body: any = null;
        if (req.method === "POST" || req.method === "DELETE") body = await readBody(req);
        const ids = [
          url.searchParams.get("pairId"),
          ...(url.searchParams.get("pairIds") ?? "").split(","),
          body?.pairId,
        ].filter((id): id is string => typeof id === "string" && id.length > 0);
        const allKnown = ids.length > 0 && ids.every(known);
        const limited = allKnown ? hit(knownHits, clientIp(req), MAX_KNOWN_PER_IP) : ipLimited(req);
        if (limited) {
          // retryable: this limit passes in seconds; a client may try again.
          return json(res, 429, { error: "Too many requests from this address. Slow down.", retryable: true });
        }
      }
      if (req.method === "GET" && url.pathname === "/api/health") {
        // Public, so nothing about use: counts live behind /api/metrics.
        // The versions stay: "server" is what the phone compares with each
        // server's heartbeat (see SERVER_VERSION).
        return json(res, 200, { ok: true, version: VERSION, server: SERVER_VERSION });
      }
      if (req.method === "GET" && url.pathname === "/api/vapid") {
        return json(res, 200, { publicKey: state.vapid.publicKey });
      }

      if (req.method === "POST" && url.pathname === "/api/subscribe") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validSubscription(body.subscription)) {
          return json(res, 400, { error: "pairId and subscription required" });
        }
        if (!pushEndpointAllowed(body.subscription.endpoint, pushHosts)) {
          return json(res, 400, { error: "That endpoint is not a browser push service." });
        }
        // Only what a push needs is stored: no extra fields to fill the file with.
        const sub: webpush.PushSubscription = {
          endpoint: body.subscription.endpoint,
          keys: { p256dh: body.subscription.keys.p256dh, auth: body.subscription.keys.auth },
        };
        const isNew = !state.subscriptions[body.pairId];
        if (isNew && Object.keys(state.subscriptions).length >= MAX_SUBSCRIBED) {
          return json(res, 503, { error: "Relay is not accepting new devices right now." });
        }
        if (isNew && newLimited(req)) {
          return json(res, 429, { error: "Too many new vaults from this address. Try again later.", retryable: true });
        }
        const pairing = getPairing(body.pairId);
        // Same endpoint = same device: replace it (its keys may have
        // rotated), and keep it last as the most recently seen.
        pairing.subscriptions = pairing.subscriptions.filter((s) => s.endpoint !== sub.endpoint);
        pairing.subscriptions.push(sub);
        while (pairing.subscriptions.length > MAX_SUBSCRIPTIONS) pairing.subscriptions.shift();
        state.subscriptions[body.pairId] = pairing.subscriptions;
        persist();
        return json(res, 200, { ok: true });
      }

      // A vault removed from a device: that device stops ringing for it.
      // Before this, the relay kept pushing a removed vault's requests.
      if (req.method === "POST" && url.pathname === "/api/unsubscribe") {
        const body = await readBody(req);
        if (!validId(body.pairId) || typeof body.endpoint !== "string") {
          return json(res, 400, { error: "pairId and endpoint required" });
        }
        const pairing = getPairing(body.pairId);
        pairing.subscriptions = pairing.subscriptions.filter((s) => s.endpoint !== body.endpoint);
        if (pairing.subscriptions.length) state.subscriptions[body.pairId] = pairing.subscriptions;
        else delete state.subscriptions[body.pairId];
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
        const claimLive = !!pairing.claim && Date.now() - pairing.claim.ts < claimTtl;
        return json(res, 200, {
          subscribed: pairing.subscriptions.length > 0,
          seen: !!pairing.lastSeen || pairing.subscriptions.length > 0,
          claimed: !!pairing.claimedAt,
          claimPending: claimLive,
        });
      }

      // --- one-time pairing claims: the relay parks a sealed blob it cannot
      // read, hands it out once, and forgets it. See pwacrypto.ts.
      if (req.method === "POST" && url.pathname === "/api/claim") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !body.payload) {
          return json(res, 400, { error: "pairId and payload required" });
        }
        const pairing = getPairing(body.pairId);
        pairing.claim = { payload: body.payload, ts: Date.now() };
        metrics.claimsIssued++;
        return json(res, 200, { ok: true });
      }
      if (req.method === "GET" && url.pathname === "/api/claim") {
        const pairId = url.searchParams.get("pairId") ?? "";
        if (!validId(pairId)) return json(res, 400, { error: "bad pairId" });
        const pairing = getPairing(pairId);
        const live = pairing.claim && Date.now() - pairing.claim.ts < claimTtl;
        if (!live) {
          pairing.claim = undefined;
          return json(res, 404, { error: "no pairing to claim: the link expired or was already used" });
        }
        // Single use: whoever reads it first has it, and nobody after.
        const payload = pairing.claim!.payload;
        pairing.claim = undefined;
        pairing.claimedAt = Date.now();
        metrics.claimsCollected++;
        return json(res, 200, { payload });
      }

      if (req.method === "POST" && url.pathname === "/api/request") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validId(body.requestId) || !body.payload) {
          return json(res, 400, { error: "pairId, requestId, payload required" });
        }
        const pairing = getPairing(body.pairId);
        // A gateway retrying a request whose first answer it never got:
        // the same request, not a new one — keep any decision it has.
        if (pairing.requests.has(body.requestId)) return json(res, 200, { ok: true });

        const now = Date.now();
        pairing.recent = pairing.recent.filter((t) => now - t < RATE_WINDOW_MS);
        let undecided = 0;
        for (const entry of pairing.requests.values()) {
          if (entry.decisions.length < entry.needed && now < entry.expiresAt) undecided++;
        }
        if (pairing.recent.length >= MAX_REQUESTS_PER_WINDOW || undecided >= MAX_UNDECIDED) {
          return json(res, 429, {
            error:
              "Too many approval requests for this pairing. The phone is being flooded; " +
              "answer or let the pending ones expire.",
          });
        }
        pairing.recent.push(now);
        metrics.requests++;

        // `needed` is the one thing about a request the relay is told in
        // the clear: how many answers to collect before hiding it from the
        // phones. It reveals that a quorum exists, not what is being asked.
        const needed = Math.min(10, Math.max(1, parseInt(String(body.needed ?? 1), 10) || 1));
        // Gateways before 0.9.1 send no lifetime: the old 30 minutes.
        const lifeSec = parseInt(String(body.ttlSec ?? ""), 10);
        const expiresAt =
          now + (Number.isFinite(lifeSec) ? Math.min(86400, Math.max(10, lifeSec)) * 1000 : REQUEST_TTL_MS);
        pairing.requests.set(body.requestId, {
          requestId: body.requestId,
          payload: body.payload,
          ts: now,
          decisions: [],
          needed,
          waiters: [],
          expiresAt,
        });
        // The sealed request rides along: the service worker on the phone
        // holds the pairing key and can show the real title — Web Push
        // payloads are end-to-end encrypted (RFC 8291), so Apple and Google
        // see nothing. The relay still reads nothing.
        const message = JSON.stringify({
          type: "approval",
          pairId: body.pairId,
          requestId: body.requestId,
          payload: body.payload,
        });
        const ttl = Math.min(3600, Math.max(30, parseInt(String(body.ttlSec ?? PUSH_TTL_DEFAULT_SEC), 10) || PUSH_TTL_DEFAULT_SEC));
        pushAll(body.pairId, message, ttl);
        notifyListeners(pairing, "request", body.pairId);
        return json(res, 200, { ok: true });
      }

      // --- server heartbeats (sealed; the relay keeps the latest only) ---
      if (url.pathname === "/api/status" && (req.method === "POST" || req.method === "DELETE")) {
        const body = await readBody(req);
        if (!validId(body.pairId)) return json(res, 400, { error: "pairId required" });
        const pairing = getPairing(body.pairId);
        const statuses = (state.statuses ??= {});
        if (req.method === "DELETE") {
          // An uninstall, on purpose: not a server that died.
          pairing.status = undefined;
          delete statuses[body.pairId];
          persist();
          notifyListeners(pairing, "status", body.pairId);
          return json(res, 200, { ok: true });
        }
        if (!body.payload || typeof body.payload !== "object") {
          return json(res, 400, { error: "payload required" });
        }
        const now = Date.now();
        const prev = pairing.status;
        // A server back from silence is always welcome, gap or not.
        if (prev && !prev.offlineAlerted && now - prev.receivedAt < MIN_STATUS_GAP_MS) {
          return json(res, 429, { error: "Heartbeat too frequent." });
        }
        if (!prev && Object.keys(statuses).length >= MAX_STATUSES) {
          return json(res, 503, { error: "Relay is not accepting new servers right now." });
        }
        if (!prev && newLimited(req)) {
          return json(res, 429, { error: "Too many new servers from this address. Try again later." });
        }
        const intervalSec = Math.min(3600, Math.max(60, parseInt(String(body.intervalSec ?? 300), 10) || 300));
        pairing.status = { payload: body.payload, receivedAt: now, intervalSec };
        statuses[body.pairId] = pairing.status;
        persist();
        if (prev?.offlineAlerted) {
          pushAll(body.pairId, JSON.stringify({ type: "server", pairId: body.pairId, state: "online", since: prev.receivedAt }), 3600);
        }
        notifyListeners(pairing, "status", body.pairId);
        return json(res, 200, { ok: true });
      }
      // `?pairIds=a,b,c` reads every vault of a device in one call: one
      // phone with eight vaults used to make eight calls per refresh.
      const batchIds = (): string[] | null => {
        const many = url.searchParams.get("pairIds");
        const list = many !== null ? many.split(",").filter(Boolean) : [url.searchParams.get("pairId") ?? ""];
        if (!list.length || list.length > MAX_BATCH || !list.every(validId)) return null;
        return [...new Set(list)];
      };
      const statusOf = (pairId: string) => {
        const st = getPairing(pairId).status;
        return st
          ? {
              status: { payload: st.payload, receivedAt: st.receivedAt, intervalSec: st.intervalSec },
              quietAfterMs: quietAfterMs(st.intervalSec),
            }
          : { status: null };
      };
      if (req.method === "GET" && url.pathname === "/api/status") {
        const ids = batchIds();
        if (!ids) return json(res, 400, { error: "bad pairId" });
        if (url.searchParams.has("pairIds")) {
          const byPair: Record<string, unknown> = {};
          for (const id of ids) byPair[id] = statusOf(id);
          return json(res, 200, { byPair, now: Date.now() });
        }
        return json(res, 200, { ...statusOf(ids[0]!), now: Date.now() });
      }

      // SSE stream for open PWA pages: instant updates instead of polling.
      if (req.method === "GET" && url.pathname === "/api/events") {
        const ids = batchIds();
        if (!ids) return json(res, 400, { error: "bad pairId" });
        const watched = ids.map(getPairing);
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        res.write("retry: 3000\n\n");
        for (const pairing of watched) {
          // A cap that was declared and never applied: the oldest stream
          // of a pairing makes way (a phone reopening the app leaves dead
          // ones behind until the proxy notices).
          if (pairing.listeners.size >= MAX_LISTENERS) {
            const oldest = pairing.listeners.values().next().value as ServerResponse | undefined;
            if (oldest) {
              pairing.listeners.delete(oldest);
              oldest.end();
            }
          }
          pairing.listeners.add(res);
        }
        // Heartbeat keeps proxies (and our own 90s read timeout) from
        // cutting an idle stream; EventSource ignores comment lines.
        const heartbeat = setInterval(() => res.write(": hb\n\n"), 25_000);
        req.on("close", () => {
          clearInterval(heartbeat);
          for (const pairing of watched) pairing.listeners.delete(res);
        });
        return;
      }

      // A gateway that stopped waiting says so, instead of leaving a card
      // on the phone that answers into the void.
      if (req.method === "POST" && url.pathname === "/api/abandon") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validId(body.requestId)) {
          return json(res, 400, { error: "pairId and requestId required" });
        }
        const pairing = getPairing(body.pairId);
        if (pairing.requests.delete(body.requestId)) {
          notifyListeners(pairing, "decision", body.pairId);
        }
        return json(res, 200, { ok: true });
      }

      if (req.method === "GET" && url.pathname === "/api/pending") {
        const ids = batchIds();
        if (!ids) return json(res, 400, { error: "bad pairId" });
        const now = Date.now();
        // Read-only: a lookup must not create a pairing for every id asked.
        const itemsOf = (pairId: string) =>
          [...(pairings.get(pairId)?.requests.values() ?? [])]
            // Past its gateway's deadline nobody is listening: an answer
            // would go nowhere, so the phones stop being shown it.
            .filter((e) => e.decisions.length < e.needed && now < e.expiresAt)
            .map((e) => ({
              requestId: e.requestId,
              payload: e.payload,
              ts: e.ts,
              decisions: e.decisions.length,
              needed: e.needed,
            }));
        if (url.searchParams.has("pairIds")) {
          const byPair: Record<string, unknown> = {};
          for (const id of ids) byPair[id] = itemsOf(id);
          return json(res, 200, { byPair });
        }
        return json(res, 200, itemsOf(ids[0]!));
      }

      if (req.method === "POST" && url.pathname === "/api/decision") {
        const body = await readBody(req);
        if (!validId(body.pairId) || !validId(body.requestId) || !body.payload) {
          return json(res, 400, { error: "pairId, requestId, payload required" });
        }
        const entry = getPairing(body.pairId).requests.get(body.requestId);
        if (!entry) return json(res, 404, { error: "unknown request" });
        // Enough already? Late taps are acknowledged and dropped: with a
        // quorum of one this is the old "first tap wins".
        if (entry.decisions.length >= entry.needed) return json(res, 200, { ok: true });
        metrics.decisions++;
        entry.decisions.push(body.payload);
        for (const waiter of entry.waiters.splice(0)) waiter(entry.decisions);
        notifyListeners(getPairing(body.pairId), "decision", body.pairId);
        return json(res, 200, { ok: true });
      }

      if (req.method === "GET" && url.pathname === "/api/decision") {
        const pairId = url.searchParams.get("pairId") ?? "";
        const requestId = url.searchParams.get("requestId") ?? "";
        const timeoutSec = Math.min(30, parseInt(url.searchParams.get("timeoutSec") ?? "25", 10) || 25);
        if (!validId(pairId) || !validId(requestId)) return json(res, 400, { error: "bad ids" });
        const entry = getPairing(pairId).requests.get(requestId);
        if (!entry) return json(res, 404, { error: "unknown request" });
        // `after`: how many decisions the caller has already seen. It gets
        // an answer as soon as there are more — the first one right away.
        const after = Math.max(0, parseInt(url.searchParams.get("after") ?? "0", 10) || 0);
        const reply = (decisions: unknown[]) =>
          json(res, 200, { payload: decisions[0], payloads: decisions });
        if (entry.decisions.length > after) return reply(entry.decisions);
        const timer = setTimeout(() => {
          const idx = entry.waiters.indexOf(waiter);
          if (idx >= 0) entry.waiters.splice(idx, 1);
          res.writeHead(204);
          res.end();
        }, timeoutSec * 1000);
        const waiter = (decisions: unknown[]) => {
          clearTimeout(timer);
          reply(decisions);
        };
        entry.waiters.push(waiter);
        return;
      }

      json(res, 404, { error: "not found" });
    } catch (err) {
      json(res, 400, { error: err instanceof Error ? err.message : "bad request" });
    }
  });

  // All interfaces unless told otherwise (a container needs that); behind
  // a proxy on the same host, SANDGATE_RELAY_HOST=127.0.0.1 keeps the
  // plain-HTTP port off the network.
  const host = opts.host ?? (process.env.SANDGATE_RELAY_HOST || undefined);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : opts.port;
  return { close: () => server.close(), port, checkQuiet, sweep, metricsEnabled: metricsDigest !== null };
}
