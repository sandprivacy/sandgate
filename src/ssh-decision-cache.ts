import { readFileSync, writeFileSync, mkdirSync, existsSync, openSync, closeSync, rmSync, statSync, lstatSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";

/**
 * A short memory of what you just decided about a login.
 *
 * One SSH login is not one PAM call: sshd retries authentication, so the
 * hook fires several times for what a person experiences as a single
 * attempt. Without this, you get buzzed twice per login — and worse, a
 * Deny only refused one of the attempts while the next one sailed
 * through on the fail-open path. Observed on a real server: a denied
 * login logged in anyway.
 *
 * So a decision is remembered for a few seconds, keyed by who is logging
 * in from where. An approval saves you the second prompt; a refusal
 * sticks, which is the whole point of refusing.
 */

/**
 * Where decisions live. NOT a shared /tmp: a decision file that any local
 * user could write is a forged approval, and a directory anyone could
 * pre-create is one they own. Root gets /run (tmpfs, root-only, cleared
 * on boot); anyone else gets a directory of their own under tmp.
 */
function defaultDir(): string {
  if (process.platform !== "win32" && typeof process.getuid === "function" && process.getuid() === 0) {
    return existsSync("/run") ? "/run/sandgate-ssh" : "/var/lib/sandgate/ssh-cache";
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : "user";
  return join(tmpdir(), `sandgate-ssh-${uid}`);
}
const DIR = process.env.SANDGATE_SSH_CACHE_DIR || defaultDir();

/**
 * Refuse to use a directory we do not fully own. If any of this fails the
 * cache is simply not used: every retry asks the phone again, which is
 * annoying and safe — the opposite of trusting a stranger's files.
 */
export function directoryIsOurs(dir: string): boolean {
  try {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(dir);
    if (!st.isDirectory() || st.isSymbolicLink()) return false;
    if (process.platform === "win32") return true; // ACLs, not mode bits
    if (typeof process.getuid === "function" && st.uid !== process.getuid()) return false;
    if ((st.mode & 0o022) !== 0) return false; // group/other writable: anyone can plant a decision
    return true;
  } catch {
    return false;
  }
}
let dirOk: boolean | null = null;
function usable(): boolean {
  if (dirOk === null) dirOk = directoryIsOurs(DIR);
  return dirOk;
}
/** Long enough to cover sshd's retries, short enough to gate the next login. */
export const APPROVAL_TTL_SEC = 20;
/** A refusal outlives an approval: it must survive every retry of the attempt. */
export const DENIAL_TTL_SEC = 60;

export interface CachedDecision {
  allow: boolean;
  ts: number;
}

/**
 * How long one asker holds the floor. Observed on a real server: a single
 * SSH login fired SEVEN hooks at once, because the client retries
 * authentication and each retry starts a fresh PAM conversation. Without
 * a claim they all buzz the phone separately for the same login.
 */
export const CLAIM_TTL_SEC = 90;

function pathFor(user: string, rhost: string): string {
  const key = createHash("sha256").update(`${user}@${rhost}`).digest("hex").slice(0, 32);
  return join(DIR, `${key}.json`);
}

export function remember(user: string, rhost: string, allow: boolean): void {
  if (!usable()) return;
  try {
    writeFileSync(pathFor(user, rhost), JSON.stringify({ allow, ts: Date.now() }), {
      mode: 0o600,
    });
  } catch {
    // A cache that cannot be written is a missing optimisation, never a
    // reason to refuse someone.
  }
}

export function recall(user: string, rhost: string, now = Date.now()): CachedDecision | null {
  if (!usable()) return null;
  try {
    const file = pathFor(user, rhost);
    if (!existsSync(file)) return null;
    const entry = JSON.parse(readFileSync(file, "utf8")) as CachedDecision;
    if (typeof entry.allow !== "boolean" || typeof entry.ts !== "number") return null;
    const ttl = (entry.allow ? APPROVAL_TTL_SEC : DENIAL_TTL_SEC) * 1000;
    return now - entry.ts < ttl ? entry : null;
  } catch {
    return null;
  }
}

function claimPath(user: string, rhost: string): string {
  return pathFor(user, rhost).replace(/\.json$/, ".claim");
}

/**
 * Be the one who asks. Returns false when another hook, for the same
 * login, is already waiting on an answer — that one's decision will serve
 * for both.
 */
export function claim(user: string, rhost: string): boolean {
  if (!usable()) return true; // no shared state: everyone asks, nobody is refused
  try {
    const file = claimPath(user, rhost);
    if (existsSync(file)) {
      const age = Date.now() - statSync(file).mtimeMs;
      if (age < CLAIM_TTL_SEC * 1000) return false;
      rmSync(file, { force: true }); // stale: whoever held it is gone
    }
    // "wx" fails if another process created it first — the whole point.
    closeSync(openSync(file, "wx"));
    return true;
  } catch {
    // Cannot claim? Ask anyway: an extra prompt beats a silent refusal.
    return true;
  }
}

export function release(user: string, rhost: string): void {
  try {
    rmSync(claimPath(user, rhost), { force: true });
  } catch {
    /* the TTL will clear it */
  }
}

/** Wait for whoever is asking to come back with an answer. */
export async function awaitDecision(
  user: string,
  rhost: string,
  timeoutMs: number
): Promise<CachedDecision | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const decided = recall(user, rhost);
    if (decided) return decided;
    // The asker vanished (killed, crashed): stop waiting on a ghost.
    if (!existsSync(claimPath(user, rhost))) return null;
    await new Promise((r) => setTimeout(r, 300));
  }
  return null;
}
