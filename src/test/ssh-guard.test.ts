import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { newPairing, deriveKey, seal, open, aadForRequest, aadForDecision } from "../pwacrypto.js";
import { startRelay } from "../relay/server.js";
import {
  decideLogin,
  describeLogin,
  loginFromEnv,
  loadGuardConfig,
  type SshGuardConfig,
} from "../ssh-guard.js";

/**
 * These decide whether a person gets a shell. Every branch is covered:
 * approve, deny, silence, relay down, break-glass — under both the
 * default gate and the notification-only mode. Getting fail-open wrong in
 * either direction is either a lockout or an open door.
 */

async function withRelay<T>(fn: (relayUrl: string) => Promise<T>): Promise<T> {
  const relay = await startRelay({
    port: 0,
    stateDir: mkdtempSync(join(tmpdir(), "sandgate-relay-")),
  });
  try {
    return await fn(`http://localhost:${relay.port}`);
  } finally {
    relay.close();
  }
}

/** A phone that answers the pending request the given way. */
async function phoneAnswers(config: SshGuardConfig, approved: boolean): Promise<string> {
  const key = deriveKey(config.secret);
  for (let i = 0; i < 200; i++) {
    const res = await fetch(`${config.relayUrl}/api/pending?pairId=${config.pairId}`);
    const items = (await res.json()) as { requestId: string; payload: any }[];
    if (items.length) {
      const { requestId, payload } = items[0]!;
      const request = open<{ title: string }>(key, payload, aadForRequest(requestId));
      await fetch(`${config.relayUrl}/api/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pairId: config.pairId,
          requestId,
          payload: seal(key, { requestId, approved, ts: Date.now() }, aadForDecision(requestId)),
        }),
      });
      return request.title;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("phone never saw the login request");
}

const login = { user: "root", rhost: "203.0.113.7", pamType: "auth" };

test("the phone sees who is logging in from where", () => {
  const described = describeLogin(login, {
    relayUrl: "https://r",
    pairId: "p",
    secret: "s",
    serverName: "vps-prod",
  });
  assert.equal(described.title, "SSH login: root@vps-prod");
  assert.match(described.body, /203\.0\.113\.7/);
});

test("approving lets the login in; denying blocks it", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const config: SshGuardConfig = { relayUrl, ...pairing, serverName: "vps", timeoutSec: 20 };

    const allowing = decideLogin(login, config);
    await phoneAnswers(config, true);
    assert.deepEqual(await allowing, { allow: true, reason: "approved" });

    const blocking = decideLogin(login, config);
    await phoneAnswers(config, false);
    assert.deepEqual(await blocking, { allow: false, reason: "denied" });
  });
});

test("silence blocks by default, and lets through only in notification mode", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const base: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 1 };

    assert.deepEqual(await decideLogin(login, base), { allow: false, reason: "timeout" });
    assert.deepEqual(await decideLogin(login, { ...base, failOpen: true }), {
      allow: true,
      reason: "fail-open",
    });
  });
});

test("an explicit deny blocks even in notification mode", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const config: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 20, failOpen: true };
    const deciding = decideLogin(login, config);
    await phoneAnswers(config, false);
    // failOpen forgives silence, never a person saying no.
    assert.deepEqual(await deciding, { allow: false, reason: "denied" });
  });
});

test("an unreachable relay blocks by default and is survivable with failOpen", async () => {
  const dead: SshGuardConfig = {
    relayUrl: "http://127.0.0.1:9",
    pairId: "x".repeat(12),
    secret: "y".repeat(12),
    timeoutSec: 5,
  };
  const blocked = await decideLogin(login, dead);
  assert.equal(blocked.allow, false);
  assert.equal(blocked.reason, "error");
  assert.deepEqual(await decideLogin(login, { ...dead, failOpen: true }), {
    allow: true,
    reason: "fail-open",
  });
});

test("break-glass users never wait, and non-auth phases pass through", async () => {
  const config: SshGuardConfig = {
    relayUrl: "http://127.0.0.1:9",
    pairId: "x".repeat(12),
    secret: "y".repeat(12),
    exemptUsers: ["Rescue"],
    timeoutSec: 5,
  };
  // Case-insensitive: a rescue account must work when you are panicking.
  assert.deepEqual(await decideLogin({ ...login, user: "rescue" }, config), {
    allow: true,
    reason: "exempt",
  });
  // pam_exec also fires for account/session; only authentication is gated.
  assert.deepEqual(await decideLogin({ ...login, pamType: "session" }, config), {
    allow: true,
    reason: "not-auth-phase",
  });
});

test("config loading refuses a half-written file rather than guessing", () => {
  const dir = mkdtempSync(join(tmpdir(), "sandgate-guard-"));
  const path = join(dir, "ssh-guard.json");
  writeFileSync(path, JSON.stringify({ relayUrl: "https://r", pairId: "p" }));
  assert.throws(() => loadGuardConfig(path), /missing "secret"/);
  assert.throws(() => loadGuardConfig(join(dir, "nope.json")), /No ssh-guard config/);
});

test("PAM environment maps to a login context", () => {
  const ctx = loginFromEnv({ PAM_USER: "deploy", PAM_RHOST: "10.0.0.9", PAM_TYPE: "auth" } as any);
  assert.deepEqual(ctx, { user: "deploy", rhost: "10.0.0.9", service: undefined, pamType: "auth" });
  const missing = loginFromEnv({} as any);
  assert.equal(missing.user, "unknown");
});
