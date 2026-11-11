import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync as mkTemp } from "node:fs";

// Decisions are cached per user+host to survive sshd's retries; give
// each run its own store so tests never inherit one another's answers.
process.env.SANDGATE_SSH_CACHE_DIR = mkTemp(join(tmpdir(), "sandgate-guard-cache-"));

const { newPairing, deriveKey, seal, open, aadForRequest, aadForDecision } = await import("../pwacrypto.js");
const { startRelay } = await import("../relay/server.js");
const { decideLogin, describeLogin, loginFromEnv, loadGuardConfig, verifiedKey } = await import(
  "../ssh-guard.js"
);
type SshGuardConfig = import("../ssh-guard.js").SshGuardConfig;

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
/** A fresh source per scenario: the cache is keyed by user+host. */
let hostCounter = 0;
const freshLogin = () => ({ ...login, rhost: `203.0.113.${++hostCounter + 100}` });

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

    const allowing = decideLogin(freshLogin(), config);
    await phoneAnswers(config, true);
    assert.deepEqual(await allowing, { allow: true, reason: "approved" });

    const blocking = decideLogin(freshLogin(), config);
    await phoneAnswers(config, false);
    assert.deepEqual(await blocking, { allow: false, reason: "denied" });
  });
});

test("silence blocks by default, and lets through only in notification mode", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const base: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 1 };

    assert.deepEqual(await decideLogin(freshLogin(), base), { allow: false, reason: "timeout" });
    assert.deepEqual(await decideLogin(freshLogin(), { ...base, failOpen: true }), {
      allow: true,
      reason: "fail-open",
    });
  });
});

test("an explicit deny blocks even in notification mode", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const config: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 20, failOpen: true };
    const deciding = decideLogin(freshLogin(), config);
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
  const blocked = await decideLogin(freshLogin(), dead);
  assert.equal(blocked.allow, false);
  assert.equal(blocked.reason, "error");
  assert.deepEqual(await decideLogin(freshLogin(), { ...dead, failOpen: true }), {
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
  assert.deepEqual(ctx, { user: "deploy", rhost: "10.0.0.9", service: undefined, pamType: "auth", authInfo: undefined });
  const missing = loginFromEnv({} as any);
  assert.equal(missing.user, "unknown");
});

test("the phone is told which key sshd accepted, by its authorized_keys name", () => {
  // A real ed25519 public key blob; fingerprint as `ssh-keygen -lf` prints it.
  const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
  const fp = "SHA256:" + createHash("sha256").update(Buffer.from(blob, "base64")).digest("base64").replace(/=+$/, "");
  const login = loginFromEnv({
    PAM_USER: "root",
    PAM_RHOST: "203.0.113.7",
    PAM_TYPE: "auth",
    SSH_AUTH_INFO_0: `publickey ssh-ed25519 ${blob}\n`,
  } as any);
  const { title, body } = describeLogin(
    login,
    { relayUrl: "x", pairId: "p", secret: "s", serverName: "us4" },
    {
      serverAddress: "51.0.0.4",
      authorizedKeys: () => `ssh-rsa AAAAB3other old@box\nssh-ed25519 ${blob} baltha@MSI\n`,
    }
  );
  assert.equal(title, "SSH login: root@us4");
  assert.equal(
    body,
    `From 203.0.113.7\nKey: baltha@MSI · ED25519 ${fp}\nServer: us4 · 51.0.0.4\nApprove to let this session in.`
  );
  // A key nobody named still shows its fingerprint; no key info, no line.
  assert.match(
    describeLogin(login, { relayUrl: "x", pairId: "p", secret: "s" }, { authorizedKeys: () => "" }).body,
    /^Key: ED25519 SHA256:/m
  );
  assert.doesNotMatch(describeLogin({ user: "a", rhost: "b" }, { relayUrl: "x", pairId: "p", secret: "s" }).body, /Key:/);
  assert.equal(verifiedKey("password\n"), null);
});

test("a refusal survives the retries sshd makes for one login", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    // Notification mode: silence lets logins through. A refusal must not.
    const config: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 3, failOpen: true };
    const attempt = { user: "root", rhost: "203.0.113.250", pamType: "auth" };

    const first = decideLogin(attempt, config);
    await phoneAnswers(config, false);
    assert.deepEqual(await first, { allow: false, reason: "denied" });

    // sshd immediately retries the same login. On a real server this
    // second call timed out and fail-open let the refused user in.
    assert.deepEqual(await decideLogin(attempt, config), {
      allow: false,
      reason: "recent-denial",
    });
  });
});

test("an approval is reused, so one login means one buzz", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const config: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 3 };
    const attempt = { user: "root", rhost: "203.0.113.251", pamType: "auth" };

    const first = decideLogin(attempt, config);
    await phoneAnswers(config, true);
    assert.deepEqual(await first, { allow: true, reason: "approved" });

    // The retry must not ask the human a second time for the same login.
    assert.deepEqual(await decideLogin(attempt, config), {
      allow: true,
      reason: "recent-approval",
    });
  });
});

test("concurrent hooks for one login ask the human exactly once", async () => {
  await withRelay(async (relayUrl) => {
    const pairing = newPairing();
    const config: SshGuardConfig = { relayUrl, ...pairing, timeoutSec: 20 };
    const attempt = { user: "root", rhost: "203.0.113.252", pamType: "auth" };

    // A real login fired SEVEN of these at once: the client retries
    // authentication and every retry starts a fresh PAM conversation.
    const hooks = Array.from({ length: 6 }, () => decideLogin(attempt, config));

    // Count what actually reached the phone while they all run.
    let seen = new Set<string>();
    const watch = (async () => {
      for (let i = 0; i < 200; i++) {
        const items = (await (
          await fetch(`${relayUrl}/api/pending?pairId=${pairing.pairId}`)
        ).json()) as { requestId: string }[];
        items.forEach((it) => seen.add(it.requestId));
        if (seen.size) break;
        await new Promise((r) => setTimeout(r, 25));
      }
    })();
    await watch;
    await phoneAnswers(config, true);

    const outcomes = await Promise.all(hooks);
    assert.equal(seen.size, 1, `the phone was asked ${seen.size} times for one login`);
    assert.ok(
      outcomes.every((o) => o.allow),
      "every hook of an approved login must let it through"
    );
    assert.equal(
      outcomes.filter((o) => o.reason === "approved").length,
      1,
      "exactly one hook should have done the asking"
    );
  });
});
