import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.SANDGATE_SSH_CACHE_DIR = mkdtempSync(join(tmpdir(), "sandgate-cache-"));
const { remember, recall, APPROVAL_TTL_SEC, DENIAL_TTL_SEC } = await import(
  "../ssh-decision-cache.js"
);

/**
 * One SSH login fires the hook several times, because sshd retries
 * authentication. On a real server a DENIED login logged in anyway: the
 * refusal covered one attempt, and the next one went through on
 * fail-open. These lock that behaviour down.
 */

test("a decision is reused for the retries of the same login", () => {
  remember("root", "203.0.113.7", true);
  assert.deepEqual(recall("root", "203.0.113.7")?.allow, true);
  // Different user, or different source: a different decision entirely.
  assert.equal(recall("deploy", "203.0.113.7"), null);
  assert.equal(recall("root", "198.51.100.4"), null);
});

test("a refusal outlives an approval, so retries cannot slip past it", () => {
  const now = Date.now();
  remember("root", "203.0.113.9", true);
  remember("root", "203.0.113.10", false);

  // Just after the approval window: the next login must ask again.
  assert.equal(recall("root", "203.0.113.9", now + (APPROVAL_TTL_SEC + 1) * 1000), null);
  // The refusal is still standing at that point — this is the bug that bit.
  assert.equal(
    recall("root", "203.0.113.10", now + (APPROVAL_TTL_SEC + 1) * 1000)?.allow,
    false
  );
  assert.ok(DENIAL_TTL_SEC > APPROVAL_TTL_SEC, "refusals must outlive approvals");
});

test("both decisions expire, so the guard keeps asking", () => {
  const now = Date.now();
  remember("root", "203.0.113.11", false);
  assert.equal(recall("root", "203.0.113.11", now + (DENIAL_TTL_SEC + 1) * 1000), null);
});

test("an unknown login is never assumed", () => {
  assert.equal(recall("nobody", "nowhere"), null);
});
