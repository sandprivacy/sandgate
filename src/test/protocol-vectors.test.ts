import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { deriveKey, open, claimKey, openClaim, aadForRequest, aadForDecision, aadForClaim } from "../pwacrypto.js";

/**
 * The vectors in docs/protocol-vectors.json are what a second
 * implementation — the iOS app, a watch, anything — checks its crypto
 * against. If this file and those numbers ever disagree, every client
 * but ours breaks silently, looking like a network fault. So the
 * vectors are tested like code.
 */
const v = JSON.parse(readFileSync(new URL("../../docs/protocol-vectors.json", import.meta.url), "utf8"));

test("the published vectors decrypt with the published keys", () => {
  const key = deriveKey(v.channel.secret);
  assert.equal(key.toString("hex"), v.channel.derivedKeyHex, "HKDF output must match the vector");

  assert.deepEqual(
    open(key, v.channel.sealedRequest, aadForRequest(v.channel.requestId)),
    v.channel.requestPlaintext
  );
  assert.deepEqual(
    open(key, v.channel.sealedDecision, aadForDecision(v.channel.requestId)),
    v.channel.decisionPlaintext
  );

  assert.equal(claimKey(v.claim.claimSecret).toString("hex"), v.claim.derivedKeyHex);
  assert.deepEqual(openClaim(v.claim.claimSecret, v.claim.pairId, v.claim.sealedClaim), v.claim.claimPlaintext);
});

test("the AADs and the challenge are exactly as documented", () => {
  assert.equal(v.channel.aadRequest, `req:${v.channel.requestId}`);
  assert.equal(v.channel.aadDecision, `dec:${v.channel.requestId}`);
  assert.equal(v.claim.aad, `claim:${v.claim.pairId}`);
  assert.equal(aadForRequest("x"), "req:x");
  assert.equal(aadForDecision("x"), "dec:x");
  assert.equal(aadForClaim("x"), "claim:x");

  assert.equal(v.webauthn.challengeInput, `sandgate-webauthn-v1:${v.channel.requestId}`);
  assert.equal(
    createHash("sha256").update(v.webauthn.challengeInput).digest("base64url"),
    v.webauthn.challengeBase64url
  );
});

test("a wrong AAD fails, which is what makes a client's mistake loud", () => {
  const key = deriveKey(v.channel.secret);
  assert.throws(() => open(key, v.channel.sealedRequest, aadForDecision(v.channel.requestId)), /authentication/);
  assert.throws(() => open(key, v.channel.sealedRequest, aadForRequest("another-request")), /authentication/);
});
