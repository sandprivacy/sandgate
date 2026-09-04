import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import {
  challengeFor,
  verifyEnrollment,
  verifyAssertion,
  type BiometricCredential,
} from "../webauthn.js";

/**
 * A synthetic platform authenticator: same key type (ES256), same signed
 * payload layout (authenticatorData || SHA256(clientDataJSON)), same DER
 * signatures as a real Face ID enclave. It lets us test the verification
 * path — including every rejection — without a physical device.
 */
const ORIGIN = "https://relay.sandgate.dev";
const RP_ID = "relay.sandgate.dev";

function b64u(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function makeAuthenticator() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  const credentialId = b64u(Buffer.from("credential-id-bytes"));

  const clientData = (type: string, challenge: string, origin = ORIGIN) =>
    b64u(Buffer.from(JSON.stringify({ type, challenge, origin }), "utf8"));

  const authData = (opts?: { rpId?: string; flags?: number }) => {
    const data = Buffer.alloc(37);
    createHash("sha256").update(opts?.rpId ?? RP_ID).digest().copy(data, 0);
    data[32] = opts?.flags ?? 0x05; // UP | UV
    return data;
  };

  return {
    credentialId,
    publicKeySpki: b64u(spki),
    enroll: (requestId: string) => ({
      credentialId,
      publicKeySpki: b64u(spki),
      clientDataJSON: clientData("webauthn.create", challengeFor(requestId)),
    }),
    assert: (
      requestId: string,
      opts?: { rpId?: string; flags?: number; origin?: string; tamper?: boolean; type?: string }
    ) => {
      const cd = clientData(opts?.type ?? "webauthn.get", challengeFor(requestId), opts?.origin);
      const ad = authData(opts);
      const signed = Buffer.concat([
        ad,
        createHash("sha256").update(Buffer.from(cd, "base64url")).digest(),
      ]);
      const signature = cryptoSign("sha256", signed, privateKey);
      if (opts?.tamper) signature[signature.length - 1] ^= 0xff;
      return {
        credentialId,
        authenticatorData: b64u(ad),
        clientDataJSON: cd,
        signature: b64u(signature),
      };
    },
  };
}

function enrolled(auth: ReturnType<typeof makeAuthenticator>): BiometricCredential {
  return verifyEnrollment(auth.enroll("enroll-req"), {
    requestId: "enroll-req",
    origin: ORIGIN,
  });
}

test("enrollment yields a usable credential bound to the relay", () => {
  const cred = enrolled(makeAuthenticator());
  assert.equal(cred.rpId, RP_ID);
  assert.equal(cred.origin, ORIGIN);
  assert.ok(cred.publicKeySpki.length > 0);
});

test("enrollment for another request or origin is rejected", () => {
  const auth = makeAuthenticator();
  assert.throws(
    () => verifyEnrollment(auth.enroll("req-a"), { requestId: "req-b", origin: ORIGIN }),
    /Challenge mismatch/
  );
  assert.throws(
    () => verifyEnrollment(auth.enroll("req-a"), { requestId: "req-a", origin: "https://evil.example" }),
    /Unexpected origin/
  );
});

test("a genuine assertion for the right request verifies", () => {
  const auth = makeAuthenticator();
  const cred = enrolled(auth);
  verifyAssertion(auth.assert("req-1"), cred, "req-1"); // must not throw
});

test("an assertion cannot be replayed on another request", () => {
  const auth = makeAuthenticator();
  const cred = enrolled(auth);
  assert.throws(() => verifyAssertion(auth.assert("req-1"), cred, "req-2"), /Challenge mismatch/);
});

test("a tampered signature is rejected", () => {
  const auth = makeAuthenticator();
  const cred = enrolled(auth);
  assert.throws(
    () => verifyAssertion(auth.assert("req-1", { tamper: true }), cred, "req-1"),
    /does not verify/
  );
});

test("an assertion without the user-verification flag is rejected", () => {
  const auth = makeAuthenticator();
  const cred = enrolled(auth);
  assert.throws(
    () => verifyAssertion(auth.assert("req-1", { flags: 0x01 }), cred, "req-1"),
    /User verification flag missing/
  );
});

test("an assertion signed for another relying party is rejected", () => {
  const auth = makeAuthenticator();
  const cred = enrolled(auth);
  assert.throws(
    () => verifyAssertion(auth.assert("req-1", { rpId: "phish.example" }), cred, "req-1"),
    /different relying party/
  );
});

test("another authenticator's assertion is rejected", () => {
  const cred = enrolled(makeAuthenticator());
  const attacker = makeAuthenticator();
  assert.throws(() => verifyAssertion(attacker.assert("req-1"), cred, "req-1"), /does not verify/);
});
