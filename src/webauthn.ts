import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

/**
 * WebAuthn verification for sensitive approvals.
 *
 * The phone enrolls a platform authenticator (Face ID / Touch ID) once;
 * its public key lives in the vault. Afterwards, a protected approval is
 * only accepted if the sealed decision carries an assertion signed by
 * that authenticator over a challenge derived from the request id — so
 * the gateway gets cryptographic proof that a human passed biometric
 * verification on the enrolled device, not just a tap the page claims
 * happened.
 *
 * No CBOR, no dependencies: enrollment ships the public key as SPKI via
 * the browser's AuthenticatorAttestationResponse.getPublicKey(), and
 * WebAuthn ECDSA signatures are DER-encoded, which node verifies natively.
 */

export interface BiometricCredential {
  credentialId: string; // base64url
  publicKeySpki: string; // base64url DER (SPKI)
  rpId: string;
  origin: string;
  enrolledAt: string;
}

export interface EnrollmentEvidence {
  credentialId: string;
  publicKeySpki: string;
  clientDataJSON: string; // base64url
}

export interface AssertionEvidence {
  credentialId: string;
  authenticatorData: string; // base64url
  clientDataJSON: string; // base64url
  signature: string; // base64url
}

/** Deterministic per-request challenge: both sides derive it from the request id. */
export function challengeFor(requestId: string): string {
  return createHash("sha256")
    .update("sandgate-webauthn-v1:" + requestId)
    .digest("base64url");
}

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
}

function parseClientData(b64url: string): ClientData {
  const json = Buffer.from(b64url, "base64url").toString("utf8");
  const data = JSON.parse(json) as ClientData;
  if (typeof data.type !== "string" || typeof data.challenge !== "string") {
    throw new Error("Malformed clientDataJSON.");
  }
  return data;
}

function checkClientData(
  evidence: { clientDataJSON: string },
  expected: { type: string; challenge: string; origin: string }
): void {
  const data = parseClientData(evidence.clientDataJSON);
  if (data.type !== expected.type) {
    throw new Error(`Wrong ceremony type: ${data.type}.`);
  }
  if (data.challenge !== expected.challenge) {
    throw new Error("Challenge mismatch (assertion is not for this request).");
  }
  if (data.origin !== expected.origin) {
    throw new Error(`Unexpected origin: ${data.origin}.`);
  }
}

/** Validate an enrollment and produce the record to store in the vault. */
export function verifyEnrollment(
  evidence: EnrollmentEvidence,
  expected: { requestId: string; origin: string }
): BiometricCredential {
  checkClientData(evidence, {
    type: "webauthn.create",
    challenge: challengeFor(expected.requestId),
    origin: expected.origin,
  });
  const spki = Buffer.from(evidence.publicKeySpki, "base64url");
  createPublicKey({ key: spki, format: "der", type: "spki" }); // throws if unusable
  return {
    credentialId: evidence.credentialId,
    publicKeySpki: evidence.publicKeySpki,
    rpId: new URL(expected.origin).hostname,
    origin: expected.origin,
    enrolledAt: new Date().toISOString(),
  };
}

/**
 * Verify an assertion for a given request. Throws on any failure — callers
 * treat a throw as a denial, never as an approval.
 */
export function verifyAssertion(
  evidence: AssertionEvidence,
  credential: BiometricCredential,
  requestId: string
): void {
  if (evidence.credentialId !== credential.credentialId) {
    throw new Error("Assertion from an unknown credential.");
  }
  checkClientData(evidence, {
    type: "webauthn.get",
    challenge: challengeFor(requestId),
    origin: credential.origin,
  });

  const authData = Buffer.from(evidence.authenticatorData, "base64url");
  if (authData.length < 37) throw new Error("Malformed authenticatorData.");

  const rpIdHash = createHash("sha256").update(credential.rpId).digest();
  if (!authData.subarray(0, 32).equals(rpIdHash)) {
    throw new Error("Assertion signed for a different relying party.");
  }

  const flags = authData[32]!;
  if ((flags & 0x01) === 0) throw new Error("User presence flag missing.");
  if ((flags & 0x04) === 0) {
    throw new Error("User verification flag missing (biometric/PIN not performed).");
  }

  const clientDataHash = createHash("sha256")
    .update(Buffer.from(evidence.clientDataJSON, "base64url"))
    .digest();
  const signedData = Buffer.concat([authData, clientDataHash]);
  const publicKey = createPublicKey({
    key: Buffer.from(credential.publicKeySpki, "base64url"),
    format: "der",
    type: "spki",
  });
  const ok = cryptoVerify(
    "sha256",
    signedData,
    publicKey,
    Buffer.from(evidence.signature, "base64url")
  );
  if (!ok) throw new Error("Assertion signature does not verify.");
}
