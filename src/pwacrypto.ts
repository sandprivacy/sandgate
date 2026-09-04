import { hkdfSync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

/**
 * End-to-end crypto between the gateway and the paired phone. The 32-byte
 * pairing secret travels once, inside a URL *fragment* (never sent to any
 * server); both sides derive one AES-256-GCM key via HKDF-SHA256. Every
 * message is sealed with the request id and direction in the AAD, so the
 * relay — which stores and forwards blobs — can neither read nor forge
 * nor cross-replay anything. The browser side mirrors this exactly with
 * WebCrypto (HKDF + AES-GCM produce identical bytes).
 */

const HKDF_SALT = Buffer.from("sandgate-pwa-v1", "utf8");
const HKDF_INFO = Buffer.from("approval-channel", "utf8");

export function newPairing(): { pairId: string; secret: string } {
  return {
    pairId: randomBytes(16).toString("base64url"),
    secret: randomBytes(32).toString("base64url"),
  };
}

export function deriveKey(secretB64url: string): Buffer {
  const secret = Buffer.from(secretB64url, "base64url");
  return Buffer.from(hkdfSync("sha256", secret, HKDF_SALT, HKDF_INFO, 32));
}

export interface SealedMessage {
  iv: string; // base64url, 12 bytes
  ct: string; // base64url, ciphertext || 16-byte GCM tag (WebCrypto layout)
}

export function seal(
  key: Buffer,
  payload: unknown,
  aad: string
): SealedMessage {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
  return { iv: iv.toString("base64url"), ct: ct.toString("base64url") };
}

export function open<T>(key: Buffer, sealed: SealedMessage, aad: string): T {
  const raw = Buffer.from(sealed.ct, "base64url");
  if (raw.length < 17) throw new Error("Sealed message too short.");
  const tag = raw.subarray(raw.length - 16);
  const ct = raw.subarray(0, raw.length - 16);
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(sealed.iv, "base64url")
  );
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(tag);
  try {
    const plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(plaintext.toString("utf8")) as T;
  } catch {
    throw new Error("Sealed message failed authentication (wrong key or tampered).");
  }
}

export const aadForRequest = (requestId: string) => `req:${requestId}`;
export const aadForDecision = (requestId: string) => `dec:${requestId}`;

/**
 * One-time pairing claims.
 *
 * A link that carries the channel secret itself is a bearer credential
 * with no expiry: found in a chat log a month later, it still reads and
 * answers everything. So the link carries a *claim* secret instead. The
 * gateway seals the channel secret under it and parks the blob on the
 * relay, which hands it out exactly once and forgets it after ten
 * minutes. The phone opens the blob, keeps the channel secret, and the
 * link is dead from then on — whoever finds it later gets a 404.
 *
 * Someone who finds the link before the owner, inside the window, wins
 * the claim; the owner's attempt then fails visibly, which is the cue to
 * pair again. That is the residual risk, and it is minutes wide instead
 * of forever.
 */

const CLAIM_INFO = Buffer.from("pairing-claim", "utf8");

export function newClaimSecret(): string {
  return randomBytes(32).toString("base64url");
}

export function claimKey(claimSecretB64url: string): Buffer {
  const secret = Buffer.from(claimSecretB64url, "base64url");
  return Buffer.from(hkdfSync("sha256", secret, HKDF_SALT, CLAIM_INFO, 32));
}

export const aadForClaim = (pairId: string) => `claim:${pairId}`;

export interface ClaimPayload {
  secret: string;
  name?: string;
}

export function sealClaim(claimSecret: string, pairId: string, payload: ClaimPayload): SealedMessage {
  return seal(claimKey(claimSecret), payload, aadForClaim(pairId));
}

export function openClaim(claimSecret: string, pairId: string, sealed: SealedMessage): ClaimPayload {
  return open<ClaimPayload>(claimKey(claimSecret), sealed, aadForClaim(pairId));
}

/** The link the phone opens: pair id, claim secret, display name — all in the fragment. */
export function pairingLink(relayUrl: string, pairId: string, claimSecret: string, name?: string): string {
  const base = relayUrl.replace(/\/$/, "");
  const suffix = name ? `&n=${encodeURIComponent(name)}` : "";
  return `${base}/#p=${pairId}&c=${claimSecret}${suffix}`;
}

/** Park the sealed channel secret on the relay for the phone to collect. */
export async function publishClaim(
  relayUrl: string,
  pairId: string,
  sealed: SealedMessage
): Promise<void> {
  const res = await fetch(relayUrl.replace(/\/$/, "") + "/api/claim", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pairId, payload: sealed }),
    signal: AbortSignal.timeout(15_000),
  });
  if (!res.ok) throw new Error(`Relay refused the pairing claim (HTTP ${res.status}).`);
}
