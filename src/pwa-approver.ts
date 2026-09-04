import { randomBytes } from "node:crypto";
import type { Approver, ApprovalRequest, ApprovalResult, AskResult } from "./telegram.js";
import type { VaultData } from "./vault.js";
import { biometricRequired, type Config } from "./config.js";
import { deriveKey, seal, open, aadForRequest, aadForDecision } from "./pwacrypto.js";
import {
  verifyAssertion,
  verifyEnrollment,
  type BiometricCredential,
  type AssertionEvidence,
  type EnrollmentEvidence,
} from "./webauthn.js";

/**
 * Approval channel backed by the paired phone PWA, through a relay that
 * only ever sees sealed blobs. Two request kinds share the same tunnel:
 * "approval" (tap yes/no) and "input" (the human types an answer — SMS
 * codes, security questions). Decisions come back authenticated by the
 * pairing key (AAD binds them to this exact request id), so a malicious
 * or compromised relay can delay or drop an answer — turning it into a
 * deny — but never forge one.
 */

export interface PwaConfig {
  relayUrl: string;
  pairId: string;
  secret: string;
  /** When set, decisions must carry an assertion from this credential. */
  biometric?: BiometricCredential;
  requireBiometric?: boolean;
}

interface DecisionPayload {
  requestId: string;
  approved: boolean;
  answer?: string;
  ts: number;
  assertion?: AssertionEvidence;
  enrollment?: EnrollmentEvidence;
}

export class PwaApprover implements Approver {
  private key: Buffer;

  constructor(private config: PwaConfig) {
    this.key = deriveKey(config.secret);
  }

  private url(path: string): string {
    return this.config.relayUrl.replace(/\/$/, "") + path;
  }

  /** Post a sealed request and long-poll its sealed decision (or null on timeout). */
  private async roundTrip(
    kind: "approval" | "input" | "enroll",
    req: ApprovalRequest
  ): Promise<{ requestId: string; decision: DecisionPayload } | null> {
    const requestId = randomBytes(16).toString("base64url");
    // Biometric enforcement travels inside the sealed request: the relay
    // cannot see it, and the phone cannot be told to skip it by anyone else.
    const needsBiometric = kind !== "enroll" && !!this.config.requireBiometric;
    const sealed = seal(
      this.key,
      {
        kind,
        title: req.title,
        body: req.body,
        timeoutSec: req.timeoutSec,
        ts: Date.now(),
        requireBiometric: needsBiometric,
        credentialId: needsBiometric ? this.config.biometric?.credentialId : undefined,
      },
      aadForRequest(requestId)
    );

    const post = await fetch(this.url("/api/request"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pairId: this.config.pairId, requestId, payload: sealed }),
    });
    if (!post.ok) throw new Error(`Relay refused the request (HTTP ${post.status}).`);

    const deadline = Date.now() + req.timeoutSec * 1000;
    while (Date.now() < deadline) {
      const pollSec = Math.min(25, Math.max(1, Math.ceil((deadline - Date.now()) / 1000)));
      const res = await fetch(
        this.url(
          `/api/decision?pairId=${encodeURIComponent(this.config.pairId)}` +
            `&requestId=${encodeURIComponent(requestId)}&timeoutSec=${pollSec}`
        )
      );
      if (res.status === 204) continue;
      if (!res.ok) throw new Error(`Relay error while waiting (HTTP ${res.status}).`);
      const { payload } = (await res.json()) as { payload: any };
      const decision = open<DecisionPayload>(this.key, payload, aadForDecision(requestId));
      if (decision.requestId !== requestId) continue; // belt and suspenders; AAD already binds it
      if (needsBiometric && decision.approved) {
        // Fail closed: an approval without a verifiable assertion is not
        // an approval. verifyAssertion throws on anything suspicious.
        if (!this.config.biometric) {
          throw new Error(
            "Biometric approval is required but no credential is enrolled. Run `sandgate enroll-biometric`."
          );
        }
        if (!decision.assertion) {
          throw new Error("Approval arrived without the required biometric assertion.");
        }
        verifyAssertion(decision.assertion, this.config.biometric, requestId);
      }
      return { requestId, decision };
    }
    return null;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    const result = await this.roundTrip("approval", req);
    if (!result) return { approved: false, decision: "timeout" };
    return {
      approved: result.decision.approved,
      decision: result.decision.approved ? "approved" : "denied",
    };
  }

  async ask(req: ApprovalRequest): Promise<AskResult> {
    const result = await this.roundTrip("input", req);
    if (!result) return { answer: null, decision: "timeout" };
    const { decision } = result;
    if (!decision.approved || typeof decision.answer !== "string") {
      return { answer: null, decision: "denied" };
    }
    return { answer: decision.answer, decision: "answered" };
  }

  /**
   * Enroll the phone's platform authenticator. Returns the credential to
   * store in the vault, or null if the human declined or let it expire.
   */
  async enroll(timeoutSec: number): Promise<BiometricCredential | null> {
    const result = await this.roundTrip("enroll", {
      title: "Enable Face ID / Touch ID approvals",
      body: "Your device will sign approvals from now on. sandgate stores only the public key.",
      timeoutSec,
    });
    if (!result) return null;
    const { requestId, decision } = result;
    if (!decision.approved || !decision.enrollment) return null;
    return verifyEnrollment(decision.enrollment, {
      requestId,
      origin: new URL(this.config.relayUrl).origin,
    });
  }
}

/**
 * Build the PWA approver from vault + config. Everything that talks to the
 * phone goes through here: when `serve` and the CLI each assembled their
 * own config, the CLI silently lost biometric enforcement.
 */
export function pwaApproverFrom(vault: VaultData, config: Config): PwaApprover | null {
  if (!vault.pwa) return null;
  return new PwaApprover({
    ...vault.pwa,
    biometric: vault.biometric,
    requireBiometric: biometricRequired(vault, config),
  });
}
