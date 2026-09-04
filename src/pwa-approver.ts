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
  /** Distinct devices that must approve (default 1). One Deny refuses. */
  quorum?: number;
}

interface DecisionPayload {
  requestId: string;
  approved: boolean;
  answer?: string;
  ts: number;
  assertion?: AssertionEvidence;
  enrollment?: EnrollmentEvidence;
  /** Random per-device id the app attaches, so a quorum can tell phones apart. */
  deviceId?: string;
}

export class PwaApprover implements Approver {
  private key: Buffer;

  constructor(private config: PwaConfig) {
    this.key = deriveKey(config.secret);
  }

  private url(path: string): string {
    return this.config.relayUrl.replace(/\/$/, "") + path;
  }

  /**
   * Never wait forever on the network. A relay that accepts a connection
   * and then goes silent must not freeze the caller — an SSH login held
   * open by a hung fetch is a locked door.
   */
  private fetchWithTimeout(url: string, init: RequestInit, seconds: number) {
    return fetch(url, { ...init, signal: AbortSignal.timeout(seconds * 1000) });
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
    // Enrolment and typed answers come from one device; only approvals
    // can require several.
    const quorum = kind === "approval" ? Math.max(1, this.config.quorum ?? 1) : 1;
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
        quorum,
      },
      aadForRequest(requestId)
    );

    const post = await this.fetchWithTimeout(
      this.url("/api/request"),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pairId: this.config.pairId, requestId, payload: sealed, needed: quorum }),
      },
      15
    );
    if (!post.ok) throw new Error(`Relay refused the request (HTTP ${post.status}).`);

    const close = () =>
      this.fetchWithTimeout(
        this.url("/api/abandon"),
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pairId: this.config.pairId, requestId }),
        },
        10
      ).catch(() => {});

    const deadline = Date.now() + req.timeoutSec * 1000;
    let ignoredDecisions = 0;
    let seen = 0;
    // Devices that approved so far. A decision without a device id — an
    // app from before quorums — counts as one anonymous device, never more:
    // one phone must not be able to make up a quorum by tapping twice.
    const approvedBy = new Set<string>();
    let approvedDecision: DecisionPayload | null = null;
    while (Date.now() < deadline) {
      const pollSec = Math.min(25, Math.max(1, Math.ceil((deadline - Date.now()) / 1000)));
      const res = await this.fetchWithTimeout(
        this.url(
          `/api/decision?pairId=${encodeURIComponent(this.config.pairId)}` +
            `&requestId=${encodeURIComponent(requestId)}&timeoutSec=${pollSec}&after=${seen}`
        ),
        {},
        pollSec + 10
      );
      if (res.status === 204) continue;
      if (!res.ok) throw new Error(`Relay error while waiting (HTTP ${res.status}).`);
      const body = (await res.json()) as { payload: any; payloads?: any[] };
      const payloads: any[] = body.payloads ?? [body.payload];
      const fresh = payloads.slice(seen);
      seen = payloads.length;
      for (const payload of fresh) {
        let decision: DecisionPayload;
        try {
          decision = open<DecisionPayload>(this.key, payload, aadForDecision(requestId));
        } catch {
          // Not sealed with our key: forged, or another party's noise. It is
          // not an answer, so it must not end the wait — the real one may
          // still arrive, and silence remains a refusal.
          ignoredDecisions++;
          continue;
        }
        if (decision.requestId !== requestId) continue; // belt and suspenders; AAD already binds it
        if (!decision.approved) {
          // One refusal is final, however many others said yes.
          await close();
          return { requestId, decision };
        }
        if (needsBiometric) {
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
        approvedBy.add(decision.deviceId || "anonymous-device");
        approvedDecision = decision;
        if (approvedBy.size >= quorum) {
          if (quorum > 1) await close(); // the other phones can stop showing it
          return { requestId, decision };
        }
      }
      if (fresh.length === 0) await new Promise((r) => setTimeout(r, 300));
    }
    void approvedDecision;
    // Out of time: withdraw the request so it stops sitting on the phone.
    await close();
    if (ignoredDecisions > 0) {
      // Worth surfacing: someone was answering for you, and failing.
      console.error(
        `sandgate: ignored ${ignoredDecisions} unreadable decision(s) for this request.`
      );
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
    quorum: vault.pwa.quorum,
  });
}
