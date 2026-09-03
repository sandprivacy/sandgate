import { randomBytes } from "node:crypto";
import type { Approver, ApprovalRequest, ApprovalResult } from "./telegram.js";
import { deriveKey, seal, open, aadForRequest, aadForDecision } from "./pwacrypto.js";

/**
 * Approval channel backed by the paired phone PWA, through a relay that
 * only ever sees sealed blobs. The decision comes back authenticated by
 * the pairing key (AAD binds it to this exact request id), so a malicious
 * or compromised relay can delay or drop an answer — turning it into a
 * deny — but never forge an approval.
 */

export interface PwaConfig {
  relayUrl: string;
  pairId: string;
  secret: string;
}

interface DecisionPayload {
  requestId: string;
  approved: boolean;
  ts: number;
}

export class PwaApprover implements Approver {
  private key: Buffer;

  constructor(private config: PwaConfig) {
    this.key = deriveKey(config.secret);
  }

  private url(path: string): string {
    return this.config.relayUrl.replace(/\/$/, "") + path;
  }

  async request(req: ApprovalRequest): Promise<ApprovalResult> {
    const requestId = randomBytes(16).toString("base64url");
    const sealed = seal(
      this.key,
      { title: req.title, body: req.body, timeoutSec: req.timeoutSec, ts: Date.now() },
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
      return {
        approved: decision.approved,
        decision: decision.approved ? "approved" : "denied",
      };
    }
    return { approved: false, decision: "timeout" };
  }
}
