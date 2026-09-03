import { ImapFlow } from "imapflow";
import { simpleParser } from "mailparser";
import { randomBytes } from "node:crypto";
import * as sandmail from "./sandmail.js";
import { extractVerification } from "./extract.js";
import type { VaultData } from "./vault.js";

/**
 * Inbox backends behind one interface. sandmail: managed disposable inboxes,
 * one API call. IMAP: self-hosted — identities are plus-addressed aliases of
 * your own mailbox (user+sg1a2b@domain), and verification emails are read
 * straight off your IMAP server with local code/link extraction.
 */

export interface VerificationResult {
  found: boolean;
  timedOut: boolean;
  code: string | null;
  from?: string;
  subject?: string;
  links: string[];
}

export interface InboxBackend {
  readonly kind: "sandmail" | "imap";
  createIdentity(ttlHours?: number): Promise<{ email: string; expiresAt: string | null }>;
  waitForVerification(email: string, timeoutSec: number): Promise<VerificationResult>;
}

export function backendFromVault(vault: VaultData): InboxBackend | null {
  if (vault.sandmail) return new SandmailBackend(vault.sandmail.apiKey);
  if (vault.imap) return new ImapBackend(vault.imap);
  return null;
}

class SandmailBackend implements InboxBackend {
  readonly kind = "sandmail" as const;
  constructor(private apiKey: string) {}

  createIdentity(ttlHours?: number) {
    return sandmail.createInbox(this.apiKey, { ttlHours });
  }

  async waitForVerification(email: string, timeoutSec: number): Promise<VerificationResult> {
    const res = await sandmail.waitForOTP(this.apiKey, email, timeoutSec);
    return {
      found: res.found,
      timedOut: res.timedOut,
      code: res.code,
      from: res.from,
      subject: res.subject,
      links: res.verificationLinks ?? [],
    };
  }
}

export interface ImapConfig {
  host: string;
  port?: number;
  user: string;
  pass: string;
  /** Address aliases are derived from, e.g. "me@fastmail.com" -> me+sg1a2b@fastmail.com */
  baseEmail?: string;
}

class ImapBackend implements InboxBackend {
  readonly kind = "imap" as const;
  constructor(private config: ImapConfig) {}

  async createIdentity(): Promise<{ email: string; expiresAt: string | null }> {
    const base = this.config.baseEmail ?? this.config.user;
    const [local, domain] = base.split("@");
    if (!domain) throw new Error(`Cannot derive an alias from "${base}".`);
    const tag = randomBytes(3).toString("hex");
    return { email: `${local}+sg${tag}@${domain}`, expiresAt: null };
  }

  async waitForVerification(email: string, timeoutSec: number): Promise<VerificationResult> {
    const client = new ImapFlow({
      host: this.config.host,
      port: this.config.port ?? 993,
      secure: (this.config.port ?? 993) === 993,
      auth: { user: this.config.user, pass: this.config.pass },
      logger: false,
    });
    const deadline = Date.now() + timeoutSec * 1000;
    const since = new Date(Date.now() - 5 * 60 * 1000);
    await client.connect();
    try {
      const lock = await client.getMailboxLock("INBOX");
      try {
        while (Date.now() < deadline) {
          const uids = await client.search({ to: email, since }, { uid: true });
          if (uids && uids.length) {
            const uid = uids[uids.length - 1];
            const dl = await client.download(String(uid), undefined, { uid: true });
            const parsed = await simpleParser(dl.content);
            const subject = parsed.subject ?? "";
            const text = (parsed.text ?? "") + "\n" + (parsed.html || "");
            const { code, links } = extractVerification(subject, text);
            return {
              found: true,
              timedOut: false,
              code,
              from: parsed.from?.text,
              subject,
              links,
            };
          }
          await new Promise((r) => setTimeout(r, 5000));
        }
        return { found: false, timedOut: true, code: null, links: [] };
      } finally {
        lock.release();
      }
    } finally {
      await client.logout().catch(() => {});
    }
  }
}

/** Used by `sandgate connect-imap` to validate credentials before saving. */
export async function testImapConnection(config: ImapConfig): Promise<void> {
  const client = new ImapFlow({
    host: config.host,
    port: config.port ?? 993,
    secure: (config.port ?? 993) === 993,
    auth: { user: config.user, pass: config.pass },
    logger: false,
  });
  await client.connect();
  await client.logout().catch(() => {});
}
