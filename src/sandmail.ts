/**
 * Minimal sandmail client (https://api.sandmail.dev) — the managed inbox
 * provider for agent identities. Optional: sandgate works without it, but
 * `create_identity` / `wait_for_verification` need an inbox backend.
 * A generic IMAP fallback is planned so self-hosters aren't locked in.
 */

const BASE_URL = process.env.SANDMAIL_BASE_URL || "https://api.sandmail.dev/v1";

async function call(
  apiKey: string,
  method: string,
  path: string,
  body?: unknown
): Promise<any> {
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers: {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
      "User-Agent": "sandgate/0.1.0",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = (await res.json()) as any;
  if (!res.ok) throw new Error(json.error || `sandmail HTTP ${res.status}`);
  return json;
}

export async function getQuota(
  apiKey: string
): Promise<{ used: number; limit: number; remaining: number }> {
  const res = await call(apiKey, "GET", "/api/rate-limit");
  return res.quota;
}

export async function createInbox(
  apiKey: string,
  opts?: { ttlHours?: number }
): Promise<{ email: string; expiresAt: string | null }> {
  const res = await call(apiKey, "POST", "/api/create", {
    ttl_hours: opts?.ttlHours ?? 24,
    permanent: false,
  });
  return { email: res.email, expiresAt: res.expires_at };
}

export async function waitForOTP(
  apiKey: string,
  email: string,
  timeoutSec: number
): Promise<{
  found: boolean;
  timedOut: boolean;
  code: string | null;
  from?: string;
  subject?: string;
  verificationLinks?: string[];
}> {
  const res = await call(
    apiKey,
    "GET",
    `/api/emails/${encodeURIComponent(email)}/wait-for-otp?timeout=${timeoutSec}`
  );
  return {
    found: res.found,
    timedOut: res.timed_out,
    code: res.code,
    from: res.from,
    subject: res.subject,
    verificationLinks: res.verification_links,
  };
}
