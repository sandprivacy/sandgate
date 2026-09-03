import * as OTPAuth from "otpauth";

/** Generate the current code for a stored seed. The seed never leaves this module's callers' memory. */
export function generateCode(
  secret: string,
  opts?: { digits?: number; period?: number }
): { code: string; secondsRemaining: number } {
  const totp = new OTPAuth.TOTP({
    secret: OTPAuth.Secret.fromBase32(normalizeSecret(secret)),
    digits: opts?.digits ?? 6,
    period: opts?.period ?? 30,
    algorithm: "SHA1",
  });
  const period = opts?.period ?? 30;
  const now = Math.floor(Date.now() / 1000);
  return {
    code: totp.generate(),
    secondsRemaining: period - (now % period),
  };
}

/** Accept secrets pasted with spaces/dashes/lowercase, and full otpauth:// URIs. */
export function normalizeSecret(input: string): string {
  const trimmed = input.trim();
  if (trimmed.startsWith("otpauth://")) {
    const url = new URL(trimmed);
    const secret = url.searchParams.get("secret");
    if (!secret) throw new Error("otpauth:// URI has no secret parameter.");
    return secret.toUpperCase();
  }
  return trimmed.replace(/[\s-]/g, "").toUpperCase();
}
