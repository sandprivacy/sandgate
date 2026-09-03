/**
 * Local OTP/verification extraction for the IMAP backend (sandmail does
 * this server-side; self-hosters get the same result locally).
 */

export interface Extraction {
  code: string | null;
  links: string[];
}

const CODE_CONTEXT =
  /(?:code|otp|pin|password|passcode|vérification|verification|confirm|2fa|authentif)/i;

const LINK_HINT = /(?:verify|confirm|activate|validate|auth|token=|code=)/i;

export function extractVerification(subject: string, text: string): Extraction {
  const links: string[] = [];
  for (const match of text.matchAll(/https?:\/\/[^\s<>"')\]]+/g)) {
    if (LINK_HINT.test(match[0]) && !links.includes(match[0])) links.push(match[0]);
  }

  // Prefer codes near context words; fall back to a lone 4-8 digit group in
  // the subject (the "Your code is 774412" pattern).
  const haystacks = [subject, text];
  for (const haystack of haystacks) {
    for (const line of haystack.split(/\r?\n/)) {
      if (!CODE_CONTEXT.test(line)) continue;
      const m = line.match(/\b(\d{4,8})\b/);
      if (m) return { code: m[1], links };
    }
  }
  const subjectOnly = subject.match(/\b(\d{4,8})\b/);
  if (subjectOnly) return { code: subjectOnly[1], links };

  // Standalone code on its own line (many emails put the code alone).
  const alone = text.match(/^\s*(\d{4,8})\s*$/m);
  return { code: alone ? alone[1] : null, links };
}
