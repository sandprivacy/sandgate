/**
 * Which relay `sandgate pair` uses when none is given.
 *
 * The hosted relay is blind by construction — it forwards sealed blobs it
 * cannot read and holds no key — so offering it by default costs little
 * in trust and removes the single biggest obstacle to trying sandgate:
 * standing up a TLS-terminated server before the first approval. It is
 * documented at https://sandgate.dev/relay: what it sees, what it cannot,
 * no SLA, and how to run your own. SANDGATE_RELAY overrides it for good.
 */
export const HOSTED_RELAY = "https://relay.sandgate.dev";

export function defaultRelayUrl(env: NodeJS.ProcessEnv = process.env): {
  url: string;
  source: "argument" | "env" | "hosted";
} {
  const fromEnv = env.SANDGATE_RELAY?.trim();
  if (fromEnv) return { url: fromEnv.replace(/\/$/, ""), source: "env" };
  return { url: HOSTED_RELAY, source: "hosted" };
}

export function resolveRelayUrl(
  argument: string | undefined,
  env: NodeJS.ProcessEnv = process.env
): { url: string; source: "argument" | "env" | "hosted" } {
  if (argument?.trim()) return { url: argument.trim().replace(/\/$/, ""), source: "argument" };
  return defaultRelayUrl(env);
}

/** What to tell someone the first time the hosted relay is picked for them. */
export const HOSTED_RELAY_NOTICE = [
  `Using the hosted relay at ${HOSTED_RELAY}.`,
  "It forwards sealed blobs it cannot read and holds no key; it does see your IP",
  "address and push endpoint. No SLA. Details and self-hosting: https://sandgate.dev/relay",
  "Prefer your own? `sandgate pair <relay-url>` or SANDGATE_RELAY=<url>.",
].join("\n");
