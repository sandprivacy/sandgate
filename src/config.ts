import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { configPath } from "./paths.js";

/**
 * Non-secret preferences and per-domain policies. Lives in plaintext
 * next to the vault so the user can read and edit it by hand.
 *
 * Policy values:
 *  - "auto":    fulfill the agent's request without asking
 *  - "approve": push an approval request to the human first (default for 2FA)
 *  - "deny":    always refuse
 */

export type Policy = "auto" | "approve" | "deny";

export interface Config {
  policies: {
    totp: Record<string, Policy>;
    totpDefault: Policy;
    verificationDefault: Policy;
    identityDefault: Policy;
  };
  approvalTimeoutSec: number;
}

export const DEFAULT_CONFIG: Config = {
  policies: {
    totp: {},
    totpDefault: "approve",
    verificationDefault: "auto",
    identityDefault: "auto",
  },
  approvalTimeoutSec: 120,
};

export function loadConfig(): Config {
  if (!existsSync(configPath())) return structuredClone(DEFAULT_CONFIG);
  const raw = JSON.parse(readFileSync(configPath(), "utf8"));
  return {
    ...structuredClone(DEFAULT_CONFIG),
    ...raw,
    policies: { ...structuredClone(DEFAULT_CONFIG.policies), ...raw.policies },
  };
}

export function saveConfig(config: Config): void {
  writeFileSync(configPath(), JSON.stringify(config, null, 2) + "\n");
}

export function totpPolicy(config: Config, domain: string): Policy {
  return config.policies.totp[domain] ?? config.policies.totpDefault;
}
