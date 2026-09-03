import { homedir } from "node:os";
import { join } from "node:path";
import { mkdirSync } from "node:fs";

export function sandgateDir(): string {
  const dir = process.env.SANDGATE_HOME || join(homedir(), ".sandgate");
  mkdirSync(dir, { recursive: true });
  return dir;
}

export const vaultPath = () => join(sandgateDir(), "vault.enc");
export const configPath = () => join(sandgateDir(), "config.json");
export const auditPath = () => join(sandgateDir(), "audit.jsonl");
