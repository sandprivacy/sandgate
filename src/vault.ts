import {
  scryptSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import type { BiometricCredential } from "./webauthn.js";
import { vaultPath } from "./paths.js";

/**
 * Encrypted-at-rest store for everything sandgate must keep secret:
 * TOTP seeds, the Telegram bot token, the sandmail API key.
 * AES-256-GCM, key derived from the passphrase with scrypt (N=2^15).
 * Secrets are only ever decrypted in memory; tools hand out derived
 * values (6-digit codes), never the seeds themselves.
 */

export interface TotpEntry {
  secret: string; // base32 seed
  label?: string;
  digits?: number;
  period?: number;
}

export interface VaultData {
  totp: Record<string, TotpEntry>; // keyed by domain, e.g. "github.com"
  telegram?: { botToken: string; chatId: string };
  /** A Slack channel, for teams. See slack.ts for what each field is. */
  slack?: {
    botToken: string;
    appToken: string;
    channel: string;
    approvers?: string[];
    quorum?: number;
  };
  sandmail?: { apiKey: string };
  imap?: {
    host: string;
    port?: number;
    user: string;
    pass: string;
    baseEmail?: string;
  };
  pwa?: {
    relayUrl: string;
    pairId: string;
    secret: string;
    /** How many distinct devices must approve (default 1). */
    quorum?: number;
  };
  /**
   * Servers this workstation paired for ssh-guard. Informational: each
   * server holds its own secret; this is the list you revoke from.
   */
  sshGuards?: { serverName: string; pairId: string; createdAt: string }[];
  /** Platform authenticator enrolled on the paired phone (Face ID / Touch ID). */
  biometric?: BiometricCredential;
  /**
   * Whether approvals must carry a verified biometric assertion. Lives
   * here, not in config.json: disabling a protection must cost the
   * passphrase, and AES-GCM makes the flag tamper-evident.
   */
  requireBiometric?: boolean;
}

const SCRYPT_OPTS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

interface VaultFile {
  version: 1;
  kdf: "scrypt";
  salt: string;
  iv: string;
  tag: string;
  data: string;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, SCRYPT_OPTS);
}

export function vaultExists(): boolean {
  return existsSync(vaultPath());
}

export function saveVault(passphrase: string, data: VaultData): void {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const file: VaultFile = {
    version: 1,
    kdf: "scrypt",
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: encrypted.toString("base64"),
  };
  writeFileSync(vaultPath(), JSON.stringify(file), { mode: 0o600 });
}

/** Change the vault passphrase in place: decrypt with the old, re-encrypt with the new. */
export function rekeyVault(oldPassphrase: string, newPassphrase: string): void {
  const data = loadVault(oldPassphrase);
  saveVault(newPassphrase, data);
}

export function loadVault(passphrase: string): VaultData {
  if (!vaultExists()) {
    throw new Error(
      `No vault found at ${vaultPath()}. Run \`sandgate init\` first.`
    );
  }
  const file = JSON.parse(readFileSync(vaultPath(), "utf8")) as VaultFile;
  const key = deriveKey(passphrase, Buffer.from(file.salt, "base64"));
  const decipher = createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(file.iv, "base64")
  );
  decipher.setAuthTag(Buffer.from(file.tag, "base64"));
  try {
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(file.data, "base64")),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString("utf8")) as VaultData;
  } catch {
    throw new Error("Could not unlock the vault: wrong passphrase.");
  }
}
