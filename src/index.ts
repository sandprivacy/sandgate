#!/usr/bin/env node
import { stdin, stdout } from "node:process";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { read } from "read";
import { getQuota } from "./sandmail.js";
import { testImapConnection } from "./inbox.js";
import {
  resolvePassphrase,
  passphraseFromLocalStore,
  protectPassphraseDpapi,
  dpapiDecryptCommand,
} from "./passphrase.js";
import { execFileSync } from "node:child_process";
import { auditPath } from "./paths.js";
import { audit } from "./audit.js";
import {
  vaultExists,
  loadVault,
  saveVault,
  rekeyVault,
  type VaultData,
} from "./vault.js";
import { loadConfig, saveConfig, biometricRequired, type Policy } from "./config.js";
import { normalizeSecret, generateCode } from "./totp.js";
import { TelegramApprover, discoverChatId, type Approver } from "./telegram.js";
import { serve } from "./server.js";
import { sandgateDir } from "./paths.js";

const HELP = `sandgate — the human gateway for AI agents

Usage:
  sandgate init                          Create the vault, connect Telegram & sandmail
  sandgate add-totp <domain> <secret>    Store a 2FA seed (base32 or otpauth:// URI)
  sandgate totp [domain] [--copy]        Show your own 2FA code (no domain = list them)
  sandgate policy <domain> <auto|approve|deny>   Set the 2FA policy for a domain
  sandgate connect-telegram <bot-token>  Connect (or fix) the Telegram approval channel
  sandgate connect-slack <bot> <app> <#ch> Approvals in a Slack channel (teams; Node 22+)
  sandgate channel [phone|slack|telegram] Show or choose where requests go
  sandgate relay [port]                  Run the approval relay (serves the phone PWA)
  sandgate pair <relay-url>              Pair your phone via the relay (E2EE, replaces Telegram)
  sandgate add-device                    Add another phone to the current pairing
  sandgate unpair                        Revoke the phone channel entirely
  sandgate pairings                      List what is paired (phone, ssh-guard servers) and its state
  sandgate quorum <n>                    Require n distinct devices to approve
  sandgate ask "<title>" [--input]       The human step from any script (exit 0/1/2)
  sandgate connect-sandmail <api-key>    Connect the sandmail inbox backend
  sandgate connect-imap                  Connect your own IMAP mailbox instead (self-hosted)
  sandgate test-approval                 Send a test approval to your phone
  sandgate rekey                         Change the vault passphrase
  sandgate protect                       Store the passphrase in the OS store (Windows DPAPI)
  sandgate enroll-biometric              Enroll Face ID / Touch ID on the paired phone
  sandgate biometric <on|off>            Require a verified biometric for every approval
  sandgate ssh-guard <cmd>               Blocking SSH approval (pair|test|install|doctor|approve)
  sandgate status                        Show what is configured and active
  sandgate audit [n]                     Show the last n audit entries (default 20)
  sandgate serve                         Run the MCP server (stdio)

The vault passphrase is read from SANDGATE_PASSPHRASE when running non-interactively
(which is how MCP clients launch \`sandgate serve\`).`;

/**
 * Prompts that work in both worlds. Interactive TTY: the `read` package —
 * the same battle-tested prompt npm itself uses for `npm login`, with
 * asterisk masking for secrets. Piped/scripted stdin: the whole input is
 * read upfront and answers are consumed line by line (readline drops lines
 * that arrive between two questions, which silently killed piped `init`).
 */
class Prompter {
  private queue: string[] | null = null;

  private async ensureReady(): Promise<void> {
    if (stdin.isTTY || this.queue) return;
    let data = "";
    for await (const chunk of stdin) data += chunk;
    this.queue = data.split(/\r?\n/);
  }

  async ask(query: string, opts?: { hidden?: boolean }): Promise<string> {
    await this.ensureReady();
    if (this.queue) {
      const value = (this.queue.shift() ?? "").trim();
      stdout.write(query + (opts?.hidden ? "(hidden)" : value) + "\n");
      return value;
    }
    const answer = await read({
      prompt: query,
      silent: opts?.hidden ?? false,
      replace: opts?.hidden ? "*" : undefined,
    });
    return answer.trim();
  }

  close(): void {
    // `read` cleans up after each prompt; nothing to release.
  }
}

async function getPassphrase(prompter: Prompter, confirm = false): Promise<string> {
  const env = process.env.SANDGATE_PASSPHRASE;
  if (env) return env;
  const pass = await prompter.ask("Vault passphrase: ", { hidden: true });
  if (!pass) {
    console.error("A passphrase is required.");
    process.exit(1);
  }
  if (confirm) {
    const again = await prompter.ask("Confirm passphrase: ", { hidden: true });
    if (again !== pass) {
      console.error("Passphrases do not match.");
      process.exit(1);
    }
  }
  return pass;
}

async function cmdInit(): Promise<void> {
  console.log(`sandgate init — files live in ${sandgateDir()}\n`);
  if (vaultExists()) {
    console.error("A vault already exists. Delete ~/.sandgate/vault.enc to start over.");
    process.exit(1);
  }
  const prompter = new Prompter();
  console.log(
    "The vault passphrase is sandgate's master password: it encrypts your 2FA\n" +
      "seeds and API keys (AES-256-GCM). Choose it well — it cannot be recovered.\n"
  );
  const pass = await getPassphrase(prompter, true);
  const data: VaultData = { totp: {} };

  console.log(
    "\nApproval channel (Telegram) — create a bot with @BotFather, then send it any message."
  );
  const botToken = await prompter.ask("Bot token (empty to skip): ");
  if (botToken) {
    const chatId = await discoverChatId(botToken);
    if (chatId) {
      data.telegram = { botToken, chatId };
      console.log(`Connected: chat ${chatId}.`);
    } else {
      console.log(
        "No message found — send your bot a message first, then run: sandgate connect-telegram <token>"
      );
    }
  }

  console.log("\nInbox backend (sandmail) — for create_identity / wait_for_verification.");
  const apiKey = await prompter.ask("sandmail API key (empty to skip): ");
  if (apiKey) data.sandmail = { apiKey };
  prompter.close();

  saveVault(pass, data);
  saveConfig(loadConfig());
  console.log(
    `\nVault created. Next steps:\n` +
      `  sandgate add-totp github.com <secret>\n` +
      `  sandgate test-approval\n` +
      `Then register the MCP server in your agent (see README).`
  );
}

/**
 * Passphrase for read-only convenience commands: the environment, then the
 * local OS store, then a prompt. Anything that CHANGES state still asks.
 */
async function getPassphraseQuick(prompter: Prompter): Promise<string> {
  const fromEnv = resolvePassphrase(process.env);
  if (fromEnv) return fromEnv;
  const stored = passphraseFromLocalStore(join(sandgateDir(), "pass.dpapi"));
  if (stored) return stored;
  return getPassphrase(prompter);
}

function copyToClipboard(value: string): boolean {
  try {
    if (process.platform === "win32") {
      execFileSync("clip", { input: value, windowsHide: true });
    } else if (process.platform === "darwin") {
      execFileSync("pbcopy", { input: value });
    } else {
      execFileSync("xclip", ["-selection", "clipboard"], { input: value });
    }
    return true;
  } catch {
    return false;
  }
}

async function cmdTotp(domain?: string, flag?: string): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphraseQuick(prompter);
  prompter.close();
  const data = loadVault(pass);
  const domains = Object.keys(data.totp).sort();

  if (!domain) {
    if (!domains.length) {
      console.log("No 2FA seeds yet. Add one with: sandgate add-totp <domain> <secret>");
      return;
    }
    console.log("2FA seeds in your vault:" + "\n" + domains.map((d) => "  " + d).join("\n"));
    console.log("\nShow a code with: sandgate totp <domain> [--copy]");
    return;
  }

  const key = domain.toLowerCase().replace(/^www\./, "");
  const entry = data.totp[key];
  if (!entry) {
    console.error(
      `No 2FA seed for "${key}".` +
        (domains.length ? ` Known: ${domains.join(", ")}` : "")
    );
    process.exit(1);
  }
  const { code, secondsRemaining } = generateCode(entry.secret, entry);
  const copied = flag === "--copy" ? copyToClipboard(code) : false;
  console.log(
    `${key}  ${code}  (${secondsRemaining}s left)` +
      (flag === "--copy" ? (copied ? "  — copied to clipboard" : "  — clipboard unavailable") : "")
  );
}

async function cmdAddTotp(domain?: string, secret?: string): Promise<void> {
  if (!domain || !secret) {
    console.error("Usage: sandgate add-totp <domain> <secret>");
    process.exit(1);
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  const key = domain.toLowerCase().replace(/^www\./, "");
  const normalized = normalizeSecret(secret);
  const { code } = generateCode(normalized); // validates the seed
  data.totp[key] = { secret: normalized };
  saveVault(pass, data);
  console.log(`Stored 2FA seed for ${key}. Current code: ${code} (sanity check against your authenticator).`);
}

async function cmdPolicy(domain?: string, policy?: string): Promise<void> {
  const valid: Policy[] = ["auto", "approve", "deny"];
  if (!domain || !valid.includes(policy as Policy)) {
    console.error("Usage: sandgate policy <domain> <auto|approve|deny>");
    process.exit(1);
  }
  const config = loadConfig();
  config.policies.totp[domain.toLowerCase()] = policy as Policy;
  saveConfig(config);
  console.log(`2FA policy for ${domain}: ${policy}`);
}

async function cmdConnectTelegram(botToken?: string): Promise<void> {
  if (!botToken) {
    console.error("Usage: sandgate connect-telegram <bot-token>");
    process.exit(1);
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  const chatId = await discoverChatId(botToken);
  if (!chatId) {
    console.error(
      "No message found for this bot. Open Telegram, send your bot any message, then rerun this command."
    );
    process.exit(1);
  }
  data.telegram = { botToken, chatId };
  saveVault(pass, data);
  console.log(`Telegram connected (chat ${chatId}). Try: sandgate test-approval`);
}

async function cmdConnectSandmail(apiKey?: string): Promise<void> {
  if (!apiKey) {
    console.error("Usage: sandgate connect-sandmail <api-key>");
    process.exit(1);
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  try {
    const quota = await getQuota(apiKey);
    data.sandmail = { apiKey };
    saveVault(pass, data);
    console.log(
      `sandmail connected (quota: ${quota.remaining}/${quota.limit} remaining). ` +
        `Agents can now use create_identity and wait_for_verification.`
    );
  } catch (err) {
    console.error(`Could not validate the sandmail key: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

async function cmdConnectImap(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  const data = loadVault(pass);
  console.log(
    "\nYour own IMAP mailbox as the inbox backend. Agent identities become\n" +
      "plus-addressed aliases (you+sg1a2b@domain) — check your provider supports them.\n" +
      "Use an app password, not your main account password, whenever available.\n"
  );
  const host = await prompter.ask("IMAP host (e.g. imap.fastmail.com): ");
  const portRaw = await prompter.ask("Port [993]: ");
  const user = await prompter.ask("User / email: ");
  const imapPass = await prompter.ask("Password (app password): ", { hidden: true });
  const baseEmail = await prompter.ask(`Alias base address [${user}]: `);
  prompter.close();
  const config = {
    host: host.trim(),
    port: portRaw ? parseInt(portRaw, 10) : 993,
    user: user.trim(),
    pass: imapPass,
    baseEmail: baseEmail.trim() || undefined,
  };
  process.stdout.write("Testing the connection… ");
  try {
    await testImapConnection(config);
    console.log("ok.");
  } catch (err) {
    console.error(`failed: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
  data.imap = config;
  saveVault(pass, data);
  const note = data.sandmail
    ? " Note: sandmail is also configured and takes precedence; remove it from the vault to use IMAP."
    : "";
  console.log(`IMAP connected (${config.user}@${config.host}).${note}`);
}

async function cmdRekey(): Promise<void> {
  const prompter = new Prompter();
  const current = await prompter.ask("Current passphrase: ", { hidden: true });
  const next = await prompter.ask("New passphrase: ", { hidden: true });
  const confirm = await prompter.ask("Confirm new passphrase: ", { hidden: true });
  prompter.close();
  if (!next) {
    console.error("A passphrase is required.");
    process.exit(1);
  }
  if (next !== confirm) {
    console.error("Passphrases do not match.");
    process.exit(1);
  }
  rekeyVault(current, next); // throws "wrong passphrase" if current is bad
  console.log(
    "Vault re-encrypted. Update SANDGATE_PASSPHRASE (or your passphrase command's store) everywhere sandgate serve is launched."
  );
}

async function cmdProtect(): Promise<void> {
  const prompter = new Prompter();
  const pass = await prompter.ask("Vault passphrase: ", { hidden: true });
  prompter.close();
  if (!pass) {
    console.error("A passphrase is required.");
    process.exit(1);
  }
  loadVault(pass); // validate before storing — a typo here would be silent later
  const target = join(sandgateDir(), "pass.dpapi");
  protectPassphraseDpapi(pass, target);
  console.log(
    `Passphrase verified against the vault and stored, DPAPI-encrypted, at:\n  ${target}\n\n` +
      `Point your MCP config at it with:\n  SANDGATE_PASSPHRASE_CMD = ${dpapiDecryptCommand(target)}`
  );
}

async function cmdEnrollBiometric(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  if (!data.pwa) {
    console.error("Biometrics need the PWA channel. Run `sandgate pair <relay-url>` first.");
    process.exit(1);
  }
  const { PwaApprover } = await import("./pwa-approver.js");
  const approver = new PwaApprover(data.pwa);
  console.log("Sent to your phone — tap Enable and confirm with Face ID / Touch ID (2 min)…");
  const credential = await approver.enroll(120);
  if (!credential) {
    console.error("Not enrolled (declined or timed out).");
    process.exit(1);
  }
  data.biometric = credential;
  saveVault(pass, data);
  console.log(
    `Enrolled. sandgate stored only the public key (${credential.rpId}).
` +
      "Turn enforcement on with: sandgate biometric on"
  );
}

async function cmdBiometric(mode?: string): Promise<void> {
  if (mode !== "on" && mode !== "off") {
    console.error("Usage: sandgate biometric <on|off>");
    process.exit(1);
  }
  // Turning a protection off must cost the passphrase, so the flag lives
  // in the vault — not in a plaintext file anyone could edit.
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  if (mode === "on" && !data.biometric) {
    console.error("Nothing enrolled yet. Run `sandgate enroll-biometric` first.");
    process.exit(1);
  }
  data.requireBiometric = mode === "on";
  saveVault(pass, data);
  // Retire the legacy plaintext flag so the two can never disagree.
  const config = loadConfig();
  if (config.requireBiometric) {
    config.requireBiometric = false;
    saveConfig(config);
  }
  console.log(
    mode === "on"
      ? "Biometric approvals required. Every approval must now be signed by the enrolled device."
      : "Biometric requirement off. A tap is enough again."
  );
}

async function cmdStatus(): Promise<void> {
  if (!vaultExists()) {
    console.log("No vault. Run `sandgate init` to get started.");
    return;
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  const config = loadConfig();
  const domains = Object.keys(data.totp);
  const auditCount = existsSync(auditPath())
    ? readFileSync(auditPath(), "utf8").trim().split("\n").filter(Boolean).length
    : 0;

  const requiresBio = biometricRequired(data, config);
  const { describeChannel } = await import("./channels.js");
  const approval = describeChannel(data, loadConfig());
  const inboxLine = data.sandmail
    ? "sandmail" + (data.imap ? " (imap configured but sandmail takes precedence)" : "")
    : data.imap
      ? `imap (${data.imap.user}@${data.imap.host})`
      : "none — run `sandgate connect-sandmail <key>` or `sandgate connect-imap`";

  console.log(`sandgate status — ${sandgateDir()}\n`);
  console.log(`  approval channel   ${approval}`);
  console.log(`  inbox backend      ${inboxLine}`);
  console.log(
    `  2FA seeds          ${domains.length ? domains.join(", ") : "none — add with \`sandgate add-totp <domain> <secret>\`"}`
  );
  console.log(
    `  2FA policy         default ${config.policies.totpDefault}` +
      (Object.keys(config.policies.totp).length
        ? "; " +
          Object.entries(config.policies.totp)
            .map(([d, p]) => `${d}=${p}`)
            .join(", ")
        : "")
  );
  console.log(
    `  biometric          ${
      requiresBio
        ? data.biometric
          ? "required (enrolled)"
          : "REQUIRED BUT NOT ENROLLED — run `sandgate enroll-biometric`"
        : data.biometric
          ? "enrolled, not enforced"
          : "off"
    }`
  );
  console.log(`  audit entries      ${auditCount}`);
}

async function cmdAudit(countArg?: string): Promise<void> {
  const count = Math.max(1, parseInt(countArg ?? "20", 10) || 20);
  if (!existsSync(auditPath())) {
    console.log("No audit entries yet.");
    return;
  }
  const lines = readFileSync(auditPath(), "utf8").trim().split("\n").slice(-count);
  const icons: Record<string, string> = {
    auto: "·",
    approved: "✓",
    denied: "✗",
    timeout: "…",
    error: "!",
  };
  for (const line of lines) {
    try {
      const e = JSON.parse(line);
      const when = e.ts.replace("T", " ").slice(0, 19);
      const what = e.domain ?? e.action ?? e.detail ?? "";
      console.log(
        `${when}  ${icons[e.decision] ?? "·"} ${String(e.decision).padEnd(8)} ${e.tool.padEnd(22)} ${what}`
      );
    } catch {
      // skip malformed lines rather than crash the report
    }
  }
}

async function cmdRelay(portArg?: string): Promise<void> {
  const port = portArg ? parseInt(portArg, 10) : 8787;
  const { startRelay } = await import("./relay/server.js");
  const relay = await startRelay({
    port,
    stateDir: join(sandgateDir(), "relay"),
  });
  console.log(
    `sandgate relay listening on http://localhost:${relay.port}\n` +
      `Behind TLS (required for phone push), pair with: sandgate pair https://your-relay-host`
  );
}

/**
 * Print a one-time pairing link (and its QR) for the channel secret. The
 * link carries a claim, not the secret: the relay hands the sealed secret
 * out once, then it is gone. See pwacrypto.ts.
 */
async function offerPairingLink(
  relayUrl: string,
  pairId: string,
  secret: string,
  name: string
): Promise<void> {
  const { newClaimSecret, sealClaim, publishClaim, pairingLink } = await import("./pwacrypto.js");
  const claim = newClaimSecret();
  await publishClaim(relayUrl, pairId, sealClaim(claim, pairId, { secret, name }));
  const link = pairingLink(relayUrl, pairId, claim, name);
  const qrcode = (await import("qrcode-terminal")).default;
  console.log(
    '\nOpen this link on your phone — in the sandgate app if it is installed ("+ add a vault" → scan or paste):\n'
  );
  console.log(`  ${link}\n`);
  qrcode.generate(link, { small: true });
  console.log("\nThe link works ONCE and expires in 10 minutes. It carries a claim, not the secret.");
}

/** Wait for the phone: claimed first, then (ideally) subscribed to push. */
async function waitForPhone(relayUrl: string, pairId: string, seconds = 120): Promise<void> {
  const deadline = Date.now() + seconds * 1000;
  let claimedAnnounced = false;
  let seenAnnounced = false;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${relayUrl}/api/pair-status?pairId=${encodeURIComponent(pairId)}`);
      const status = (await res.json()) as {
        subscribed: boolean;
        seen?: boolean;
        claimed?: boolean;
        claimPending?: boolean;
      };
      if (status.claimed && !claimedAnnounced) {
        claimedAnnounced = true;
        console.log("Phone collected the pairing — that link is now dead.");
      }
      if (status.subscribed) {
        console.log("Paired, push notifications on. Try: sandgate test-approval");
        return;
      }
      if (status.seen && !seenAnnounced) {
        seenAnnounced = true;
        console.log(
          'Phone connected. For notifications with the app closed, tap "Enable notifications" in the app (on iPhone: install to home screen first)…'
        );
      }
    } catch {
      /* relay hiccup: keep waiting */
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  console.log(
    claimedAnnounced
      ? 'Paired. Notifications are not on yet: open the app and tap "Enable notifications".'
      : "No phone showed up. The link has expired or will shortly; run `sandgate pair` again when you are ready."
  );
}

async function cmdPair(relayUrl?: string): Promise<void> {
  if (!relayUrl) {
    console.error(
      "Usage: sandgate pair <relay-url>\n" +
        "Run `sandgate relay` first (behind TLS for a real phone; http://localhost:8787 works for a desktop browser test)."
    );
    process.exit(1);
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);

  const { newPairing } = await import("./pwacrypto.js");
  const pairing = newPairing();
  const base = relayUrl.replace(/\/$/, "");
  if (data.pwa) {
    console.log(
      "Replacing the existing pairing: every device that had the old one stops receiving anything.\n" +
        "(To add a second device to the CURRENT pairing, use `sandgate add-device` instead.)"
    );
  }
  data.pwa = { relayUrl: base, pairId: pairing.pairId, secret: pairing.secret, quorum: data.pwa?.quorum };
  saveVault(pass, data);

  const { hostname } = await import("node:os");
  await offerPairingLink(base, pairing.pairId, pairing.secret, hostname());
  console.log("\nWaiting for the phone (2 min)…");
  await waitForPhone(base, pairing.pairId);
}

/** A second phone (or a replacement) on the same pairing, without rotating it. */
async function cmdAddDevice(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphraseQuick(prompter);
  prompter.close();
  const data = loadVault(pass);
  if (!data.pwa) {
    console.error("Nothing to add a device to: run `sandgate pair <relay-url>` first.");
    process.exit(1);
  }
  const { hostname } = await import("node:os");
  await offerPairingLink(data.pwa.relayUrl, data.pwa.pairId, data.pwa.secret, hostname());
  console.log("\nWaiting for the new device (2 min)…");
  await waitForPhone(data.pwa.relayUrl, data.pwa.pairId);
}

/** Revoke the phone channel: nothing is ever posted to that pairing again. */
async function cmdUnpair(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  if (!data.pwa) {
    console.log("No phone is paired.");
    return;
  }
  const { pairId } = data.pwa;
  delete data.pwa;
  saveVault(pass, data);
  audit({ tool: "cli", action: "unpair", decision: "auto", detail: pairId });
  console.log(
    `Unpaired (${pairId}). Every device holding that pairing is cut off: the gateway will never\n` +
      "post to it again. Approvals now fall back to Telegram if configured, otherwise refuse.\n" +
      "Pair again with: sandgate pair <relay-url>"
  );
}

/** What is paired, and whether each pairing looks alive on the relay. */
async function cmdPairings(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphraseQuick(prompter);
  prompter.close();
  const data = loadVault(pass);
  const status = async (relayUrl: string, pairId: string): Promise<string> => {
    try {
      const res = await fetch(`${relayUrl}/api/pair-status?pairId=${encodeURIComponent(pairId)}`, {
        signal: AbortSignal.timeout(8000),
      });
      const st = (await res.json()) as {
        subscribed: boolean;
        seen: boolean;
        claimed?: boolean;
        claimPending?: boolean;
      };
      if (st.claimPending) return "link issued, not collected yet";
      if (st.subscribed) return "phone subscribed to push";
      if (st.seen) return "phone seen (no push)";
      return "never seen by the relay";
    } catch {
      return "relay unreachable";
    }
  };
  if (data.pwa) {
    console.log(`phone   ${data.pwa.pairId}  ${data.pwa.relayUrl}`);
    console.log(`        quorum ${data.pwa.quorum ?? 1}, ${await status(data.pwa.relayUrl, data.pwa.pairId)}`);
  } else {
    console.log("phone   not paired");
  }
  const servers = data.sshGuards ?? [];
  if (servers.length) {
    console.log(
      "\nssh-guard servers (each holds its own secret; revoke on the phone or with `ssh-guard uninstall` on the server):"
    );
    for (const srv of servers) {
      const relay = data.pwa?.relayUrl;
      const line = relay ? await status(relay, srv.pairId) : "no relay configured";
      console.log(`  ${srv.serverName.padEnd(18)} ${srv.pairId}  since ${srv.createdAt.slice(0, 10)}  ${line}`);
    }
  }
}

/** How many devices must approve. Costs the passphrase: it changes what every approval means. */
async function cmdQuorum(value?: string): Promise<void> {
  const n = parseInt(value ?? "", 10);
  if (!Number.isInteger(n) || n < 1 || n > 10) {
    console.error("Usage: sandgate quorum <1-10>   (distinct devices that must approve each request)");
    process.exit(1);
  }
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  if (!data.pwa) {
    console.error("Pair a phone first: sandgate pair <relay-url>");
    process.exit(1);
  }
  data.pwa.quorum = n;
  saveVault(pass, data);
  console.log(
    n === 1
      ? "Quorum 1: any paired device approves."
      : `Quorum ${n}: ${n} distinct devices must approve; a single Deny refuses. Add devices with: sandgate add-device`
  );
}

/**
 * The human step from any script: exit 0 approved, 1 refused, 2 no answer.
 * With --input, the typed answer is the only thing on stdout.
 */
async function cmdAsk(args: string[]): Promise<void> {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--input") flags.input = true;
    else if (a === "--body" || a === "--timeout") flags[a.slice(2)] = args[++i] ?? "";
    else positional.push(a);
  }
  const title = positional.join(" ").trim();
  if (!title) {
    console.error(
      'Usage: sandgate ask "<title>" [--body "<details>"] [--timeout <sec>] [--input]\n' +
        "  exit 0 approved / answered, 1 refused, 2 no answer or error\n" +
        "  --input prints the human's typed answer on stdout"
    );
    process.exit(2);
  }
  const prompter = new Prompter();
  const pass = await getPassphraseQuick(prompter);
  prompter.close();
  const vault = loadVault(pass);
  const config = loadConfig();
  const { approverFor } = await import("./channels.js");
  const approver: Approver | null = approverFor(vault, config);
  if (!approver) {
    console.error("No approval channel: run `sandgate pair <relay-url>`, `sandgate connect-slack …` or connect Telegram.");
    process.exit(2);
  }
  const timeoutSec = parseInt(String(flags.timeout ?? ""), 10) || config.approvalTimeoutSec;
  const req = { title, body: typeof flags.body === "string" ? flags.body : undefined, timeoutSec };
  const outcome = (d: string) => (d === "approved" || d === "answered" ? "approved" : d === "denied" ? "denied" : "timeout");
  try {
    if (flags.input) {
      if (!approver.ask) {
        console.error("This approval channel cannot collect typed answers.");
        process.exit(2);
      }
      const result = await approver.ask(req);
      audit({ tool: "cli", action: `ask: ${title}`, decision: outcome(result.decision) });
      if (result.decision === "answered") {
        process.stdout.write(result.answer + "\n");
        process.exit(0);
      }
      console.error(result.decision === "denied" ? "refused" : "no answer");
      process.exit(result.decision === "denied" ? 1 : 2);
    }
    const result = await approver.request(req);
    audit({ tool: "cli", action: `ask: ${title}`, decision: outcome(result.decision) });
    console.error(result.decision);
    process.exit(result.approved ? 0 : result.decision === "denied" ? 1 : 2);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(2);
  }
}

async function cmdTestApproval(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  const config = loadConfig();
  const { approverFor, describeChannel } = await import("./channels.js");
  const approver = approverFor(data, config);
  if (!approver) {
    console.error(`No approval channel. ${describeChannel(data, config)}`);
    process.exit(1);
  }
  console.log(`Sending a test approval — ${describeChannel(data, config)} (60s timeout)…`);
  const result = await approver.request({
    title: "Test from sandgate",
    body: "Tap Approve to confirm your approval channel works.",
    timeoutSec: 60,
  });
  console.log(`Result: ${result.decision}`);
}

/** Slack for teams: a bot token, an app-level token for Socket Mode, a channel. */
async function cmdConnectSlack(args: string[]): Promise<void> {
  const [botToken, appToken, channel, ...rest] = args;
  const approvers = rest.includes("--approvers")
    ? (rest[rest.indexOf("--approvers") + 1] ?? "").split(",").map((u) => u.trim()).filter(Boolean)
    : [];
  if (!botToken?.startsWith("xoxb-") || !appToken?.startsWith("xapp-") || !channel) {
    console.error(
      "Usage: sandgate connect-slack <xoxb-bot-token> <xapp-app-token> <#channel> [--approvers U123,U456]\n\n" +
        "Create a Slack app (api.slack.com/apps) with:\n" +
        "  - Socket Mode ON, and an app-level token with connections:write  (xapp-…)\n" +
        "  - Bot scopes: chat:write, channels:read, groups:read           (xoxb-…)\n" +
        "  - Interactivity ON (no request URL needed with Socket Mode)\n" +
        "  - Install to workspace, then /invite the bot into the channel\n" +
        "--approvers limits who can decide (Slack user ids); without it, anyone in the channel can."
    );
    process.exit(1);
  }
  const { verifySlack } = await import("./slack.js");
  const info = await verifySlack({ botToken, appToken, channel });
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  data.slack = { botToken, appToken, channel: info.channelId, approvers, quorum: data.slack?.quorum };
  saveVault(pass, data);
  const config = loadConfig();
  const { chooseChannel } = await import("./channels.js");
  console.log(
    `Connected to ${info.team} as @${info.bot}, channel ${info.channelId}` +
      (approvers.length ? `, approvers: ${approvers.join(", ")}` : ", anyone in the channel can decide") +
      ".\n" +
      (chooseChannel(data, config) === "slack"
        ? "Slack is now the approval channel. Try: sandgate test-approval"
        : "Your phone stays the approval channel; switch with: sandgate channel slack")
  );
}

/** Which configured channel gets the requests. */
async function cmdChannel(name?: string): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphraseQuick(prompter);
  prompter.close();
  const data = loadVault(pass);
  const config = loadConfig();
  const { availableChannels, describeChannel } = await import("./channels.js");
  if (!name) {
    console.log(`Approval channel: ${describeChannel(data, config)}`);
    return;
  }
  const available = availableChannels(data);
  if (name !== "phone" && name !== "slack" && name !== "telegram") {
    console.error("Usage: sandgate channel <phone|slack|telegram>");
    process.exit(1);
  }
  if (!available.includes(name)) {
    console.error(`${name} is not configured. Available: ${available.join(", ") || "none"}`);
    process.exit(1);
  }
  config.approvalChannel = name;
  saveConfig(config);
  console.log(`Approval channel: ${describeChannel(data, config)}`);
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  switch (command) {
    case "init":
      return cmdInit();
    case "add-totp":
      return cmdAddTotp(args[0], args[1]);
    case "totp":
      return cmdTotp(args[0], args[1]);
    case "policy":
      return cmdPolicy(args[0], args[1]);
    case "connect-telegram":
      return cmdConnectTelegram(args[0]);
    case "connect-sandmail":
      return cmdConnectSandmail(args[0]);
    case "connect-imap":
      return cmdConnectImap();
    case "test-approval":
      return cmdTestApproval();
    case "connect-slack":
      return cmdConnectSlack(args);
    case "channel":
      return cmdChannel(args[0]);
    case "relay":
      return cmdRelay(args[0]);
    case "pair":
      return cmdPair(args[0]);
    case "add-device":
      return cmdAddDevice();
    case "unpair":
      return cmdUnpair();
    case "pairings":
      return cmdPairings();
    case "quorum":
      return cmdQuorum(args[0]);
    case "ask":
      return cmdAsk(args);
    case "rekey":
      return cmdRekey();
    case "protect":
      return cmdProtect();
    case "enroll-biometric":
      return cmdEnrollBiometric();
    case "biometric":
      return cmdBiometric(args[0]);
    case "ssh-guard": {
      const { runSshGuard } = await import("./ssh-guard-cli.js");
      // Read-only as far as the vault goes: `pair` only needs the relay
      // URL, and generates a brand-new pairing of its own. Same quick
      // unlock as `totp`, so a machine with `protect` set up is not
      // prompted for a command that changes nothing.
      return runSshGuard(args[0], args[1], async () => {
        const prompter = new Prompter();
        const pass = await getPassphraseQuick(prompter);
        prompter.close();
        return pass;
      });
    }
    case "status":
      return cmdStatus();
    case "audit":
      return cmdAudit(args[0]);
    case undefined:
    case "serve": {
      let pass: string | undefined;
      try {
        pass = resolvePassphrase(process.env);
      } catch (err) {
        console.error(
          `SANDGATE_PASSPHRASE_CMD failed: ${err instanceof Error ? err.message : err}`
        );
        process.exit(1);
      }
      if (!pass) {
        console.error(
          "No vault passphrase. MCP clients launch sandgate non-interactively; provide either\n" +
            '  SANDGATE_PASSPHRASE      the value itself, or\n' +
            "  SANDGATE_PASSPHRASE_CMD  a command printing it (OS keychain, DPAPI, password manager CLI)\n" +
            "in the MCP server config env."
        );
        process.exit(1);
      }
      return serve(pass);
    }
    case "help":
    case "--help":
    case "-h":
      console.log(HELP);
      return;
    default:
      console.error(`Unknown command: ${command}\n\n${HELP}`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
