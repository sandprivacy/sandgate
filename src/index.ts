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
import {
  vaultExists,
  loadVault,
  saveVault,
  rekeyVault,
  type VaultData,
} from "./vault.js";
import { loadConfig, saveConfig, biometricRequired, type Policy } from "./config.js";
import { normalizeSecret, generateCode } from "./totp.js";
import { TelegramApprover, discoverChatId } from "./telegram.js";
import { serve } from "./server.js";
import { sandgateDir } from "./paths.js";

const HELP = `sandgate — the human gateway for AI agents

Usage:
  sandgate init                          Create the vault, connect Telegram & sandmail
  sandgate add-totp <domain> <secret>    Store a 2FA seed (base32 or otpauth:// URI)
  sandgate totp [domain] [--copy]        Show your own 2FA code (no domain = list them)
  sandgate policy <domain> <auto|approve|deny>   Set the 2FA policy for a domain
  sandgate connect-telegram <bot-token>  Connect (or fix) the Telegram approval channel
  sandgate relay [port]                  Run the approval relay (serves the phone PWA)
  sandgate pair <relay-url>              Pair your phone via the relay (E2EE, replaces Telegram)
  sandgate connect-sandmail <api-key>    Connect the sandmail inbox backend
  sandgate connect-imap                  Connect your own IMAP mailbox instead (self-hosted)
  sandgate test-approval                 Send a test approval to your phone
  sandgate rekey                         Change the vault passphrase
  sandgate protect                       Store the passphrase in the OS store (Windows DPAPI)
  sandgate enroll-biometric              Enroll Face ID / Touch ID on the paired phone
  sandgate biometric <on|off>            Require a verified biometric for every approval
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
  const approval = data.pwa
    ? `PWA via ${data.pwa.relayUrl} (Telegram ${data.telegram ? "fallback" : "not set"})`
    : data.telegram
      ? "Telegram"
      : "none — run `sandgate pair <relay-url>` or `sandgate connect-telegram <token>`";
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
  const pairLink = `${base}/#p=${pairing.pairId}&s=${pairing.secret}`;

  data.pwa = { relayUrl: base, pairId: pairing.pairId, secret: pairing.secret };
  saveVault(pass, data);

  const qrcode = (await import("qrcode-terminal")).default;
  console.log("\nOpen this link on your phone (the secret is in the URL fragment — it never reaches the relay):\n");
  console.log(`  ${pairLink}\n`);
  qrcode.generate(pairLink, { small: true });
  console.log("\nWaiting for the phone to subscribe (2 min)…");

  const deadline = Date.now() + 120_000;
  let seenAnnounced = false;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(
        `${base}/api/pair-status?pairId=${encodeURIComponent(pairing.pairId)}`
      );
      const status = (await res.json()) as { subscribed: boolean; seen?: boolean };
      if (status.subscribed) {
        console.log(
          "Paired, push notifications on. The PWA now takes over approvals (Telegram becomes the fallback). Try: sandgate test-approval"
        );
        return;
      }
      if (status.seen && !seenAnnounced) {
        seenAnnounced = true;
        console.log(
          'Phone connected. For notifications with the app closed, tap "Enable notifications" in the app (on iPhone: install to home screen first)…'
        );
      }
    } catch {
      // relay not reachable yet; keep trying
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  console.log(
    seenAnnounced
      ? "Paired (no push yet — the app works while open; enable notifications in it when you can)."
      : "No phone yet — the pairing is saved anyway. Open the link on the phone, then check with: sandgate test-approval"
  );
}

async function cmdTestApproval(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  let approver;
  if (data.pwa) {
    const { pwaApproverFrom } = await import("./pwa-approver.js");
    const config = loadConfig();
    approver = pwaApproverFrom(data, config)!;
    console.log(
      biometricRequired(data, config)
        ? "Sending test approval to the paired PWA — Face ID required (60s timeout)…"
        : "Sending test approval to the paired PWA (60s timeout)…"
    );
  } else if (data.telegram) {
    approver = new TelegramApprover(data.telegram.botToken, data.telegram.chatId);
    console.log("Sending test approval to Telegram (60s timeout)…");
  } else {
    console.error("No approval channel. Run `sandgate connect-telegram <bot-token>` or `sandgate pair <relay-url>`.");
    process.exit(1);
  }
  const result = await approver.request({
    title: "Test from sandgate",
    body: "Tap Approve to confirm your approval channel works.",
    timeoutSec: 60,
  });
  console.log(`Result: ${result.decision}`);
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
    case "relay":
      return cmdRelay(args[0]);
    case "pair":
      return cmdPair(args[0]);
    case "rekey":
      return cmdRekey();
    case "protect":
      return cmdProtect();
    case "enroll-biometric":
      return cmdEnrollBiometric();
    case "biometric":
      return cmdBiometric(args[0]);
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
