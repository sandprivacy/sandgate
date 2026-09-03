#!/usr/bin/env node
import { stdin, stdout } from "node:process";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { read } from "read";
import { getQuota } from "./sandmail.js";
import { testImapConnection } from "./inbox.js";
import { auditPath } from "./paths.js";
import {
  vaultExists,
  loadVault,
  saveVault,
  type VaultData,
} from "./vault.js";
import { loadConfig, saveConfig, type Policy } from "./config.js";
import { normalizeSecret, generateCode } from "./totp.js";
import { TelegramApprover, discoverChatId } from "./telegram.js";
import { serve } from "./server.js";
import { sandgateDir } from "./paths.js";

const HELP = `sandgate — the human gateway for AI agents

Usage:
  sandgate init                          Create the vault, connect Telegram & sandmail
  sandgate add-totp <domain> <secret>    Store a 2FA seed (base32 or otpauth:// URI)
  sandgate policy <domain> <auto|approve|deny>   Set the 2FA policy for a domain
  sandgate connect-telegram <bot-token>  Connect (or fix) the Telegram approval channel
  sandgate relay [port]                  Run the approval relay (serves the phone PWA)
  sandgate pair <relay-url>              Pair your phone via the relay (E2EE, replaces Telegram)
  sandgate connect-sandmail <api-key>    Connect the sandmail inbox backend
  sandgate connect-imap                  Connect your own IMAP mailbox instead (self-hosted)
  sandgate test-approval                 Send a test approval to your phone
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
  while (Date.now() < deadline) {
    try {
      const res = await fetch(
        `${base}/api/pair-status?pairId=${encodeURIComponent(pairing.pairId)}`
      );
      const status = (await res.json()) as { subscribed: boolean };
      if (status.subscribed) {
        console.log("Paired! The PWA now takes over approvals (Telegram becomes the fallback). Try: sandgate test-approval");
        return;
      }
    } catch {
      // relay not reachable yet; keep trying
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  console.log(
    "No subscription yet — the pairing is saved anyway. Open the link on the phone, then check with: sandgate test-approval"
  );
}

async function cmdTestApproval(): Promise<void> {
  const prompter = new Prompter();
  const pass = await getPassphrase(prompter);
  prompter.close();
  const data = loadVault(pass);
  let approver;
  if (data.pwa) {
    const { PwaApprover } = await import("./pwa-approver.js");
    approver = new PwaApprover(data.pwa);
    console.log("Sending test approval to the paired PWA (60s timeout)…");
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
    case "status":
      return cmdStatus();
    case "audit":
      return cmdAudit(args[0]);
    case undefined:
    case "serve": {
      const pass = process.env.SANDGATE_PASSPHRASE;
      if (!pass) {
        console.error(
          "SANDGATE_PASSPHRASE is not set. MCP clients launch sandgate non-interactively;\n" +
            'add it to the server config, e.g. {"env": {"SANDGATE_PASSPHRASE": "..."}}'
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
