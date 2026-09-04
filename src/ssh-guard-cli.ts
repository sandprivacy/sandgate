import { existsSync, readFileSync } from "node:fs";
import { loadVault } from "./vault.js";
import { audit } from "./audit.js";
import {
  configPathFromEnv,
  loadGuardConfig,
  loginFromEnv,
  describeLogin,
  decideLogin,
  installInstructions,
} from "./ssh-guard.js";

/**
 * The `sandgate ssh-guard` commands. Kept out of index.ts because the
 * PAM-facing path deserves to be read on its own: it decides whether a
 * login happens, and it must never leave that decision to an accident.
 */

/** Supplied by the CLI so this module never touches terminal plumbing. */
type AskPassphrase = () => Promise<string>;

export async function runSshGuard(
  sub: string | undefined,
  arg: string | undefined,
  askPassphrase: AskPassphrase
): Promise<void> {
  const configPath = configPathFromEnv();

  switch (sub) {
    case "approve":
      return approve(configPath);
    case "pair":
      return pair(arg, askPassphrase, configPath);
    case "test":
      return test(configPath);
    case "install":
      console.log(installInstructions(configPath, binaryInvocation()));
      return;
    case "doctor":
      return doctor(configPath);
    default:
      console.error(
        [
          "Usage: sandgate ssh-guard <pair [name]|install|doctor|test|approve>",
          "  pair     on your workstation: give this server a pairing of its own",
          "  install  on the server: print the PAM and sshd lines to add",
          "  doctor   on the server: check the wiring and your escape hatch",
          "  test     on the server: send a fake login to your phone",
          "  approve  called by PAM, not by you",
        ].join("\n")
      );
      process.exit(1);
  }
}

function binaryInvocation(): string {
  const entry = process.argv[1];
  return entry && entry.endsWith(".js") ? `${process.execPath} ${entry}` : "sandgate";
}

/**
 * The PAM hook. No prompts, no stdout: PAM reads the exit code and
 * nothing else. Every path ends in an explicit exit, and a broken config
 * refuses rather than opening the door.
 */
async function approve(configPath: string): Promise<void> {
  try {
    const config = loadGuardConfig(configPath);
    const login = loginFromEnv(process.env);
    const outcome = await decideLogin(login, config);
    audit({
      tool: "ssh_guard",
      action: `${login.user}@${config.serverName ?? "server"} from ${login.rhost}`,
      decision: outcome.allow
        ? outcome.reason === "approved"
          ? "approved"
          : "auto"
        : outcome.reason === "denied"
          ? "denied"
          : outcome.reason === "timeout"
            ? "timeout"
            : "error",
      detail: outcome.reason,
    });
    process.exit(outcome.allow ? 0 : 1);
  } catch (err) {
    console.error(`sandgate ssh-guard: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

async function pair(
  name: string | undefined,
  askPassphrase: AskPassphrase,
  configPath: string
): Promise<void> {
  const data = loadVault(await askPassphrase());
  if (!data.pwa) {
    console.error("Pair your phone first: sandgate pair <relay-url>");
    process.exit(1);
  }
  const { newPairing } = await import("./pwacrypto.js");
  const pairing = newPairing();
  const serverName = name || "server";
  const relayUrl = data.pwa!.relayUrl.replace(/\/$/, "");
  const config = {
    relayUrl,
    pairId: pairing.pairId,
    secret: pairing.secret,
    serverName,
    exemptUsers: [] as string[],
    timeoutSec: 60,
    failOpen: false,
  };
  const link = `${relayUrl}/#p=${pairing.pairId}&s=${pairing.secret}`;
  const qrcode = (await import("qrcode-terminal")).default;

  console.log(
    [
      `A pairing of its own for "${serverName}", separate from your workstation:`,
      "revoking this one server later is a single line removed on the phone,",
      "and the server never holds your vault — only the right to ask.",
      "",
      '1. Add it to your phone: open this link there, or scan it, then "+ add a vault".',
      "",
      `  ${link}`,
      "",
    ].join("\n")
  );
  qrcode.generate(link, { small: true });
  console.log(
    [
      "",
      `2. Write this on the server as ${configPath} (root, chmod 600):`,
      "",
      JSON.stringify(config, null, 2),
      "",
      "3. Then, on the server: sandgate ssh-guard install",
    ].join("\n")
  );
}

async function test(configPath: string): Promise<void> {
  const config = loadGuardConfig(configPath);
  const login = loginFromEnv({
    ...process.env,
    PAM_USER: process.env.PAM_USER || process.env.USER || process.env.USERNAME || "test-user",
    PAM_RHOST: process.env.PAM_RHOST || "test run, no real login",
    PAM_TYPE: "auth",
  });
  console.log(`Sending "${describeLogin(login, config).title}" to your phone…`);
  const outcome = await decideLogin(login, config);
  console.log(
    outcome.allow
      ? `Would ALLOW this login (${outcome.reason}).`
      : `Would REFUSE this login (${outcome.reason}${
          "detail" in outcome && outcome.detail ? ": " + outcome.detail : ""
        }).`
  );
}

async function doctor(configPath: string): Promise<void> {
  const problems: string[] = [];

  let config: ReturnType<typeof loadGuardConfig> | null = null;
  try {
    config = loadGuardConfig(configPath);
    console.log(`config                   ok (${configPath})`);
  } catch (err) {
    console.log(`config                   MISSING`);
    problems.push(String(err instanceof Error ? err.message : err));
  }

  const pamFile = "/etc/pam.d/sshd";
  if (existsSync(pamFile)) {
    const hooked = /pam_exec\.so.*ssh-guard\s+approve/.test(readFileSync(pamFile, "utf8"));
    console.log(`pam hook                 ${hooked ? "ok" : "MISSING"}`);
    if (!hooked) problems.push(`add the pam_exec line to ${pamFile} (see: ssh-guard install)`);
  }

  const sshdFile = "/etc/ssh/sshd_config";
  if (existsSync(sshdFile)) {
    const text = readFileSync(sshdFile, "utf8");
    // Without this, public-key logins skip the PAM auth stack entirely and
    // sail past the guard — the mistake that makes people think it works.
    const forced = /^\s*AuthenticationMethods\s+.*keyboard-interactive:pam/m.test(text);
    console.log(`key logins go through PAM ${forced ? "ok" : "NOT FORCED"}`);
    if (!forced) {
      problems.push(
        `add "AuthenticationMethods publickey,keyboard-interactive:pam" to ${sshdFile}, ` +
          "otherwise key-based logins never ask for approval"
      );
    }
  }

  if (config) {
    const hasHatch = (config.exemptUsers ?? []).length > 0 || config.failOpen === true;
    console.log(`escape hatch             ${hasHatch ? "ok" : "NONE"}`);
    if (!hasHatch) {
      problems.push(
        'set "exemptUsers" (a user that never needs approval) or "failOpen": true ' +
          "before relying on this — a flat phone would otherwise lock you out"
      );
    }
  }

  if (problems.length) {
    console.log("\nTo fix:\n" + problems.map((p) => `  - ${p}`).join("\n"));
    process.exit(1);
  }
  console.log("\nAll good. Now open a NEW ssh session from another terminal to confirm.");
}
