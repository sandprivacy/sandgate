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
    case "setup":
      return setup(configPath, arg);
    case "install":
      return install(configPath, arg === "--manual");
    case "enforce":
      return enforce(configPath, arg === "--yes");
    case "uninstall":
      return uninstall();
    case "doctor":
      return doctor(configPath);
    default:
      console.error(
        [
          "Usage: sandgate ssh-guard <pair|install|test|enforce|doctor|uninstall|approve>",
          "  pair [name]      on your workstation: give this server its own pairing",
          "  setup <blob>     on the server, as root: write the config AND wire it up",
          "  install          on the server, as root: wire it up (notification mode)",
          "  install --manual print the lines instead of applying them",
          "  test             send a fake login to your phone",
          "  enforce --yes    switch from notifying to actually blocking",
          "  doctor           check the wiring and your escape hatch",
          "  uninstall        remove everything it added",
          "  approve          called by PAM, not by you",
        ].join("\n")
      );
      process.exit(1);
  }
}

async function binaryInvocation(): Promise<string> {
  const { hookCommand } = await import("./ssh-guard-install.js");
  return hookCommand().display;
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
    // Notification mode to begin with: the first install must not be able
    // to lock anyone out. `ssh-guard enforce` is the deliberate step.
    failOpen: true,
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
  const blob = Buffer.from(JSON.stringify(config), "utf8").toString("base64");
  console.log(
    [
      "",
      "2. On the server, once (needs Node 18+):",
      "",
      "     npm i -g @sandprivacy/sandgate",
      `     sudo sandgate ssh-guard setup ${blob}`,
      "",
      "   That single command writes the config and wires up PAM, in",
      "   notification mode so it cannot lock you out.",
      "",
      "   The blob carries this server's pairing secret, so it will sit in",
      "   your shell history. Prefer to avoid that? Pipe it instead:",
      "     ... | sudo sandgate ssh-guard setup -",
    ].join("\n")
  );
}

/**
 * The whole server-side install in one line: decode the blob printed by
 * `ssh-guard pair`, write it where it belongs with the right permissions,
 * then wire up PAM. Pass "-" to read the blob from stdin instead, when you
 * would rather it not appear in ps output or shell history.
 */
async function setup(configPath: string, blob: string | undefined): Promise<void> {
  const { installHook, isRoot } = await import("./ssh-guard-install.js");
  const { writeFileSync, mkdirSync } = await import("node:fs");
  const { dirname } = await import("node:path");

  if (!isRoot()) {
    console.error("Run this as root (sudo): it writes to /etc and edits sshd's configuration.");
    process.exit(1);
  }
  let encoded = blob;
  if (!encoded || encoded === "-") {
    encoded = await new Promise<string>((resolve) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => (data += chunk));
      process.stdin.on("end", () => resolve(data.trim()));
    });
  }
  if (!encoded) {
    console.error("Usage: sudo sandgate ssh-guard setup <blob from `ssh-guard pair`>");
    process.exit(1);
  }

  let config: unknown;
  try {
    config = JSON.parse(Buffer.from(encoded.trim(), "base64").toString("utf8"));
  } catch {
    console.error("That blob is not readable. Copy the whole line printed by `ssh-guard pair`.");
    process.exit(1);
  }
  for (const field of ["relayUrl", "pairId", "secret"]) {
    if (!(config as Record<string, unknown>)[field]) {
      console.error(`The config is missing "${field}" — copy the whole blob.`);
      process.exit(1);
    }
  }

  mkdirSync(dirname(configPath), { recursive: true, mode: 0o700 });
  writeFileSync(configPath, JSON.stringify(config, null, 2), { mode: 0o600 });
  console.log(`  config written to ${configPath} (root, 0600)`);

  const report = installHook();
  for (const step of report.steps) console.log(`  ${step}`);
  if (report.backups.length) console.log(`  backups: ${report.backups.join(", ")}`);
  if (report.error) {
    console.error("\n" + report.error);
    process.exit(1);
  }
  console.log(
    [
      "",
      "Installed in NOTIFICATION mode — this step cannot lock you out:",
      "logins are announced on your phone and a Deny stops them, but",
      "silence still lets them through.",
      "",
      "Now, WITHOUT closing this session:",
      "  1. sandgate ssh-guard test          (your phone should buzz)",
      "  2. open a NEW ssh session           (it should ask, then let you in)",
      "  3. sandgate ssh-guard enforce --yes (start actually blocking)",
      "",
      "To undo everything: sudo sandgate ssh-guard uninstall",
    ].join("\n")
  );
}

async function install(configPath: string, manual: boolean): Promise<void> {
  const {
    installHook,
    isRoot,
  } = await import("./ssh-guard-install.js");

  if (manual) {
    console.log(installInstructions(configPath, await binaryInvocation()));
    return;
  }
  if (!isRoot()) {
    console.error("Run this as root (sudo): it edits sshd's configuration.");
    process.exit(1);
  }
  let config;
  try {
    config = loadGuardConfig(configPath);
  } catch (err) {
    console.error(String(err instanceof Error ? err.message : err));
    process.exit(1);
  }

  const report = installHook();
  for (const step of report.steps) console.log(`  ${step}`);
  if (report.backups.length) {
    console.log(`  backups: ${report.backups.join(", ")}`);
  }
  if (report.error) {
    console.error(`
${report.error}`);
    process.exit(1);
  }

  const notifying = config.failOpen === true;
  console.log(
    [
      "",
      notifying
        ? "Installed in NOTIFICATION mode: logins are announced on your phone and"
        : "Installed in BLOCKING mode (failOpen is already false in your config).",
      notifying
        ? "an explicit Deny stops them, but silence still lets them through — so a"
        : "Silence now refuses logins. Make sure you have an exempt user.",
      notifying ? "mistake here cannot lock you out." : "",
      "",
      "Now, WITHOUT closing this session:",
      "  1. sandgate ssh-guard test        (your phone should buzz)",
      "  2. open a NEW ssh session         (it should ask, and let you in)",
      notifying ? "  3. sandgate ssh-guard enforce --yes   (start actually blocking)" : "",
      "",
      "To undo everything: sandgate ssh-guard uninstall",
    ]
      .filter((line) => line !== "")
      .join("\n")
  );
}

async function enforce(configPath: string, confirmed: boolean): Promise<void> {
  const config = loadGuardConfig(configPath);
  if (config.failOpen !== true) {
    console.log("Already blocking: silence refuses logins.");
    return;
  }
  const hatch = (config.exemptUsers ?? []).length > 0;
  if (!confirmed) {
    console.log(
      [
        "This switches the guard from notifying to BLOCKING: a login with no",
        "answer on your phone will be refused.",
        "",
        hatch
          ? `Escape hatch in place: ${(config.exemptUsers ?? []).join(", ")}`
          : 'NO ESCAPE HATCH. Add one first: "exemptUsers": ["rescue"] in ' + configPath,
        "",
        "Keep a second SSH session open, then rerun with --yes.",
      ].join("\n")
    );
    process.exit(1);
  }
  const { writeFileSync } = await import("node:fs");
  writeFileSync(configPath, JSON.stringify({ ...config, failOpen: false }, null, 2));
  console.log(
    "Blocking. Test a new login from another terminal now, while this session is still open."
  );
}

async function uninstall(): Promise<void> {
  const { uninstallHook, isRoot } = await import("./ssh-guard-install.js");
  if (!isRoot()) {
    console.error("Run this as root (sudo).");
    process.exit(1);
  }
  const report = uninstallHook();
  for (const step of report.steps) console.log(`  ${step}`);
  if (report.backups.length) console.log(`  backups: ${report.backups.join(", ")}`);
  if (report.error) {
    console.error(`
${report.error}`);
    process.exit(1);
  }
  console.log("\nRemoved. Logins no longer ask for approval.");
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
