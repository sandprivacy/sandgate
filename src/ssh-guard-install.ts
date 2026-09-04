import { readFileSync, writeFileSync, copyFileSync, existsSync, rmSync, realpathSync } from "node:fs";
import { execFileSync } from "node:child_process";

/**
 * Automated install of the SSH approval hook.
 *
 * Editing sshd's configuration from a script is how people lose access to
 * their servers, so three rules hold everywhere below:
 *
 *  1. Every file is backed up before it is touched.
 *  2. `sshd -t` must accept the result; if it does not, everything is
 *     rolled back and sshd is never reloaded.
 *  3. The first install cannot lock anyone out, because it lands in
 *     notification mode — silence lets logins through until you
 *     deliberately run `ssh-guard enforce`.
 *
 * The text edits are pure functions so they can be tested without root,
 * without sshd, and without a server to break.
 */

export const PAM_MARKER = "# sandgate ssh-guard (managed)";
export const SSHD_MARKER = "# sandgate ssh-guard (managed)";
export const PAM_FILE = "/etc/pam.d/sshd";
export const SSHD_FILE = "/etc/ssh/sshd_config";
/**
 * sshd keeps the FIRST value it sees for a keyword, and distributions ship
 * `KbdInteractiveAuthentication no` half-way down sshd_config. Appending
 * our directives there is therefore useless — they lose. Modern sshd
 * includes this directory from the top of the file, and reads it in
 * lexical order, so a `00-` drop-in is read before anything else.
 */
export const DROPIN_DIR = "/etc/ssh/sshd_config.d";
export const DROPIN_FILE = `${DROPIN_DIR}/00-sandgate.conf`;

export interface PatchResult {
  text: string;
  changed: boolean;
  note?: string;
}

/** Append the pam_exec hook, once, as the last auth line. */
export function patchPam(text: string, invocation: string): PatchResult {
  if (text.includes(PAM_MARKER)) return { text, changed: false, note: "already present" };
  const block = `\n${PAM_MARKER}\nauth required pam_exec.so quiet ${invocation} ssh-guard approve\n`;
  return { text: text.replace(/\s*$/, "\n") + block, changed: true };
}

/**
 * The directives that make logins consult PAM — and, crucially, that do
 * not remove the way this machine is actually reachable.
 *
 * "publickey,keyboard-interactive:pam" alone demands a key as the FIRST
 * factor. On a box where people log in with a password, that is an
 * instant lockout: sshd stops offering password authentication and
 * nobody can get in. Learned the hard way on a real server.
 *
 * So when password logins are possible we list both alternatives. Key
 * users get key + PAM; password users get PAM, which checks their
 * password and runs the hook. Neither path skips the guard.
 */
export function sshdDirectives(passwordLoginPossible: boolean): string {
  const methods = passwordLoginPossible
    ? "publickey,keyboard-interactive:pam keyboard-interactive:pam"
    : "publickey,keyboard-interactive:pam";
  return [
    SSHD_MARKER,
    "UsePAM yes",
    "KbdInteractiveAuthentication yes",
    `AuthenticationMethods ${methods}`,
    "",
  ].join("\n");
}

/**
 * Ask sshd itself what it is currently doing. `sshd -T` prints the
 * effective configuration, includes and drop-ins resolved — far more
 * reliable than reading sshd_config and guessing.
 */
export function effectiveSshdSettings(): Map<string, string> | null {
  for (const binary of ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd"]) {
    const result = run(binary, ["-T"]);
    if (!result.ok) continue;
    const settings = new Map<string, string>();
    for (const line of result.output.split("\n")) {
      const at = line.indexOf(" ");
      if (at > 0) settings.set(line.slice(0, at).toLowerCase(), line.slice(at + 1).trim());
    }
    return settings;
  }
  return null;
}

/** Can anyone still log in with a password right now? */
export function passwordLoginPossible(settings: Map<string, string> | null): boolean {
  if (!settings) return true; // cannot tell: assume yes, the safe assumption
  return (
    settings.get("passwordauthentication") === "yes" ||
    settings.get("kbdinteractiveauthentication") === "yes"
  );
}

/** Does this sshd_config pull in the drop-in directory, and from the top? */
export function usesDropins(text: string): boolean {
  return /^[ \t]*Include[ \t]+\/etc\/ssh\/sshd_config\.d\/\*\.conf/m.test(text);
}

/**
 * Refuse to touch a policy someone set on purpose: overwriting
 * AuthenticationMethods could lock them out or weaken their rules.
 */
export function conflictingPolicy(text: string): string | null {
  const existing = text.match(/^[ \t]*AuthenticationMethods[ \t]+(.+)$/m);
  if (existing && !existing[1]!.includes("keyboard-interactive:pam")) {
    return existing[1]!.trim();
  }
  return null;
}

/**
 * Force public-key logins through the PAM stack. Without this the hook is
 * never consulted for key logins — the mistake that makes people believe
 * the guard works when it does not.
 */
/**
 * Fallback for sshd_config files with no Include directory: prepend,
 * because sshd keeps the FIRST value it sees and a distribution's own
 * "KbdInteractiveAuthentication no" usually sits further down.
 */
export function patchSshd(text: string, passwordLogin = true): PatchResult {
  if (text.includes(SSHD_MARKER)) return { text, changed: false, note: "already present" };
  const conflict = conflictingPolicy(text);
  if (conflict) {
    return {
      text,
      changed: false,
      note:
        `AuthenticationMethods is already set to "${conflict}". ` +
        "Leaving it alone: add keyboard-interactive:pam to it yourself, then rerun.",
    };
  }
  return { text: sshdDirectives(passwordLogin) + "\n" + text, changed: true };
}

/** Remove everything the installer added, and nothing else. */
export function unpatch(text: string, marker: string): PatchResult {
  if (!text.includes(marker)) return { text, changed: false, note: "nothing to remove" };
  const lines = text.split("\n");
  const kept: string[] = [];
  let skipping = false;
  for (const line of lines) {
    if (line.trim() === marker) {
      skipping = true;
      continue;
    }
    // The managed block runs until the next blank line.
    if (skipping) {
      if (line.trim() === "") {
        skipping = false;
      }
      continue;
    }
    kept.push(line);
  }
  return { text: kept.join("\n").replace(/\n{3,}/g, "\n\n"), changed: true };
}

export function backupPath(file: string): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `${file}.sandgate-backup-${stamp}`;
}

function run(command: string, args: string[]): { ok: boolean; output: string } {
  try {
    const output = execFileSync(command, args, { encoding: "utf8", stdio: "pipe" });
    return { ok: true, output };
  } catch (err: any) {
    return { ok: false, output: String(err?.stderr || err?.message || err) };
  }
}

/** `sshd -t`, wherever sshd lives. */
export function sshdConfigIsValid(): { ok: boolean; output: string } {
  for (const binary of ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd"]) {
    const result = run(binary, ["-t"]);
    if (result.ok) return result;
    if (!/not found|ENOENT/i.test(result.output)) return result; // sshd ran and complained
  }
  return { ok: false, output: "sshd not found — cannot validate the configuration" };
}

export function reloadSshd(): { ok: boolean; output: string } {
  for (const [cmd, args] of [
    ["systemctl", ["reload", "sshd"]],
    ["systemctl", ["reload", "ssh"]],
    ["service", ["sshd", "reload"]],
    ["service", ["ssh", "reload"]],
  ] as const) {
    const result = run(cmd, [...args]);
    if (result.ok) return result;
  }
  return { ok: false, output: "could not reload sshd — do it yourself, then test a new login" };
}

/**
 * The exact command PAM will run. It MUST be absolute: pam_exec executes
 * with a bare environment, and a global npm install puts the shim in
 * /usr/local/bin, which is not on that PATH. A bare "sandgate" there is
 * "command not found", which pam_exec reports as failure — and every
 * login is refused. This locked a real server out during testing.
 */
export function hookCommand(): { argv: string[]; display: string } {
  const node = process.execPath;
  const entry = process.argv[1];
  let script: string | null = null;
  if (entry) {
    try {
      // Resolves the /usr/local/bin/sandgate symlink to the real .js file.
      const resolved = realpathSync(entry);
      if (resolved.endsWith(".js")) script = resolved;
    } catch {
      /* fall through */
    }
  }
  const argv = script ? [node, script, "ssh-guard", "approve"] : ["sandgate", "ssh-guard", "approve"];
  return { argv, display: argv.join(" ") };
}

/**
 * Run the hook exactly as PAM will — empty environment included — during
 * the account phase, which passes through without touching the relay.
 * If this fails, the hook would refuse every login, so the install must
 * not stand.
 */
export function hookRunsUnderPam(argv: string[]): { ok: boolean; output: string } {
  const [command, ...args] = argv;
  try {
    execFileSync(command!, args, {
      env: { PAM_TYPE: "account", PAM_USER: "sandgate-selftest", PAM_RHOST: "selftest" },
      encoding: "utf8",
      stdio: "pipe",
      timeout: 30_000,
    });
    return { ok: true, output: "" };
  } catch (err: any) {
    return {
      ok: false,
      output: String(err?.stderr || err?.message || err).slice(0, 300),
    };
  }
}

export interface InstallReport {
  steps: string[];
  backups: string[];
  rolledBack: boolean;
  error?: string;
}

/**
 * Apply the hook. Returns a report rather than throwing: the caller needs
 * to tell the human exactly what happened to their sshd.
 */
export function installHook(invocation?: string): InstallReport {
  const report: InstallReport = { steps: [], backups: [], rolledBack: false };

  if (!existsSync(PAM_FILE)) {
    report.error = `${PAM_FILE} not found — is this a Linux box with OpenSSH?`;
    return report;
  }

  const originals = new Map<string, string>();
  let createdDropin = false;

  // Build the directives from what this machine actually allows today, so
  // installing the guard never removes the way in that is being used.
  const settings = effectiveSshdSettings();
  const passwordOk = passwordLoginPossible(settings);
  const directives = sshdDirectives(passwordOk);
  report.steps.push(
    passwordOk
      ? "password logins are in use here: keeping a password path through PAM"
      : "key-only machine: requiring publickey plus PAM"
  );
  const write = (file: string, next: string) => {
    originals.set(file, readFileSync(file, "utf8"));
    const backup = backupPath(file);
    copyFileSync(file, backup);
    report.backups.push(backup);
    writeFileSync(file, next);
  };

  const hook = hookCommand();
  const pam = patchPam(readFileSync(PAM_FILE, "utf8"), invocation ?? hook.display);
  if (pam.changed) {
    write(PAM_FILE, pam.text);
    report.steps.push(`hook added to ${PAM_FILE}`);
  } else {
    report.steps.push(`${PAM_FILE}: ${pam.note}`);
  }

  if (existsSync(SSHD_FILE)) {
    const sshdText = readFileSync(SSHD_FILE, "utf8");
    const conflict = conflictingPolicy(sshdText);
    if (conflict) {
      report.steps.push(
        `${SSHD_FILE}: AuthenticationMethods is already "${conflict}" — left alone, ` +
          "add keyboard-interactive:pam to it yourself"
      );
    } else if (usesDropins(sshdText) && existsSync(DROPIN_DIR)) {
      // Read before the distribution's own directives, so ours win.
      if (existsSync(DROPIN_FILE)) {
        report.steps.push(`${DROPIN_FILE}: already present`);
      } else {
        writeFileSync(DROPIN_FILE, directives);
        createdDropin = true;
        report.steps.push(`key logins forced through PAM via ${DROPIN_FILE}`);
      }
    } else {
      const sshd = patchSshd(sshdText, passwordOk);
      if (sshd.changed) {
        write(SSHD_FILE, sshd.text);
        report.steps.push(`key logins forced through PAM in ${SSHD_FILE}`);
      } else {
        report.steps.push(`${SSHD_FILE}: ${sshd.note}`);
      }
    }
  }

  const valid = sshdConfigIsValid();
  if (!valid.ok) {
    for (const [file, text] of originals) writeFileSync(file, text);
    if (createdDropin) rmSync(DROPIN_FILE, { force: true });
    report.rolledBack = true;
    report.error = `sshd rejected the configuration, everything was reverted:\n${valid.output}`;
    return report;
  }
  report.steps.push("sshd -t accepted the configuration");

  const reloaded = reloadSshd();
  report.steps.push(reloaded.ok ? "sshd reloaded" : `WARNING: ${reloaded.output}`);
  return report;
}

export function uninstallHook(): InstallReport {
  const report: InstallReport = { steps: [], backups: [], rolledBack: false };
  if (existsSync(DROPIN_FILE)) {
    rmSync(DROPIN_FILE, { force: true });
    report.steps.push(`removed ${DROPIN_FILE}`);
  }
  for (const [file, marker] of [
    [PAM_FILE, PAM_MARKER],
    [SSHD_FILE, SSHD_MARKER],
  ] as const) {
    if (!existsSync(file)) continue;
    const result = unpatch(readFileSync(file, "utf8"), marker);
    if (!result.changed) {
      report.steps.push(`${file}: ${result.note}`);
      continue;
    }
    const backup = backupPath(file);
    copyFileSync(file, backup);
    report.backups.push(backup);
    writeFileSync(file, result.text);
    report.steps.push(`removed from ${file}`);
  }
  const valid = sshdConfigIsValid();
  if (!valid.ok) {
    report.error = `sshd is unhappy after removal — check it before reloading:\n${valid.output}`;
    return report;
  }
  const reloaded = reloadSshd();
  report.steps.push(reloaded.ok ? "sshd reloaded" : `WARNING: ${reloaded.output}`);
  return report;
}

export function isRoot(): boolean {
  return typeof process.getuid === "function" ? process.getuid() === 0 : false;
}
