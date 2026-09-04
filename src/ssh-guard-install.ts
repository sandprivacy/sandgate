import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
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
 * Force public-key logins through the PAM stack. Without this the hook is
 * never consulted for key logins — the mistake that makes people believe
 * the guard works when it does not.
 */
export function patchSshd(text: string): PatchResult {
  if (text.includes(SSHD_MARKER)) return { text, changed: false, note: "already present" };

  const existing = text.match(/^[ \t]*AuthenticationMethods[ \t]+(.+)$/m);
  if (existing && !existing[1]!.includes("keyboard-interactive:pam")) {
    // Someone configured this deliberately; overwriting it could lock them
    // out or weaken their policy. Refuse and let a human decide.
    return {
      text,
      changed: false,
      note:
        `AuthenticationMethods is already set to "${existing[1]!.trim()}". ` +
        "Leaving it alone: add keyboard-interactive:pam to it yourself, then rerun.",
    };
  }

  const block = [
    "",
    SSHD_MARKER,
    "UsePAM yes",
    "KbdInteractiveAuthentication yes",
    "AuthenticationMethods publickey,keyboard-interactive:pam",
    "",
  ].join("\n");
  return { text: text.replace(/\s*$/, "\n") + block, changed: true };
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
export function installHook(invocation: string): InstallReport {
  const report: InstallReport = { steps: [], backups: [], rolledBack: false };

  if (!existsSync(PAM_FILE)) {
    report.error = `${PAM_FILE} not found — is this a Linux box with OpenSSH?`;
    return report;
  }

  const originals = new Map<string, string>();
  const write = (file: string, next: string) => {
    originals.set(file, readFileSync(file, "utf8"));
    const backup = backupPath(file);
    copyFileSync(file, backup);
    report.backups.push(backup);
    writeFileSync(file, next);
  };

  const pam = patchPam(readFileSync(PAM_FILE, "utf8"), invocation);
  if (pam.changed) {
    write(PAM_FILE, pam.text);
    report.steps.push(`hook added to ${PAM_FILE}`);
  } else {
    report.steps.push(`${PAM_FILE}: ${pam.note}`);
  }

  if (existsSync(SSHD_FILE)) {
    const sshd = patchSshd(readFileSync(SSHD_FILE, "utf8"));
    if (sshd.changed) {
      write(SSHD_FILE, sshd.text);
      report.steps.push(`key logins forced through PAM in ${SSHD_FILE}`);
    } else {
      report.steps.push(`${SSHD_FILE}: ${sshd.note}`);
    }
  }

  const valid = sshdConfigIsValid();
  if (!valid.ok) {
    for (const [file, text] of originals) writeFileSync(file, text);
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
