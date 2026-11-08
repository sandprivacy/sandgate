import {
  readFileSync,
  writeFileSync,
  copyFileSync,
  existsSync,
  rmSync,
  realpathSync,
  readdirSync,
} from "node:fs";
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
 *  3. A silent phone cannot lock anyone out of a first install: it lands in
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

/**
 * Password mode: append the pam_exec hook, once, as the last auth line —
 * AFTER the distribution's password check, so a password user still has
 * to know the password before the phone is even asked.
 */
export function patchPam(text: string, command: string): PatchResult {
  if (text.includes(PAM_MARKER)) return { text, changed: false, note: "already present" };
  const block = `\n${PAM_MARKER}\nauth required pam_exec.so quiet ${command}\n`;
  return { text: text.replace(/\s*$/, "\n") + block, changed: true };
}

/**
 * Key-only mode: the hook goes BEFORE the password check, and an approval
 * ends the auth stack there.
 *
 * Appended after `@include common-auth`, the hook made sshd ask for the
 * Unix password after the key — key, then password, then phone — and an
 * account without a password (root on most cloud images) could not log
 * in at all. Placed first:
 *   - approved  → success=done: authenticated, no password asked;
 *   - denied, silence, crash → default=die: refused on the spot;
 *   - setcred, where pam_exec answers PAM_IGNORE → ignore=ignore, so the
 *     stack carries on to pam_unix's setcred instead of dying after an
 *     approval.
 *
 * This is ONLY safe while sshd demands a key first: the PAM stack is then
 * the second factor and the phone is that factor. Anywhere sshd would let
 * PAM run without a key, this placement means the phone alone opens the
 * server — see keyFirstProblems(), which install and doctor both enforce.
 */
export const PAM_FIRST_CONTROL = "[success=done ignore=ignore default=die]";

/** The line where this PAM file starts checking a password, or -1. */
export function passwordCheckIndex(lines: string[]): number {
  return lines.findIndex(
    (line) =>
      /^\s*@include\s+common-auth\b/.test(line) ||
      /^\s*auth\s+(substack|include)\s+(password-auth|system-auth|common-auth)\b/.test(line)
  );
}

/** Is our hook installed in key-only position (before the password check)? */
export function hookPlacedFirst(text: string): boolean {
  const lines = text.split("\n");
  const at = lines.findIndex((line) => line.trim() === PAM_MARKER);
  const hook = at >= 0 ? (lines[at + 1] ?? "") : "";
  return /pam_exec\.so/.test(hook) && hook.includes("success=done");
}

export function patchPamKeyOnly(text: string, command: string): PatchResult {
  let base = text;
  if (text.includes(PAM_MARKER)) {
    if (hookPlacedFirst(text)) {
      return { text, changed: false, note: "already present, before the password check" };
    }
    // Migrating a password-mode install: take the appended hook out first.
    base = unpatch(text, PAM_MARKER).text;
  }
  const lines = base.split("\n");
  const at = passwordCheckIndex(lines);
  if (at < 0) {
    return {
      text,
      changed: false,
      note:
        "no password check found (@include common-auth, auth substack password-auth): " +
        "this PAM layout is unknown, so key-only mode will not guess where the hook goes",
    };
  }
  // The trailing blank line ends the managed block, so unpatch() restores
  // the file byte for byte.
  lines.splice(at, 0, PAM_MARKER, `auth ${PAM_FIRST_CONTROL} pam_exec.so quiet ${command}`, "");
  return { text: lines.join("\n"), changed: true };
}

export interface DirectiveOptions {
  /** Key + phone, no password path. Defaults to "no password login today". */
  keyOnly?: boolean;
  /**
   * Root logs in with a key, but PermitRootLogin prohibit-password refuses
   * keyboard-interactive for root — which the PAM step is. With key-first
   * enforced, "yes" still requires the key; it only lets the phone step run.
   */
  permitRoot?: boolean;
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
 *
 * Key-only mode says "PasswordAuthentication no" out loud as well: our
 * drop-in is read first and sshd keeps the first value, so a later
 * "PasswordAuthentication yes" elsewhere cannot quietly reopen it.
 */
export function sshdDirectives(passwordLoginPossible: boolean, opts: DirectiveOptions = {}): string {
  const keyOnly = opts.keyOnly ?? !passwordLoginPossible;
  const methods = keyOnly
    ? "publickey,keyboard-interactive:pam"
    : "publickey,keyboard-interactive:pam keyboard-interactive:pam";
  return [
    SSHD_MARKER,
    "UsePAM yes",
    "KbdInteractiveAuthentication yes",
    ...(keyOnly ? ["PasswordAuthentication no"] : []),
    ...(keyOnly && opts.permitRoot ? ["PermitRootLogin yes"] : []),
    `AuthenticationMethods ${methods}`,
    "",
  ].join("\n");
}

const RESTRICTED_ROOT = new Set(["prohibit-password", "without-password", "forced-commands-only"]);

/** Does PermitRootLogin let root log in by key but refuse the PAM step? */
export function rootPamRefused(permitRootLogin: string | undefined): boolean {
  return RESTRICTED_ROOT.has((permitRootLogin ?? "").trim().toLowerCase());
}

function methodLists(settings: Map<string, string>): string[][] {
  const methods = (settings.get("authenticationmethods") ?? "any").trim();
  if (!methods || methods === "any") return [];
  return methods.split(/\s+/).map((list) => list.split(","));
}

/**
 * Everything that would make the key-only placement unsafe — or useless —
 * for this account, as sshd itself resolved it. Empty means: a key is
 * required, then PAM runs, then nothing else can stand in for either.
 */
export function keyFirstProblems(
  user: string,
  settings: Map<string, string>,
  usesKey = true
): string[] {
  const problems: string[] = [];
  if ((settings.get("usepam") ?? "").toLowerCase() !== "yes") {
    problems.push(`${user}: UsePAM is off, so sshd never consults the hook`);
  }
  const lists = methodLists(settings);
  const shown = settings.get("authenticationmethods") ?? "any";
  if (!lists.length || lists.some((list) => !list.includes("publickey"))) {
    problems.push(
      `${user}: sshd accepts a login without a key (AuthenticationMethods "${shown}"). ` +
        "With the hook before the password check, your phone alone would open this server"
    );
  } else if (lists.some((list) => !list.some((m) => m.startsWith("keyboard-interactive")))) {
    problems.push(
      `${user}: some key logins never reach PAM (AuthenticationMethods "${shown}"), so they skip your phone`
    );
  }
  if (user === "root" && usesKey && rootPamRefused(settings.get("permitrootlogin"))) {
    problems.push(
      `root: PermitRootLogin "${settings.get("permitrootlogin")}" refuses the PAM step for root, ` +
        "so root could not log in at all"
    );
  }
  return problems;
}

/**
 * A Match block can hand some users or addresses their own
 * AuthenticationMethods — and with the hook placed first, one without a
 * key is a phone-only door. Per-account `sshd -T -C` covers root and you;
 * this covers everyone else we cannot enumerate.
 */
export function matchOverrides(text: string, file = "sshd_config"): string[] {
  const problems: string[] = [];
  let match: string | null = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [keyword, ...rest] = line.split(/\s+/);
    const key = keyword!.toLowerCase();
    const value = rest.join(" ");
    if (key === "match") {
      match = value;
      continue;
    }
    if (match && key === "authenticationmethods") {
      const lists = value === "any" ? [] : value.split(/\s+/).map((l) => l.split(","));
      if (!lists.length || lists.some((list) => !list.includes("publickey"))) {
        problems.push(
          `${file}: "Match ${match}" sets AuthenticationMethods "${value}", which needs no key — ` +
            "require publickey there, or key-only mode would let those logins in on your phone alone"
        );
      }
    }
  }
  return problems;
}

/** The account that will log in to fix things: whoever ran sudo, else root. */
export function adminAccount(env: NodeJS.ProcessEnv = process.env): string {
  const sudoUser = env.SUDO_USER?.trim();
  return sudoUser && sudoUser !== "root" ? sudoUser : "root";
}

/** Home directory of a user, from /etc/passwd's text. */
export function homeOf(user: string, passwd: string): string | null {
  for (const line of passwd.split("\n")) {
    const fields = line.split(":");
    if (fields[0] === user && fields.length >= 6) return fields[5] || null;
  }
  return null;
}

/** sshd's AuthorizedKeysFile, expanded for one user. */
export function authorizedKeyFiles(setting: string | undefined, user: string, home: string): string[] {
  const spec = setting && setting !== "none" ? setting : ".ssh/authorized_keys .ssh/authorized_keys2";
  home = home.replace(/\/+$/, "") || "/";
  return spec
    .split(/\s+/)
    .filter(Boolean)
    .map((path) =>
      path.replace(/%%/g, "\0").replace(/%h/g, home).replace(/%u/g, user).replace(/\0/g, "%")
    )
    .map((path) => (path.startsWith("/") ? path : `${home === "/" ? "" : home}/${path}`));
}

/** Does an authorized_keys file hold at least one key? */
export function containsKey(text: string): boolean {
  return text.split("\n").some((line) => {
    const trimmed = line.trim();
    return trimmed !== "" && !trimmed.startsWith("#");
  });
}

/**
 * Can this user log in with a key today? "unknown" when keys come from an
 * AuthorizedKeysCommand (LDAP, a vault…) that we cannot see into.
 */
export function userHasKey(user: string, settings: Map<string, string> | null): boolean | "unknown" {
  const command = settings?.get("authorizedkeyscommand");
  let home: string | null = null;
  try {
    home = homeOf(user, readFileSync("/etc/passwd", "utf8"));
  } catch {
    /* no passwd: no key we can find */
  }
  if (home) {
    for (const file of authorizedKeyFiles(settings?.get("authorizedkeysfile"), user, home)) {
      try {
        if (containsKey(readFileSync(file, "utf8"))) return true;
      } catch {
        /* missing or unreadable */
      }
    }
  }
  return command && command !== "none" ? "unknown" : false;
}

/**
 * What must hold BEFORE key-only mode touches anything. Pure, so the
 * refusals can be tested without a server to lock.
 */
export function keyOnlyPreflight(input: {
  pamText: string;
  settingsKnown: boolean;
  admin: string;
  adminHasKey: boolean | "unknown";
  matchProblems: string[];
}): string[] {
  const problems: string[] = [];
  if (!input.settingsKnown) {
    problems.push("sshd -T did not answer, so the effective configuration cannot be checked");
  }
  if (!hookPlacedFirst(input.pamText) && passwordCheckIndex(input.pamText.split("\n")) < 0) {
    problems.push(
      `${PAM_FILE} has no recognisable password check (@include common-auth, ` +
        "auth substack password-auth): key-only mode will not guess where the hook goes"
    );
  }
  if (input.adminHasKey === false) {
    problems.push(
      `${input.admin} has no key in authorized_keys: turning passwords off would lock you out. ` +
        "Copy your key first (ssh-copy-id), log in with it from a new terminal, then rerun"
    );
  }
  problems.push(...input.matchProblems);
  return problems;
}

/** `user=…,host=…,addr=…` for `sshd -T -C`: old releases want all three. */
export function matchSpec(user: string, env: NodeJS.ProcessEnv = process.env): string {
  const addr = env.SSH_CONNECTION?.trim().split(/\s+/)[0] || "127.0.0.1";
  return `user=${user},host=${addr},addr=${addr}`;
}

/**
 * Ask sshd itself what it is currently doing. `sshd -T` prints the
 * effective configuration, includes and drop-ins resolved — far more
 * reliable than reading sshd_config and guessing. With `match`, the
 * configuration for that connection, Match blocks applied.
 */
export function effectiveSshdSettings(match?: string): Map<string, string> | null {
  for (const binary of ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd"]) {
    const result = run(binary, match ? ["-T", "-C", match] : ["-T"]);
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
export function patchSshd(
  text: string,
  passwordLogin = true,
  opts: DirectiveOptions = {}
): PatchResult {
  if (text.includes(SSHD_MARKER)) {
    // Ours already: rewrite it only if the mode changed (password → key-only).
    const base = unpatch(text, SSHD_MARKER).text;
    const next = sshdDirectives(passwordLogin, opts) + "\n" + base;
    return next === text
      ? { text, changed: false, note: "already present" }
      : { text: next, changed: true };
  }
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
  return { text: sshdDirectives(passwordLogin, opts) + "\n" + text, changed: true };
}

/** sshd_config and its drop-ins, as [file, text] — for the Match scan. */
export function sshdConfigTexts(): Array<[string, string]> {
  const texts: Array<[string, string]> = [];
  try {
    texts.push([SSHD_FILE, readFileSync(SSHD_FILE, "utf8")]);
  } catch {
    /* no main file */
  }
  try {
    for (const name of readdirSync(DROPIN_DIR).filter((n) => n.endsWith(".conf")).sort()) {
      const file = `${DROPIN_DIR}/${name}`;
      texts.push([file, readFileSync(file, "utf8")]);
    }
  } catch {
    /* no drop-in directory */
  }
  return texts;
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
/** Is this program Node itself, or a compiled sandgate binary? */
export function looksLikeNode(executable: string): boolean {
  return /(^|[\\/])node(\.exe)?$/i.test(executable);
}

export function hookCommand(): { argv: string[]; display: string } {
  const node = process.execPath;
  // A standalone binary (see the release workflow) IS the program: no
  // interpreter, no script. Node is recognisable by name; anything else
  // that is running this code is a compiled sandgate.
  if (!looksLikeNode(node)) {
    const argv = [node, "ssh-guard", "approve"];
    return { argv, display: argv.join(" ") };
  }
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

/**
 * SELinux in enforcing mode is the one thing on RHEL-family systems that
 * silently defeats this whole setup: sshd's domain is not allowed to run
 * an interpreter and open a network connection during authentication.
 * The install still validates, sshd still reloads, and every login then
 * fails — or passes, in notification mode — with the reason only in
 * audit.log. Say so at install time, and point at the policy.
 */
export function selinuxEnforcing(): boolean {
  const result = run("getenforce", []);
  return result.ok && result.output.trim() === "Enforcing";
}

export interface InstallReport {
  steps: string[];
  backups: string[];
  rolledBack: boolean;
  error?: string;
}

export interface InstallOptions {
  /** Key + phone, passwords off. Implied on a machine with no password login. */
  keyOnly?: boolean;
  /** Override the PAM command line (tests, unusual layouts). */
  invocation?: string;
}

/**
 * Apply the hook. Returns a report rather than throwing: the caller needs
 * to tell the human exactly what happened to their sshd.
 */
export function installHook(opts: InstallOptions = {}): InstallReport {
  const report: InstallReport = { steps: [], backups: [], rolledBack: false };

  if (!existsSync(PAM_FILE)) {
    report.error = `${PAM_FILE} not found — is this a Linux box with OpenSSH?`;
    return report;
  }

  // Build the directives from what this machine actually allows today, so
  // installing the guard never removes the way in that is being used.
  const settings = effectiveSshdSettings();
  const passwordOk = passwordLoginPossible(settings);
  const pamText = readFileSync(PAM_FILE, "utf8");
  // Once key-only, always key-only until uninstall: our own drop-in turns
  // keyboard-interactive on, which would otherwise read as "passwords in
  // use" on a rerun and rebuild the password path — with the hook still
  // placed first, a phone-only door.
  const keyOnly = opts.keyOnly === true || !passwordOk || hookPlacedFirst(pamText);

  const admin = adminAccount();
  const rootSettings = effectiveSshdSettings(matchSpec("root")) ?? settings;
  const rootKey = userHasKey("root", rootSettings) !== false;
  const rootRefused = rootKey && rootPamRefused(rootSettings?.get("permitrootlogin"));

  if (keyOnly) {
    const adminSettings = admin === "root" ? rootSettings : effectiveSshdSettings(matchSpec(admin));
    const problems = keyOnlyPreflight({
      pamText,
      settingsKnown: settings !== null,
      admin,
      adminHasKey: userHasKey(admin, adminSettings),
      matchProblems: sshdConfigTexts().flatMap(([file, text]) => matchOverrides(text, file)),
    });
    if (problems.length) {
      report.error =
        "Key-only mode refused, nothing was changed:\n" + problems.map((p) => `  - ${p}`).join("\n");
      return report;
    }
    report.steps.push(
      passwordOk && !hookPlacedFirst(pamText)
        ? "key-only mode: passwords off, every login needs your key, then your phone"
        : "key-only machine: requiring your key, then your phone — no password asked"
    );
  } else {
    // Password mode keeps a PAM-only path, and PermitRootLogin
    // prohibit-password refuses keyboard-interactive for root: root's key
    // logins would stop working altogether.
    if (rootRefused) {
      const value = rootSettings?.get("permitrootlogin");
      if (admin === "root") {
        report.error =
          `root logs in with a key here, and PermitRootLogin "${value}" refuses the PAM step ` +
          "for root: installing would lock root out. Use --key-only (key + phone, recommended), " +
          "or log in as another user and run this with sudo. Nothing was changed.";
        return report;
      }
      report.steps.push(
        `WARNING: root will no longer be able to log in over SSH (PermitRootLogin ${value}); ` +
          `log in as ${admin}, or use --key-only`
      );
    }
    report.steps.push("password logins are in use here: keeping a password path through PAM");
  }

  const permitRoot = keyOnly && rootRefused;
  const directives = sshdDirectives(passwordOk, { keyOnly, permitRoot });
  if (permitRoot) {
    report.steps.push(
      "PermitRootLogin yes in the drop-in: root still needs its key, this only lets the phone step run"
    );
  }

  // Every file we touch: its previous text, or null if we created it.
  const originals = new Map<string, string | null>();
  const write = (file: string, next: string) => {
    if (!originals.has(file)) {
      if (existsSync(file)) {
        originals.set(file, readFileSync(file, "utf8"));
        const backup = backupPath(file);
        copyFileSync(file, backup);
        report.backups.push(backup);
      } else {
        originals.set(file, null);
      }
    }
    writeFileSync(file, next);
  };
  const rollback = () => {
    for (const [file, text] of originals) {
      if (text === null) rmSync(file, { force: true });
      else writeFileSync(file, text);
    }
    report.rolledBack = true;
  };

  const hook = hookCommand();
  const command = opts.invocation ?? hook.display;
  const pam = keyOnly ? patchPamKeyOnly(pamText, command) : patchPam(pamText, command);
  if (pam.changed) {
    write(PAM_FILE, pam.text);
    report.steps.push(
      keyOnly ? `hook added to ${PAM_FILE}, before the password check` : `hook added to ${PAM_FILE}`
    );
  } else {
    report.steps.push(`${PAM_FILE}: ${pam.note}`);
  }

  if (existsSync(SSHD_FILE)) {
    const sshdText = readFileSync(SSHD_FILE, "utf8");
    const conflict = sshdText.includes(SSHD_MARKER) ? null : conflictingPolicy(sshdText);
    if (conflict) {
      report.steps.push(
        `${SSHD_FILE}: AuthenticationMethods is already "${conflict}" — left alone, ` +
          "add keyboard-interactive:pam to it yourself"
      );
    } else if (usesDropins(sshdText) && existsSync(DROPIN_DIR)) {
      // Read before the distribution's own directives, so ours win.
      const current = existsSync(DROPIN_FILE) ? readFileSync(DROPIN_FILE, "utf8") : null;
      if (current === directives) {
        report.steps.push(`${DROPIN_FILE}: already present`);
      } else {
        write(DROPIN_FILE, directives);
        report.steps.push(
          current === null
            ? `key logins forced through PAM via ${DROPIN_FILE}`
            : `${DROPIN_FILE} updated${keyOnly ? " to key-only" : ""}`
        );
      }
    } else {
      const sshd = patchSshd(sshdText, passwordOk, { keyOnly, permitRoot });
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
    rollback();
    report.error = `sshd rejected the configuration, everything was reverted:\n${valid.output}`;
    return report;
  }
  report.steps.push("sshd -t accepted the configuration");

  // Key-only: prove, from sshd's own resolution with Match blocks applied,
  // that no account we know of can reach the hook without a key.
  if (keyOnly) {
    const users = [...new Set(["root", admin])];
    const problems: string[] = [];
    for (const user of users) {
      const resolved = effectiveSshdSettings(matchSpec(user));
      if (!resolved) problems.push(`${user}: sshd -T -C did not answer`);
      else problems.push(...keyFirstProblems(user, resolved, user === "root" ? rootKey : true));
    }
    if (problems.length) {
      rollback();
      report.error =
        "the result would not be key + phone, everything was reverted:\n" +
        problems.map((p) => `  - ${p}`).join("\n");
      return report;
    }
    report.steps.push(`sshd requires a key before the phone for ${users.join(" and ")}`);
  }

  // The decisive check: can PAM actually run this command? A hook it
  // cannot execute refuses every login, and sshd -t cannot see that.
  const selfTest = hookRunsUnderPam(hook.argv);
  if (!selfTest.ok) {
    rollback();
    report.error =
      "the hook does not run in PAM's bare environment, so it would have " +
      `refused every login. Everything was reverted:
${selfTest.output}`;
    return report;
  }
  report.steps.push("the hook runs under PAM's environment");
  if (selinuxEnforcing()) {
    report.steps.push(
      "SELinux is ENFORCING: sshd may be denied running the hook or reaching the relay. " +
        "Install the policy in deploy/selinux/ and watch: ausearch -m avc -ts recent"
    );
  }

  const reloaded = reloadSshd();
  report.steps.push(reloaded.ok ? "sshd reloaded" : `WARNING: ${reloaded.output}`);
  return report;
}

/** One line of `doctor`. */
export interface Finding {
  level: "ok" | "warn" | "fail";
  label: string;
  detail?: string;
}

/**
 * Read the wiring the way an attacker would, and the way a lockout would.
 * Pure: the caller gathers the PAM text and sshd's resolved settings.
 */
export function analyzeWiring(input: {
  pamText: string | null;
  global: Map<string, string> | null;
  accounts: Array<{ user: string; settings: Map<string, string> | null; usesKey: boolean }>;
}): Finding[] {
  const findings: Finding[] = [];
  const pam = input.pamText ?? "";
  if (!/pam_exec\.so.*ssh-guard\s+approve/.test(pam)) {
    findings.push({
      level: "fail",
      label: "pam hook",
      detail:
        `no hook in ${PAM_FILE}: logins no longer ask your phone. An openssh-server ` +
        "update may have replaced the file — rerun `sandgate ssh-guard install`",
    });
    return findings;
  }
  const first = hookPlacedFirst(pam);
  findings.push({ level: "ok", label: first ? "pam hook (key-only)" : "pam hook" });

  const global = input.global;
  if (global && (global.get("usepam") ?? "").toLowerCase() !== "yes") {
    findings.push({
      level: "fail",
      label: "UsePAM",
      detail: "UsePAM is off: sshd never runs the hook — set UsePAM yes",
    });
  }

  if (first) {
    const problems = input.accounts.flatMap((a) =>
      a.settings
        ? keyFirstProblems(a.user, a.settings, a.usesKey)
        : [`${a.user}: sshd -T -C did not answer`]
    );
    findings.push(
      problems.length
        ? {
            level: "fail",
            label: "key before phone",
            detail: problems.join("\n    ") + "\n    rerun `sandgate ssh-guard install --key-only`",
          }
        : { level: "ok", label: "key before phone" }
    );
    return findings;
  }

  if (global) {
    const methods = global.get("authenticationmethods") ?? "any";
    const forced = methods.includes("keyboard-interactive");
    findings.push(
      forced
        ? { level: "ok", label: "key logins go through PAM" }
        : {
            level: "fail",
            label: "key logins go through PAM",
            detail:
              `sshd resolves AuthenticationMethods to "${methods}", so key-based logins ` +
              "never reach the hook — rerun `sandgate ssh-guard install`",
          }
    );
    if (forced && (global.get("passwordauthentication") ?? "").toLowerCase() === "no") {
      findings.push({
        level: "warn",
        label: "password after key",
        detail:
          "passwords are off, yet the hook sits after the password check: logins ask key, " +
          "then the Unix password, then your phone, and accounts without a password cannot " +
          "log in. `sandgate ssh-guard install --key-only` fixes it",
      });
    }
  }
  const root = input.accounts.find((a) => a.user === "root");
  if (root?.usesKey && root.settings && rootPamRefused(root.settings.get("permitrootlogin"))) {
    findings.push({
      level: "fail",
      label: "root login",
      detail:
        `PermitRootLogin "${root.settings.get("permitrootlogin")}" refuses the PAM step for root: ` +
        "root cannot log in over SSH. `sandgate ssh-guard install --key-only` fixes it",
    });
  }
  return findings;
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
