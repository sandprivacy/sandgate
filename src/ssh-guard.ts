import { readFileSync, existsSync } from "node:fs";
import { hostname } from "node:os";
import { PwaApprover } from "./pwa-approver.js";
import type { BiometricCredential } from "./webauthn.js";
import { recall, remember, claim, release, awaitDecision } from "./ssh-decision-cache.js";

/**
 * Blocking SSH approval: a login pauses until you tap on your phone.
 *
 * The server never holds your vault — only its own pairing, in a
 * root-only file. A compromised server can therefore ask you to approve
 * things (and you will refuse), but cannot read anything, cannot approve
 * on your behalf, and cannot reach your other pairings; revoking that one
 * server is a single line removed on the phone.
 *
 * Lockout is the real risk here, not cryptography. Two safety valves:
 * exempt users (break-glass) and, when you want alerts rather than a
 * gate, failOpen — which lets *silence* through but still honours an
 * explicit deny.
 */

export interface SshGuardConfig {
  relayUrl: string;
  pairId: string;
  secret: string;
  /** Shown on the phone so you know which machine is asking. */
  serverName?: string;
  /** Users that never need approval — your way back in. */
  exemptUsers?: string[];
  /** Seconds before a login gives up waiting. */
  timeoutSec?: number;
  /**
   * false (default): no answer = refused. Keep an exempt user or a
   * console, or a flat phone locks you out.
   * true: notification mode — silence and relay failures let the login
   * through, an explicit Deny still blocks it.
   */
  failOpen?: boolean;
  /** Require Face ID / Touch ID on the phone for SSH approvals. */
  biometric?: BiometricCredential;
  requireBiometric?: boolean;
}

export const DEFAULT_CONFIG_PATH =
  process.platform === "win32" ? "C:/ProgramData/sandgate/ssh-guard.json" : "/etc/sandgate/ssh-guard.json";

export function configPathFromEnv(env: NodeJS.ProcessEnv = process.env): string {
  return env.SANDGATE_SSH_GUARD_CONFIG || DEFAULT_CONFIG_PATH;
}

export function loadGuardConfig(path: string): SshGuardConfig {
  if (!existsSync(path)) {
    throw new Error(`No ssh-guard config at ${path}. Run \`sandgate ssh-guard pair\` on your workstation.`);
  }
  const config = JSON.parse(readFileSync(path, "utf8")) as SshGuardConfig;
  for (const field of ["relayUrl", "pairId", "secret"] as const) {
    if (!config[field]) throw new Error(`ssh-guard config is missing "${field}".`);
  }
  return config;
}

export interface LoginContext {
  user: string;
  rhost: string;
  service?: string;
  pamType?: string;
}

export function loginFromEnv(env: NodeJS.ProcessEnv): LoginContext {
  return {
    user: env.PAM_USER || "unknown",
    rhost: env.PAM_RHOST || "unknown source",
    service: env.PAM_SERVICE,
    pamType: env.PAM_TYPE,
  };
}

export function describeLogin(login: LoginContext, config: SshGuardConfig) {
  const where = config.serverName || hostname();
  return {
    title: `SSH login: ${login.user}@${where}`,
    body: `From ${login.rhost}. Approve to let this session in.`,
  };
}

export type GuardOutcome =
  | { allow: true; reason: "approved" | "exempt" | "not-auth-phase" | "fail-open" | "recent-approval" }
  | { allow: false; reason: "denied" | "timeout" | "error" | "recent-denial"; detail?: string };

/**
 * Decide a login. Never throws: a guard that crashes must still produce a
 * deliberate answer, because PAM reads only the exit code.
 */
export async function decideLogin(
  login: LoginContext,
  config: SshGuardConfig
): Promise<GuardOutcome> {
  // pam_exec runs for account/session phases too; only gate authentication.
  if (login.pamType && login.pamType !== "auth") {
    return { allow: true, reason: "not-auth-phase" };
  }
  const exempt = (config.exemptUsers ?? []).map((u) => u.toLowerCase());
  if (exempt.includes(login.user.toLowerCase())) {
    return { allow: true, reason: "exempt" };
  }

  // sshd retries authentication, so one login means several hook calls.
  // Reuse the answer you just gave: one buzz per login, and a refusal
  // that actually holds for the whole attempt.
  const recent = recall(login.user, login.rhost);
  if (recent) {
    return recent.allow
      ? { allow: true, reason: "recent-approval" }
      : { allow: false, reason: "recent-denial" };
  }

  // Only one hook per login talks to the phone; the others wait for its
  // answer. Otherwise a single SSH attempt buzzes you half a dozen times.
  if (!claim(login.user, login.rhost)) {
    const shared = await awaitDecision(
      login.user,
      login.rhost,
      (config.timeoutSec ?? 60) * 1000
    );
    if (shared) {
      return shared.allow
        ? { allow: true, reason: "recent-approval" }
        : { allow: false, reason: "recent-denial" };
    }
    // No answer came: same rules as if we had asked ourselves.
    return config.failOpen
      ? { allow: true, reason: "fail-open" }
      : { allow: false, reason: "timeout" };
  }

  const approver = new PwaApprover({
    relayUrl: config.relayUrl,
    pairId: config.pairId,
    secret: config.secret,
    biometric: config.biometric,
    requireBiometric: config.requireBiometric,
  });
  const { title, body } = describeLogin(login, config);

  try {
    const result = await approver.request({
      title,
      body,
      timeoutSec: config.timeoutSec ?? 60,
    });
    release(login.user, login.rhost);
    if (result.approved) {
      remember(login.user, login.rhost, true);
      return { allow: true, reason: "approved" };
    }
    // An explicit deny always blocks, even in failOpen: that is the point
    // of being asked. Only silence is negotiable — and the refusal is
    // remembered, so sshd's next retry cannot slip past it.
    if (result.decision === "denied") {
      remember(login.user, login.rhost, false);
      return { allow: false, reason: "denied" };
    }
    return config.failOpen
      ? { allow: true, reason: "fail-open" }
      : { allow: false, reason: "timeout" };
  } catch (err) {
    release(login.user, login.rhost);
    const detail = err instanceof Error ? err.message : String(err);
    return config.failOpen
      ? { allow: true, reason: "fail-open" }
      : { allow: false, reason: "error", detail };
  }
}

/** The lines a sysadmin must add. Printed, never applied behind your back. */
export function installInstructions(configPath: string, hookCommand: string): string {
  return `sandgate ssh-guard — manual install (deliberately manual: a mistake here
locks you out of the machine).

KEEP A SECOND SSH SESSION OPEN until you have tested a new login.

1. Put the config from \`sandgate ssh-guard pair\` on this server:
     sudo install -d -m 700 $(dirname ${configPath})
     sudo tee ${configPath} > /dev/null   # paste, then Ctrl-D
     sudo chmod 600 ${configPath}

2. Add the approval hook, as the LAST auth line in /etc/pam.d/sshd:
     auth required pam_exec.so quiet ${hookCommand}

3. Public-key logins skip the PAM auth stack, so force it in
   /etc/ssh/sshd_config:
     AuthenticationMethods publickey,keyboard-interactive:pam
     KbdInteractiveAuthentication yes
     UsePAM yes

4. Reload sshd, then — from your OTHER session — check it:
     sudo sshd -t && sudo systemctl reload sshd
     sandgate ssh-guard doctor

5. Open a NEW ssh session. Your phone should buzz.

Escape hatches, set them before you need them:
  "exemptUsers": ["rescue"]   a user that never needs approval
  "failOpen": true            silence lets logins through (alerts, not a gate)`;
}
