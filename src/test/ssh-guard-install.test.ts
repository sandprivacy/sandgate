import { test } from "node:test";
import assert from "node:assert/strict";
import {
  patchPam,
  patchSshd,
  unpatch,
  sshdDirectives,
  passwordLoginPossible,
  usesDropins,
  conflictingPolicy,
  PAM_MARKER,
  SSHD_MARKER,
} from "../ssh-guard-install.js";

/**
 * The installer edits the files that decide whether anyone can log into
 * the machine. These cover the edits themselves — idempotence, refusing
 * to trample an existing policy, and removing exactly what was added and
 * nothing else — without needing root or a server to break.
 */

const PAM_BEFORE = ["#%PAM-1.0", "auth       substack     password-auth", "account    required     pam_nologin.so", ""].join("\n");

test("the pam hook is appended once, and only once", () => {
  const first = patchPam(PAM_BEFORE, "/usr/bin/sandgate");
  assert.equal(first.changed, true);
  assert.match(first.text, /pam_exec\.so quiet \/usr\/bin\/sandgate ssh-guard approve/);
  assert.ok(first.text.startsWith(PAM_BEFORE.trimEnd()), "existing rules must survive untouched");

  const second = patchPam(first.text, "/usr/bin/sandgate");
  assert.equal(second.changed, false, "a second install must not duplicate the hook");
  assert.equal(second.text, first.text);
});

test("sshd gains the lines that make key logins consult PAM", () => {
  const result = patchSshd("Port 22\nPermitRootLogin prohibit-password\n");
  assert.equal(result.changed, true);
  // Without this exact directive the hook is never reached for key logins.
  assert.match(result.text, /AuthenticationMethods publickey,keyboard-interactive:pam/);
  assert.match(result.text, /KbdInteractiveAuthentication yes/);
  assert.match(result.text, /UsePAM yes/);
});

test("an existing AuthenticationMethods policy is never overwritten", () => {
  const existing = "Port 22\nAuthenticationMethods publickey,password\n";
  const result = patchSshd(existing);
  assert.equal(result.changed, false, "someone configured this on purpose");
  assert.equal(result.text, existing);
  assert.match(result.note!, /already set/);
});

test("an already-forced policy is accepted as-is", () => {
  const ok = "AuthenticationMethods publickey,keyboard-interactive:pam\n";
  const result = patchSshd(ok);
  assert.equal(result.changed, true, "still needs its own managed block");
  assert.ok(result.text.includes(SSHD_MARKER), "the managed block must be marked for removal");
});

test("uninstall removes the managed block and leaves the rest alone", () => {
  const installed = patchPam(PAM_BEFORE, "/usr/bin/sandgate").text;
  const removed = unpatch(installed, PAM_MARKER);
  assert.equal(removed.changed, true);
  assert.ok(!removed.text.includes("ssh-guard approve"), "the hook must be gone");
  assert.match(removed.text, /auth {7}substack {5}password-auth/, "other rules must remain");

  const again = unpatch(removed.text, PAM_MARKER);
  assert.equal(again.changed, false);
});

test("uninstall on an untouched file changes nothing", () => {
  const result = unpatch(PAM_BEFORE, PAM_MARKER);
  assert.equal(result.changed, false);
  assert.equal(result.text, PAM_BEFORE);
});

test("a password-only machine keeps a way in", () => {
  // Requiring publickey as the first factor, on a box where people log in
  // with a password, locks everyone out the moment sshd reloads. This
  // happened on a real server during testing; it must never happen again.
  const withPassword = sshdDirectives(true);
  assert.match(
    withPassword,
    /AuthenticationMethods publickey,keyboard-interactive:pam keyboard-interactive:pam/,
    "password users need a PAM-only path — which still runs the hook"
  );

  const keysOnly = sshdDirectives(false);
  assert.match(keysOnly, /AuthenticationMethods publickey,keyboard-interactive:pam\n/);
  assert.ok(
    !/pam keyboard-interactive/.test(keysOnly),
    "a key-only machine must not gain a password path it did not have"
  );
});

test("password availability is read from sshd's own effective settings", () => {
  assert.equal(passwordLoginPossible(new Map([["passwordauthentication", "yes"]])), true);
  assert.equal(
    passwordLoginPossible(
      new Map([
        ["passwordauthentication", "no"],
        ["kbdinteractiveauthentication", "yes"],
      ])
    ),
    true
  );
  assert.equal(
    passwordLoginPossible(
      new Map([
        ["passwordauthentication", "no"],
        ["kbdinteractiveauthentication", "no"],
      ])
    ),
    false
  );
  // Cannot tell? Assume a password is in use — the assumption that keeps
  // people able to log in.
  assert.equal(passwordLoginPossible(null), true);
});

test("our directives are prepended, because the first value wins", () => {
  const result = patchSshd("Port 22\nKbdInteractiveAuthentication no\n");
  assert.ok(
    result.text.indexOf("KbdInteractiveAuthentication yes") <
      result.text.indexOf("KbdInteractiveAuthentication no"),
    "appending would silently lose to the distribution's own setting"
  );
});

test("drop-in usage is detected from the Include directive", () => {
  assert.equal(usesDropins("Include /etc/ssh/sshd_config.d/*.conf\nPort 22"), true);
  assert.equal(usesDropins("Port 22\n"), false);
});

test("an existing policy is reported rather than trampled", () => {
  assert.equal(conflictingPolicy("AuthenticationMethods publickey,password"), "publickey,password");
  assert.equal(conflictingPolicy("AuthenticationMethods publickey,keyboard-interactive:pam"), null);
  assert.equal(conflictingPolicy("Port 22"), null);
});
