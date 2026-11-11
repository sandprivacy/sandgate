import { test } from "node:test";
import assert from "node:assert/strict";
import {
  patchPam,
  patchPamKeyOnly,
  patchSshd,
  unpatch,
  hookPlacedFirst,
  passwordCheckIndex,
  sshdDirectives,
  keyFirstProblems,
  matchOverrides,
  rootPamRefused,
  authorizedKeyFiles,
  containsKey,
  homeOf,
  keyOnlyPreflight,
  adminAccount,
  matchSpec,
  analyzeWiring,
  kbdIntProblems,
  legacyChallengeSwitch,
  managedBlock,
  PAM_MARKER,
  SSHD_MARKER,
  PAM_FIRST_CONTROL,
} from "../ssh-guard-install.js";

/**
 * Key-only mode: key, then phone, no password. The hook moves BEFORE the
 * password check, which is only safe while sshd demands a key first —
 * so most of these tests are about refusing, and about noticing when
 * that stops being true.
 */

const CMD = "/usr/local/bin/sandgate ssh-guard approve";

// /etc/pam.d/sshd as shipped by Ubuntu 24.04 (abridged, same shape).
const UBUNTU_PAM = [
  "# PAM configuration for the Secure Shell service",
  "",
  "# Standard Un*x authentication.",
  "@include common-auth",
  "",
  "# Disallow non-root logins when /etc/nologin exists.",
  "account    required     pam_nologin.so",
  "",
  "# Standard Un*x authorization.",
  "@include common-account",
  "",
  "@include common-session",
  "@include common-password",
  "",
].join("\n");

// Rocky / Alma 9.
const RHEL_PAM = [
  "#%PAM-1.0",
  "auth       required     pam_sepermit.so",
  "auth       substack     password-auth",
  "auth       include      postlogin",
  "account    required     pam_nologin.so",
  "account    include      password-auth",
  "",
].join("\n");

const strict = (extra: Record<string, string> = {}) =>
  new Map(
    Object.entries({
      usepam: "yes",
      authenticationmethods: "publickey,keyboard-interactive:pam",
      passwordauthentication: "no",
      kbdinteractiveauthentication: "yes",
      permitrootlogin: "yes",
      ...extra,
    })
  );

test("key-only: the hook lands just before the password check, with the done/die control", () => {
  const result = patchPamKeyOnly(UBUNTU_PAM, CMD);
  assert.equal(result.changed, true);
  const lines = result.text.split("\n");
  const hook = lines.findIndex((l) => l.includes("pam_exec.so"));
  assert.ok(hook >= 0 && hook < passwordCheckIndex(lines), "the hook must run before common-auth");
  assert.equal(lines[hook], `auth ${PAM_FIRST_CONTROL} pam_exec.so quiet ${CMD}`);
  assert.equal(lines[hook - 1], PAM_MARKER, "marked, so uninstall can find it");
  // ignore=ignore is what keeps setcred alive after an approval: pam_exec
  // answers PAM_IGNORE there, and default=die would turn it into a failure.
  assert.match(PAM_FIRST_CONTROL, /success=done/);
  assert.match(PAM_FIRST_CONTROL, /ignore=ignore/);
  assert.match(PAM_FIRST_CONTROL, /default=die/);
  assert.equal(hookPlacedFirst(result.text), true);
});

test("key-only: uninstall restores the PAM file byte for byte", () => {
  const installed = patchPamKeyOnly(UBUNTU_PAM, CMD).text;
  assert.equal(unpatch(installed, PAM_MARKER).text, UBUNTU_PAM);
  const rhel = patchPamKeyOnly(RHEL_PAM, CMD).text;
  assert.equal(unpatch(rhel, PAM_MARKER).text, RHEL_PAM);
});

test("key-only on RHEL: after pam_sepermit, before password-auth", () => {
  const lines = patchPamKeyOnly(RHEL_PAM, CMD).text.split("\n");
  const sepermit = lines.findIndex((l) => l.includes("pam_sepermit"));
  const hook = lines.findIndex((l) => l.includes("pam_exec"));
  const password = lines.findIndex((l) => /substack\s+password-auth/.test(l));
  assert.ok(sepermit < hook && hook < password);
});

test("key-only: an unknown PAM layout is refused, not guessed", () => {
  const odd = "#%PAM-1.0\nauth required pam_custom.so\n";
  const result = patchPamKeyOnly(odd, CMD);
  assert.equal(result.changed, false);
  assert.equal(result.text, odd);
  assert.match(result.note!, /will not guess/);
});

test("key-only is idempotent", () => {
  const once = patchPamKeyOnly(UBUNTU_PAM, CMD).text;
  const twice = patchPamKeyOnly(once, CMD);
  assert.equal(twice.changed, false);
  assert.equal(twice.text, once);
});

test("migrating a password-mode install moves the hook, and leaves exactly one", () => {
  const passwordMode = patchPam(UBUNTU_PAM, CMD).text;
  assert.equal(hookPlacedFirst(passwordMode), false, "appended is not key-only");
  const migrated = patchPamKeyOnly(passwordMode, CMD);
  assert.equal(migrated.changed, true);
  assert.equal(migrated.text.split("pam_exec.so").length - 1, 1, "the appended hook must be gone");
  assert.equal(hookPlacedFirst(migrated.text), true);
  assert.equal(unpatch(migrated.text, PAM_MARKER).text.trimEnd(), UBUNTU_PAM.trimEnd());
});

test("key-only directives turn passwords off and keep the key first", () => {
  const d = sshdDirectives(true, { keyOnly: true });
  assert.match(d, /^PasswordAuthentication no$/m);
  assert.match(d, /^AuthenticationMethods publickey,keyboard-interactive:pam$/m);
  assert.ok(!/pam keyboard-interactive/.test(d), "no PAM-only alternative: that would be phone alone");
  assert.ok(!/PermitRootLogin/.test(d), "root is left alone unless it needs the phone step");
  assert.match(sshdDirectives(true, { keyOnly: true, permitRoot: true }), /^PermitRootLogin yes$/m);
  // A machine with no password login today is key-only by default.
  assert.match(sshdDirectives(false), /^PasswordAuthentication no$/m);
});

test("password-mode directives never touch PasswordAuthentication or root", () => {
  const d = sshdDirectives(true, { permitRoot: true });
  assert.ok(!/PasswordAuthentication/.test(d));
  assert.ok(!/PermitRootLogin/.test(d), "PermitRootLogin yes with a password path would open root to passwords");
});

test("sshd_config without drop-ins: the managed block is rewritten on migration, and removable", () => {
  const original = "Port 22\nKbdInteractiveAuthentication no\n";
  const passwordMode = patchSshd(original, true).text;
  const keyOnly = patchSshd(passwordMode, true, { keyOnly: true });
  assert.equal(keyOnly.changed, true);
  assert.equal(keyOnly.text.split(SSHD_MARKER).length - 1, 1, "one managed block, not two");
  assert.match(keyOnly.text, /PasswordAuthentication no/);
  assert.equal(patchSshd(keyOnly.text, true, { keyOnly: true }).changed, false);
  assert.equal(unpatch(keyOnly.text, SSHD_MARKER).text, original);
});

test("key before phone: a strict configuration passes", () => {
  assert.deepEqual(keyFirstProblems("root", strict()), []);
  assert.deepEqual(keyFirstProblems("baltha", strict({ permitrootlogin: "prohibit-password" })), []);
});

test("key before phone: any path without a key is flagged as phone-alone", () => {
  for (const methods of ["any", "publickey,keyboard-interactive:pam keyboard-interactive:pam", "password"]) {
    const problems = keyFirstProblems("root", strict({ authenticationmethods: methods }));
    assert.ok(
      problems.some((p) => /phone alone/.test(p)),
      `"${methods}" must be caught: ${problems.join(" | ")}`
    );
  }
});

test("key before phone: a key path that skips PAM is flagged", () => {
  const problems = keyFirstProblems("root", strict({ authenticationmethods: "publickey" }));
  assert.ok(problems.some((p) => /never reach PAM/.test(p)));
});

test("key before phone: UsePAM off is flagged", () => {
  assert.ok(keyFirstProblems("root", strict({ usepam: "no" })).some((p) => /UsePAM/.test(p)));
});

test("root by key with prohibit-password cannot pass the PAM step", () => {
  for (const value of ["prohibit-password", "without-password", "forced-commands-only"]) {
    assert.equal(rootPamRefused(value), true, value);
    const problems = keyFirstProblems("root", strict({ permitrootlogin: value }), true);
    assert.ok(problems.some((p) => /could not log in/.test(p)), value);
  }
  assert.equal(rootPamRefused("yes"), false);
  assert.equal(rootPamRefused("no"), false);
  // Root without a key does not log in by key: nothing to break.
  assert.deepEqual(keyFirstProblems("root", strict({ permitrootlogin: "prohibit-password" }), false), []);
});

test("Match blocks that hand out a keyless policy are caught", () => {
  const config = [
    "AuthenticationMethods publickey,keyboard-interactive:pam",
    "#Match User anoncvs",
    "#  AuthenticationMethods any",
    "Match User deploy",
    "  AuthenticationMethods keyboard-interactive:pam",
    "Match Address 10.0.0.0/8",
    "  AuthenticationMethods publickey,keyboard-interactive:pam",
    "",
  ].join("\n");
  const problems = matchOverrides(config, "/etc/ssh/sshd_config");
  assert.equal(problems.length, 1, problems.join(" | "));
  assert.match(problems[0]!, /Match User deploy/);
  assert.deepEqual(matchOverrides("AuthenticationMethods password\n"), [], "global lines are sshd -T's job");
  assert.equal(matchOverrides("Match User x\n  AuthenticationMethods any\n").length, 1);
});

test("authorized_keys: sshd's tokens expand, comments do not count as keys", () => {
  assert.deepEqual(authorizedKeyFiles(undefined, "root", "/root"), [
    "/root/.ssh/authorized_keys",
    "/root/.ssh/authorized_keys2",
  ]);
  assert.deepEqual(authorizedKeyFiles("/etc/ssh/keys/%u %h/.ssh/k 100%%", "bob", "/home/bob/"), [
    "/etc/ssh/keys/bob",
    "/home/bob/.ssh/k",
    "/home/bob/100%",
  ]);
  assert.equal(containsKey("# nothing here\n\n"), false);
  assert.equal(containsKey("ssh-ed25519 AAAAC3Nza... baltha\n"), true);
  assert.equal(homeOf("bob", "root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n"), "/home/bob");
  assert.equal(homeOf("nobody-here", "root:x:0:0:root:/root:/bin/bash\n"), null);
});

test("preflight: no key for you means no key-only", () => {
  const base = {
    pamText: UBUNTU_PAM,
    settingsKnown: true,
    admin: "root",
    adminHasKey: true as boolean | "unknown",
    matchProblems: [] as string[],
  };
  assert.deepEqual(keyOnlyPreflight(base), []);
  assert.ok(keyOnlyPreflight({ ...base, adminHasKey: false }).some((p) => /lock you out/.test(p)));
  assert.deepEqual(keyOnlyPreflight({ ...base, adminHasKey: "unknown" }), [], "AuthorizedKeysCommand: trust it");
  assert.ok(keyOnlyPreflight({ ...base, settingsKnown: false }).length > 0);
  assert.ok(keyOnlyPreflight({ ...base, pamText: "auth required pam_custom.so\n" }).length > 0);
  assert.equal(keyOnlyPreflight({ ...base, matchProblems: ["x"] }).length, 1);
  // Already key-only: a layout we placed ourselves is fine.
  const placed = patchPamKeyOnly(UBUNTU_PAM, CMD).text;
  assert.deepEqual(keyOnlyPreflight({ ...base, pamText: placed }), []);
});

test("the admin is whoever ran sudo, else root", () => {
  assert.equal(adminAccount({ SUDO_USER: "baltha" }), "baltha");
  assert.equal(adminAccount({ SUDO_USER: "root" }), "root");
  assert.equal(adminAccount({}), "root");
});

test("sshd -T -C gets all three fields, from the live connection when known", () => {
  assert.equal(matchSpec("root", {}), "user=root,host=127.0.0.1,addr=127.0.0.1");
  assert.equal(
    matchSpec("root", { SSH_CONNECTION: "203.0.113.7 51234 10.0.0.2 22" }),
    "user=root,host=203.0.113.7,addr=203.0.113.7"
  );
});

test("doctor: a vanished hook says why it may have vanished", () => {
  const findings = analyzeWiring({ pamText: UBUNTU_PAM, global: strict(), accounts: [] });
  assert.equal(findings[0]!.level, "fail");
  assert.match(findings[0]!.detail!, /openssh-server/);
});

test("doctor: key-only that drifted to a keyless path is a failure", () => {
  const pamText = patchPamKeyOnly(UBUNTU_PAM, CMD).text;
  const clean = analyzeWiring({
    pamText,
    global: strict(),
    accounts: [{ user: "root", settings: strict(), usesKey: true }],
  });
  assert.ok(clean.every((f) => f.level === "ok"), JSON.stringify(clean));

  const drifted = strict({ authenticationmethods: "publickey,keyboard-interactive:pam keyboard-interactive:pam" });
  const findings = analyzeWiring({
    pamText,
    global: drifted,
    accounts: [{ user: "root", settings: drifted, usesKey: true }],
  });
  const fail = findings.find((f) => f.level === "fail");
  assert.ok(fail, "a phone-only door must not pass");
  assert.match(fail!.detail!, /phone alone/);
});

test("doctor: the old key-then-password wiring is called out", () => {
  const pamText = patchPam(UBUNTU_PAM, CMD).text;
  const findings = analyzeWiring({
    pamText,
    global: strict(),
    accounts: [{ user: "root", settings: strict(), usesKey: true }],
  });
  assert.ok(findings.some((f) => f.level === "warn" && /--key-only/.test(f.detail ?? "")));
});

test("doctor: root locked out by prohibit-password is a failure", () => {
  const pamText = patchPam(UBUNTU_PAM, CMD).text;
  const settings = strict({
    permitrootlogin: "prohibit-password",
    passwordauthentication: "yes",
    authenticationmethods: "publickey,keyboard-interactive:pam keyboard-interactive:pam",
  });
  const findings = analyzeWiring({
    pamText,
    global: settings,
    accounts: [{ user: "root", settings, usesKey: true }],
  });
  assert.ok(findings.some((f) => f.level === "fail" && f.label === "root login"));
});

test("doctor: UsePAM off is a failure", () => {
  const pamText = patchPam(UBUNTU_PAM, CMD).text;
  const settings = strict({ usepam: "no" });
  const findings = analyzeWiring({ pamText, global: settings, accounts: [] });
  assert.ok(findings.some((f) => f.level === "fail" && f.label === "UsePAM"));
});

// ---- OpenSSH older than 8.7 (Ubuntu 20.04, Debian 11) --------------------
// There, ChallengeResponseAuthentication is the switch that turns
// keyboard-interactive through PAM on; distributions ship it "no". On a
// real Ubuntu 20.04 server, sshd -t passed, doctor said "All good", and
// every login failed.

/** `sshd -T` on Ubuntu 20.04 after a v0.9.0 install: kbd on, challenge off. */
const focal = (extra: Record<string, string> = {}) =>
  strict({ challengeresponseauthentication: "no", ...extra });

test("an old sshd is recognised by the switch sshd -T still prints", () => {
  assert.equal(legacyChallengeSwitch(focal()), true);
  assert.equal(legacyChallengeSwitch(strict()), false, "8.7+ no longer prints it");
  assert.equal(legacyChallengeSwitch(null), true, "unknown: add the harmless alias");
});

test("the drop-in turns ChallengeResponseAuthentication on for an old sshd only", () => {
  assert.match(
    sshdDirectives(true, { legacyChallenge: true }),
    /^ChallengeResponseAuthentication yes$/m
  );
  assert.match(
    sshdDirectives(false, { keyOnly: true, legacyChallenge: true }),
    /^ChallengeResponseAuthentication yes$/m
  );
  assert.ok(!/ChallengeResponse/.test(sshdDirectives(true)));
  // Our line must sit in the drop-in that is read FIRST: sshd keeps the
  // first value, and the distribution's "no" comes later in sshd_config.
  const d = sshdDirectives(true, { legacyChallenge: true });
  assert.ok(d.indexOf("ChallengeResponseAuthentication yes") < d.indexOf("AuthenticationMethods"));
});

test("keyboard-interactive switched off is caught, whichever switch did it", () => {
  assert.deepEqual(kbdIntProblems(strict()), []);
  assert.ok(kbdIntProblems(focal()).some((p) => /older than 8\.7/.test(p)));
  assert.ok(kbdIntProblems(strict({ kbdinteractiveauthentication: "no" })).length > 0);
  assert.deepEqual(kbdIntProblems(focal({ challengeresponseauthentication: "yes" })), []);
});

test("doctor: the Ubuntu 20.04 case is no longer 'All good' (password mode)", () => {
  const pamText = patchPam(UBUNTU_PAM, CMD).text;
  const findings = analyzeWiring({
    pamText,
    global: focal({ authenticationmethods: "publickey,keyboard-interactive:pam keyboard-interactive:pam" }),
    accounts: [],
  });
  const fail = findings.find((f) => f.label === "keyboard-interactive");
  assert.ok(fail && fail.level === "fail", JSON.stringify(findings));
  assert.match(fail!.detail!, /ChallengeResponseAuthentication/);
});

test("doctor and install: the Ubuntu 20.04 case fails key-only verification too", () => {
  const pamText = patchPamKeyOnly(UBUNTU_PAM, CMD).text;
  const findings = analyzeWiring({
    pamText,
    global: focal(),
    accounts: [{ user: "root", settings: focal(), usesKey: true }],
  });
  assert.ok(findings.some((f) => f.level === "fail"));
  assert.ok(keyFirstProblems("root", focal()).some((p) => /ChallengeResponseAuthentication/.test(p)));
});

test("our own managed block is read back, and only it", () => {
  // On a rerun, sshd -T reports OUR "PermitRootLogin yes" as if root were
  // fine — dropping it on that basis locked root out again (seen on
  // Ubuntu 20.04). The installer reads its own block instead.
  const dropin = sshdDirectives(false, { keyOnly: true, permitRoot: true, legacyChallenge: true });
  const block = managedBlock(dropin);
  assert.ok(block.includes("PermitRootLogin yes"));
  assert.ok(block.includes("PasswordAuthentication no"));
  assert.ok(!block.includes(SSHD_MARKER), "the marker itself is not a directive");

  const mixed = "Port 22\nPermitRootLogin yes\n\n" + dropin + "\nPermitRootLogin no\n";
  assert.deepEqual(managedBlock(mixed), block, "lines outside the block are not ours");
  assert.deepEqual(managedBlock("Port 22\nPermitRootLogin yes\n"), []);
});
