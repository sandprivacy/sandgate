# SSH logins that wait for your thumb

Duo does this and charges for it, through their cloud. ntfy and a PAM
script can *tell* you someone logged in — after the fact. `sandgate
ssh-guard` **blocks** the login until you approve it on your phone, over
the same end-to-end-encrypted channel as everything else, on
infrastructure you own.

```
ssh root@vps-prod
  → session pauses
  → phone buzzes: "SSH login: root@vps-prod — from 203.0.113.7"
  → you tap Approve
  → shell opens
```

Deny closes the connection. So does silence, unless you say otherwise.

## What the server holds

Only its own pairing — relay URL, pair id, secret — in a root-only file.
Not your vault, not your 2FA seeds, not your other pairings. A server
that gets compromised can therefore *ask* you to approve things, which
you will refuse, and nothing else. Revoking it is one line removed in the
phone app.

## Setup

**On your workstation** (where your vault lives):

```bash
sandgate ssh-guard pair vps-prod
```

It prints a link and a QR for your phone (in the app: "+ add a vault",
then *Scan a QR code* or paste — the link works once and expires in ten
minutes), and the one line to run on the server. The workstation
remembers the server, so `sandgate pairings` can list it later.

**On the server — literally one command** (plus installing the package):

```bash
npm i -g @sandprivacy/sandgate
sudo sandgate ssh-guard setup eyJyZWxheVVybCI6...   # the exact line `pair` printed
```

Rather not put Node on a server? Each release ships a standalone binary:

```bash
V=v0.9.1   # pin the version you mean to run
cd /usr/local/bin
curl -fL --progress-bar -o sandgate.new https://github.com/sandprivacy/sandgate/releases/download/$V/sandgate-linux-x64
curl -fsSL https://github.com/sandprivacy/sandgate/releases/download/$V/sandgate-linux-x64.sha256 \
  | sed 's/sandgate-linux-x64/sandgate.new/' | sha256sum -c -
chmod +x sandgate.new && ./sandgate.new --version && mv sandgate.new sandgate
sudo sandgate ssh-guard setup eyJ...     # identical from here on
```

Download to a temporary name and `mv` it into place — always, and above
all when upgrading. Once installed, this file IS the PAM hook: a download
cut halfway, written straight over it, leaves a truncated binary that
refuses every SSH login. `mv` swaps it in one step, so PAM only ever sees
the old binary or the new one.

The installer writes the binary itself as the PAM hook — no interpreter,
one file, `bin_t` under SELinux.

`setup` decodes the pairing, writes `/etc/sandgate/ssh-guard.json` as
root with mode 0600, then wires up PAM: it backs up `/etc/pam.d/sshd` and
`/etc/ssh/sshd_config`, applies the hook, and if `sshd -t` rejects the
result it puts everything back and never reloads. Idempotent;
`sudo sandgate ssh-guard uninstall` removes exactly what it added.

The blob carries this server's pairing secret, so it lands in your shell
history. To avoid that, pipe it instead: `... | sudo sandgate ssh-guard setup -`.

**It lands in notification mode**, so a silent phone or a relay outage
cannot lock you out: logins are announced on your phone and an explicit
Deny stops them, but silence still lets them through. What notification
mode does *not* cover is a broken hook: if the sandgate binary itself
cannot run (a truncated download, the wrong architecture), PAM refuses
every login, exempt users included — `failOpen` and `exemptUsers` are
decided inside that binary. Keep the second session open. Verify, then
commit:

```bash
sandgate ssh-guard test              # your phone should buzz
# open a NEW ssh session — it should ask, and let you in
sandgate ssh-guard enforce --yes     # now silence refuses logins
```

`enforce` refuses to run until you have an escape hatch. Prefer to see
the lines before they are applied? `sandgate ssh-guard install --manual`
prints them and touches nothing, and `install` alone wires up a config
you placed yourself.

## Key + phone, no password (`--key-only`)

By default, a machine that accepts passwords keeps doing so: password,
then phone. The stronger setup is a key, then your phone, and no
password at all: a leaked password is then worthless, and a stolen key
is useless without your phone.

```bash
# first, from your workstation: put your key on the server, and log in
# with it from a NEW terminal to be sure it works
ssh-copy-id root@vps-prod

# then, on the server (the session you keep open):
sudo sandgate ssh-guard install --key-only --yes
# or, on a fresh server: ... | sudo sandgate ssh-guard setup - --key-only --yes
```

What changes:

- The hook moves **before** the password check in `/etc/pam.d/sshd`, as
  `auth [success=done ignore=ignore default=die] pam_exec.so …`: an
  approval ends authentication there, so no password is asked; a Deny,
  silence or a crash refuses on the spot. No line of the distribution's
  is edited, so `uninstall` still just removes the marked block.
- The drop-in adds `PasswordAuthentication no` and keeps only
  `AuthenticationMethods publickey,keyboard-interactive:pam`: a key
  first, always.
- If root logs in by key under `PermitRootLogin prohibit-password` (the
  OpenSSH default), the drop-in also says `PermitRootLogin yes`.
  `prohibit-password` refuses keyboard-interactive for root, which is the
  phone step, so root could not log in at all. With a key required
  first, `yes` lets the phone step run and nothing else.

What it refuses, before touching anything:

- **No key for you.** Whoever ran `sudo` (else root) must have a key in
  `authorized_keys`. The command cannot try that key from the inside,
  which is why it also wants `--yes` on a machine that uses passwords
  today.
- **A Match block with a keyless policy.** A `Match User …` that sets
  `AuthenticationMethods keyboard-interactive:pam` would be your phone
  alone, for those users. After writing, the installer also asks sshd
  itself (`sshd -T -C user=…`) for root and for you, Match blocks
  applied, and puts everything back if a login could reach the hook
  without a key.
- **A PAM layout it does not recognise** (no `@include common-auth` or
  `auth substack password-auth`): it will not guess where the hook goes.

**The one rule that keeps this safe:** with the hook before the
password check, the phone is the second factor, so sshd must demand a
key first, everywhere. If you re-enable a password-only path later,
your phone alone opens the server. `sandgate ssh-guard doctor` checks
for exactly that and reports it as a problem.

A machine that already has no password login gets this placement
automatically: earlier versions appended the hook after the password
check there, so logins asked key, then the Unix password, then the
phone, and an account with no password (root on most cloud images)
could not log in. `doctor` flags such an install, and
`install --key-only` fixes it in place.

After an `openssh-server` upgrade, run `doctor`: if the package replaced
`/etc/pam.d/sshd`, the hook is gone and logins stop asking you.

## If you lose access anyway

From your provider's console (this is why it must keep working):

```bash
sudo sandgate ssh-guard uninstall     # or, by hand:
sudo rm -f /etc/ssh/sshd_config.d/00-sandgate.conf
sudo systemctl reload sshd
```

## Not locking yourself out

This is the real risk — the cryptography is the easy part.

- **Keep a second SSH session open** while installing, and test from a
  third. If something is wrong, you still have a way in.
- **`exemptUsers`** — an account that never needs approval. A rescue user
  with a key you keep offline is the classic setup.
- **`failOpen: true`** — notification mode: silence and relay outages let
  logins through, an explicit Deny still blocks. Use it when you want to
  *watch* logins rather than gate them.
- With the default (`failOpen: false`), a flat phone means no SSH. That
  is the point, and it is also how people lock themselves out. `doctor`
  refuses to call your setup healthy until you have one hatch or the
  other.
- Console access (your provider's web console, IPMI) bypasses sshd
  entirely — keep it working. It is the recovery path above.
- The installer reads sshd's own effective configuration and keeps the
  way in that this machine actually uses: on a password box it adds a
  PAM-only path (still gated), on a key-only box it requires the key,
  then the phone, and no password (see `--key-only` above).
  Early versions always demanded a public key, which locked a real
  password-only server out during testing.
- Keep `timeoutSec` below sshd's `LoginGraceTime` (120s by default), or
  sshd hangs up before you have finished deciding.

## Other distributions

Tested against a real sshd on Ubuntu 24.04 (OpenSSH 9.6) and Ubuntu
20.04 (OpenSSH 8.2). The installer adapts to what it finds, but two
families deserve a warning rather than a promise:

**Debian/Ubuntu** — the tested path. `sshd_config.d` exists and is
included from the top of `sshd_config`, so the directives go in a
drop-in read before everything else.

**OpenSSH older than 8.7** (Ubuntu 20.04, Debian 11) — there,
keyboard-interactive through PAM is switched on by
`ChallengeResponseAuthentication`, not `KbdInteractiveAuthentication`,
and these distributions ship it `no`. v0.9.0 did not know that: `sshd -t`
passed, `doctor` said all good, and every login failed. Since v0.9.1 the
installer adds `ChallengeResponseAuthentication yes` when sshd still has
that switch, refuses to keep any configuration in which
keyboard-interactive ends up off, and `doctor` reports it. A server
installed with v0.9.0 is repaired by upgrading the binary and running
`sudo sandgate ssh-guard install` again.

**RHEL / Rocky / Alma 9** — same layout, so the drop-in path applies.
Node comes from `dnf` or NodeSource rather than `apt` — or use the
standalone binary. **SELinux is the real obstacle**: `sshd_t` executing
a binary and opening a network connection during authentication is
exactly what the default policy is built to refuse, and denials surface
as AVC messages in `/var/log/audit/audit.log`. The installer warns when
`getenforce` says Enforcing; [deploy/selinux/](../deploy/selinux/)
carries a policy module and the procedure. Untested on a real enforcing
machine at the time of writing: treat it as a starting point, and send
the denials you hit.

**RHEL 8 and other older releases** — OpenSSH predating 8.2 has no
`Include`, so there is no drop-in directory. The installer detects that
and prepends its directives to `sshd_config` instead, which is correct
because sshd keeps the first value it sees.

## Options

```jsonc
{
  "relayUrl": "https://relay.sandgate.dev",
  "pairId": "…",            // from `ssh-guard pair`
  "secret": "…",
  "serverName": "vps-prod", // shown on the phone
  "exemptUsers": ["rescue"],
  "timeoutSec": 60,
  "failOpen": false,
  "requireBiometric": false // Face ID on the phone for SSH approvals too
}
```

`sandgate ssh-guard pair vps-prod --biometric` fills in the last one for
you: the server gets the public key of the device you enrolled with
`sandgate enroll-biometric`, and every SSH approval then needs Face ID
or Touch ID on that device. Biometrics are per pairing — your workstation
requiring them says nothing about a server.

## What it protects against, and what it does not

**It stops** a stolen key, a leaked password, a brute-forced login: the
attacker authenticates and still gets nowhere, and you find out
instantly.

**It does not stop** an already-root-compromised server — at that point
the attacker controls sshd, PAM and this guard alike. Nor does it replace
key hygiene, fail2ban or a firewall; it is the last gate, not the only
one.
