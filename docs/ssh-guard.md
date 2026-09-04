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

It prints a link and a QR for your phone (add it with "+ add a vault", so
the server shows up under its own name), then the JSON config to install
on the server.

**On the server — literally one command** (plus installing the package):

```bash
npm i -g @sandprivacy/sandgate
sudo sandgate ssh-guard setup eyJyZWxheVVybCI6...   # the exact line `pair` printed
```

`setup` decodes the pairing, writes `/etc/sandgate/ssh-guard.json` as
root with mode 0600, then wires up PAM: it backs up `/etc/pam.d/sshd` and
`/etc/ssh/sshd_config`, applies the hook, and if `sshd -t` rejects the
result it puts everything back and never reloads. Idempotent;
`sudo sandgate ssh-guard uninstall` removes exactly what it added.

The blob carries this server's pairing secret, so it lands in your shell
history. To avoid that, pipe it instead: `... | sudo sandgate ssh-guard setup -`.

**It lands in notification mode**, so this first step cannot lock you
out: logins are announced on your phone and an explicit Deny stops them,
but silence still lets them through. Verify, then commit:

```bash
sandgate ssh-guard test              # your phone should buzz
# open a NEW ssh session — it should ask, and let you in
sandgate ssh-guard enforce --yes     # now silence refuses logins
```

`enforce` refuses to run until you have an escape hatch. Prefer to see
the lines before they are applied? `sandgate ssh-guard install --manual`
prints them and touches nothing, and `install` alone wires up a config
you placed yourself.

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
  PAM-only path (still gated), on a key-only box it requires the key.
  Early versions always demanded a public key, which locked a real
  password-only server out during testing.
- Keep `timeoutSec` below sshd's `LoginGraceTime` (120s by default), or
  sshd hangs up before you have finished deciding.

## Other distributions

Tested on Ubuntu 24.04. The installer adapts to what it finds, but two
families deserve a warning rather than a promise:

**Debian/Ubuntu** — the tested path. `sshd_config.d` exists and is
included from the top of `sshd_config`, so the directives go in a
drop-in read before everything else.

**RHEL / Rocky / Alma 9** — same layout, so the drop-in path applies.
Node comes from `dnf` or NodeSource rather than `apt`. **SELinux is the
real obstacle**: `sshd_t` executing a Node binary and opening a network
connection during authentication is exactly what the default policy is
built to refuse, and denials surface as AVC messages in
`/var/log/audit/audit.log`. Expect to write a small policy module before
this works. Untested; treat it as a project, not a command.

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

## What it protects against, and what it does not

**It stops** a stolen key, a leaked password, a brute-forced login: the
attacker authenticates and still gets nowhere, and you find out
instantly.

**It does not stop** an already-root-compromised server — at that point
the attacker controls sshd, PAM and this guard alike. Nor does it replace
key hygiene, fail2ban or a firewall; it is the last gate, not the only
one.
