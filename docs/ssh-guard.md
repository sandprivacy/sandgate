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

**On the server — one command:**

```bash
sudo install -d -m 700 /etc/sandgate
sudo tee /etc/sandgate/ssh-guard.json > /dev/null   # paste, Ctrl-D
sudo chmod 600 /etc/sandgate/ssh-guard.json

sudo sandgate ssh-guard install
```

That single command edits `/etc/pam.d/sshd` and `/etc/ssh/sshd_config`,
having first backed both up; if `sshd -t` rejects the result it puts
everything back and refuses to reload. It is idempotent, and
`sudo sandgate ssh-guard uninstall` removes exactly what it added.

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
prints them and touches nothing.

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
  entirely — keep it working.
- Keep `timeoutSec` below sshd's `LoginGraceTime` (120s by default), or
  sshd hangs up before you have finished deciding.

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
