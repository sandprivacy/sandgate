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

**On the server:**

```bash
sudo install -d -m 700 /etc/sandgate
sudo tee /etc/sandgate/ssh-guard.json > /dev/null   # paste, Ctrl-D
sudo chmod 600 /etc/sandgate/ssh-guard.json
sandgate ssh-guard install    # prints the exact lines to add
sandgate ssh-guard doctor     # checks them, and your escape hatch
sandgate ssh-guard test       # a fake login: your phone should buzz
```

The two lines that matter:

```
# /etc/pam.d/sshd — last auth line
auth required pam_exec.so quiet /usr/bin/sandgate ssh-guard approve

# /etc/ssh/sshd_config
AuthenticationMethods publickey,keyboard-interactive:pam
KbdInteractiveAuthentication yes
UsePAM yes
```

**That second block is not optional.** Public-key logins skip the PAM
auth stack entirely; without forcing `keyboard-interactive:pam`, your key
sails straight past the guard and you will believe it works when it does
not. `doctor` checks this explicitly.

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
