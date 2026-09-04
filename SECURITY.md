# Security

Reporting a vulnerability: open a [private security advisory](https://github.com/sandprivacy/sandgate/security/advisories/new)
on this repository. No bounty, but credit in the release notes and a fast
reply.

This document says what sandgate protects, what it does not, and where
the sharp edges are. It is written for someone deciding whether to trust
it, not to reassure.

## What it is

A gateway on your machine, a relay in the middle, an app on your phone.
Requests and decisions are sealed end to end; the relay carries blobs it
cannot read.

- **Vault** — AES-256-GCM, key from scrypt (N=2¹⁵) over your passphrase.
  Holds TOTP seeds, API keys, pairings, the enrolled biometric public
  key. Decrypted in memory only.
- **Channel** — the pairing secret travels once, in a URL *fragment*
  (never sent to a server). Both ends derive one AES-256-GCM key with
  HKDF-SHA256. Every message binds the request id in its AAD, so nothing
  can be replayed onto another request.
- **Biometrics (optional)** — a WebAuthn assertion from your phone's
  secure enclave, verified by the gateway: signature, relying party,
  challenge, origin and the user-verification flag. Enforcement lives in
  the encrypted vault, so turning it off costs the passphrase.

## What it protects against

- **The model seeing secrets.** Agents receive derived, short-lived
  values — a 30-second code, a yes/no. Never seeds, tokens or passwords.
- **A malicious or compromised relay.** It can delay or drop an answer,
  which is a refusal. It cannot read a request, forge an approval, or
  produce a biometric assertion. There is a test for each.
- **A stolen SSH key or password** (with `ssh-guard`): the attacker
  authenticates and still gets nowhere, and you find out immediately.
- **Notification fatigue.** The relay caps requests per pairing so a
  compromised gateway cannot bury your phone until you tap yes by reflex.
- **Failure.** Silence, timeouts, unreadable answers, dropped
  connections and unknown domains all refuse. Refusing is the default
  everywhere; `ssh-guard` is the one place you can deliberately choose
  otherwise, and it says so loudly.

## What it does not protect against

- **A compromised machine.** If an attacker runs code as you, they can
  read the vault once unlocked, or use `SANDGATE_PASSPHRASE_CMD` exactly
  as the MCP server does. No local secret store — OS keychain included —
  survives this; sandgate does not pretend otherwise.
- **A misleading request.** The approval text is written by whatever is
  asking. An agent under prompt injection can describe a harmful action
  in reassuring words, and you would be approving the words. sandgate
  guarantees *nothing happens without your tap*, not that what you read
  is true. Treat approvals like a bank SMS: check the amount, not the
  story.
- **A root-compromised server** (for `ssh-guard`): at that point the
  attacker owns sshd, PAM and the guard alike.
- **A stolen, unlocked phone**, unless you enable biometric approvals.
- **Relay outage.** With the defaults this means approvals fail, so
  agents stop and SSH refuses. That is safe, not available. `ssh-guard`
  offers `failOpen` and exempt users precisely because a server you
  cannot reach is its own kind of incident.

## Known weaknesses

Listed because you will find them anyway.

1. **No external audit.** Written fast, tested hard (60+ tests, including
   browser-level runs of the real page against a real relay and a
   simulated authenticator), reviewed by nobody but its author.
2. **A leaked `pairId` lets someone hijack push delivery.** The relay is
   blind by design, so it cannot tell your phone from an impostor when
   registering a push subscription. The consequence is notification
   theft and denial — never approval, since the attacker has no key.
   Re-pair to recover.
3. **One biometric credential**, with no revocation list. Enrolling a new
   device replaces the old one.
4. **The relay is a single point of failure** for approvals.
5. **`ssh-guard` needs Node on the server.** A standalone binary would
   shrink that surface; it is on the roadmap.
6. **The audit log is local and unsigned.** It records what was asked and
   decided, never codes, answers or secrets — but a root-compromised
   machine can rewrite it.

## If you run a public relay

It sees pairing ids, sealed blobs, push endpoints and IP addresses — no
plaintext, no keys. Put it behind TLS (service workers require it), rate
limit it, and keep `relay-state.json` (VAPID keys and push
subscriptions) at 0600. Losing that file costs your users a re-pair and
nothing more.
