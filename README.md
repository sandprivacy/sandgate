# sandgate

**The human gateway for AI agents.** Approvals, 2FA codes and email verification — one self-hosted MCP server. Your agent asks; your phone buzzes; you decide. Secrets never touch the LLM.

<!-- TODO(launch): hero GIF — agent hits a 2FA screen → phone buzzes → tap Approve → agent finishes the task -->

```
Agent: "I need the 2FA code for github.com"
   │
   ▼
sandgate ──► your phone: [✅ Approve] [❌ Deny]
   │
   ▼  (approved)
Agent gets: 483 921        ← a 30-second code
Agent never gets: the seed ← stays AES-256-GCM encrypted in your vault
```

## Why

Agents stall on everything that needs a human: TOTP prompts, verification emails, magic links, "are you sure?" moments. Today the workarounds are ugly — TOTP seeds in plaintext `.env` files, agents with full access to your inbox, or a human babysitting the terminal. sandgate replaces all of that with one MCP server any agent can call:

| | DIY (`.env` + custom tools) | sandgate |
|---|---|---|
| TOTP seed storage | plaintext | encrypted vault (AES-256-GCM, scrypt) |
| What the LLM sees | the seed | a 30-second code, after policy check |
| Sensitive actions | agent decides | your phone decides |
| Verification emails | build it yourself | `create_identity` + `wait_for_verification` |
| Audit trail | none | every request, decision and outcome |

## Quickstart

```bash
npm install -g @sandprivacy/sandgate
sandgate init                          # vault passphrase + Telegram bot + inbox backend
sandgate add-totp github.com JBSWY3DPEHPK3PXP
sandgate test-approval                 # your phone should buzz
```

Register it with your agent (Claude Code shown; any MCP client works):

```bash
claude mcp add sandgate -e SANDGATE_PASSPHRASE=your-passphrase -- sandgate serve
```

That's it. Your agent now has four new tools.

## The five tools

- **`request_approval`** — "May I pay €300 on this site?" → push to your phone → approve/deny. No answer = denied.
- **`ask_human`** — "What's the code you received by SMS?" → your phone shows an input field → your typed answer returns over the same encrypted channel. Covers SMS codes on your *real* number (no VoIP numbers that sites reject), security questions, choices.
- **`get_totp`** — the current 6-digit code for a domain. Per-domain policy: `auto` (trusted sites), `approve` (buzz first — the default), or `deny`. The seed itself is never exposed.
- **`create_identity`** — a disposable email inbox so the agent can sign up for services without your real address.
- **`wait_for_verification`** — long-polls that inbox and returns the extracted verification code and links the moment they arrive.

## Recipes

**CAPTCHAs.** sandgate will never auto-solve a CAPTCHA — that's the point of a CAPTCHA. The pattern that works today, by composition: tell your agent that on hitting one it should call `request_approval("CAPTCHA on <site> — solve it at the computer, then approve to continue")`. Your phone buzzes, you solve it where the browser is, you tap approve, the agent resumes. Same behavior as OpenAI's Operator, plus the notification.

## Face ID / Touch ID on sensitive approvals (optional)

A tap proves someone holds your unlocked phone. A biometric assertion
proves it was *you*, on the *enrolled* device — and the gateway verifies
it cryptographically instead of trusting the page:

```bash
sandgate enroll-biometric    # your phone asks; Face ID confirms
sandgate biometric on        # now every approval must be signed
```

Each approval carries a WebAuthn assertion over a challenge derived from
the request id, signed inside your phone's secure enclave. sandgate
stores only the public key and checks the signature, the relying party,
the challenge and the user-verification flag. Anything off — a replayed
assertion, another device, a missing biometric — is a denial, never an
approval. Off by default; `sandgate status` tells you where you stand.

Turning it back off (`sandgate biometric off`) asks for the vault
passphrase: the switch lives inside the encrypted vault, so editing a
config file — or running the command without the passphrase — cannot
weaken your setup.

## Your authenticator too, not just your agents'

The seeds are already in the vault, so stop opening an authenticator app
to read six digits:

```bash
sandgate totp                    # what's in the vault
sandgate totp github.com --copy  # code in your clipboard, seconds left on screen
```

After `sandgate protect`, this doesn't even ask for the passphrase — the
same OS-store lookup the MCP server uses. Read-only convenience;
anything that changes state still asks.

## From any script: `sandgate ask`

```bash
sandgate ask "Rotate the production DB password?" --body "Runs pg_rotate.sh" && ./pg_rotate.sh
CODE=$(sandgate ask "SMS code from the bank?" --input)     # the typed answer, on stdout
```

Exit 0 approved, 1 refused, 2 no answer. The same phone, the same
end-to-end channel, from cron, CI, or a shell one-liner.

## Teams: several devices, or a Slack channel

```bash
sandgate add-device          # a second phone on the same pairing
sandgate quorum 2            # two distinct devices must approve; one Deny refuses
sandgate connect-slack xoxb-… xapp-… "#approvals" --approvers U0123,U0456
sandgate channel slack       # send requests there instead of the phone
```

Slack requests are messages with Approve / Deny buttons (typed answers
through a modal), settled in place so the channel keeps the record.
Socket Mode, so no public URL. Slack does see the request text — that is
what a shared channel is for, and why a personal secret still goes to
the phone.

## Beyond agents: SSH logins that wait for your thumb

```bash
sandgate ssh-guard pair vps-prod         # on your workstation: prints one line
sudo sandgate ssh-guard setup eyJ...     # on the server: that line, and you are done
sandgate ssh-guard enforce --yes         # once verified, start blocking
```

No Node on the server? Each release ships standalone Linux binaries
(x64, arm64): one file under `/usr/local/bin`, same commands.

An SSH login pauses until you approve it on your phone. Duo does this
from their cloud, for a fee; ntfy plus a PAM script only *notifies* you
after the fact. This blocks, end-to-end encrypted, on your own
infrastructure — and the server holds nothing but its own pairing.

Read [docs/ssh-guard.md](docs/ssh-guard.md) before enabling it: the
danger is locking yourself out, not cryptography.

## Policies

```bash
sandgate policy github.com auto      # trusted: no buzz, code released instantly
sandgate policy mybank.com deny      # never
# everything else defaults to "approve" — your phone decides
```

## What's in `~/.sandgate/`

- `vault.enc` — TOTP seeds, bot token, API keys. AES-256-GCM, key derived from your passphrase with scrypt. Nothing sensitive is ever written in clear.
- `config.json` — policies and preferences, plaintext, hand-editable.
- `audit.jsonl` — append-only log of every request: which tool, which domain, what was decided, when. Codes and secrets are never logged.

## Design principles

1. **Zero disclosure.** The LLM sees derived, short-lived values (a 6-digit code, an approval verdict) — never seeds, tokens or passwords.
2. **Deny by default.** Unknown domains refuse. Unanswered approvals refuse. Policy gaps refuse.
3. **Self-hosted.** Runs on your machine; the vault and the audit trail never leave it. The email backend is pluggable: [sandmail](https://sandmail.dev) works out of the box (managed disposable inboxes), or bring your own mailbox with `sandgate connect-imap` — identities become plus-addressed aliases (`you+sg1a2b@domain`) and codes/links are extracted locally.
4. **Everything audited.** If an agent asked for it, it's in the log.

## The PWA approval channel (E2EE)

Telegram is the quick start; the PWA is the destination. Run your own relay and pair your phone:

```bash
sandgate relay                    # serves the PWA + forwards sealed blobs (port 8787)
sandgate pair https://your-relay  # prints a link + QR — open it on your phone
```

How the trust works: the link carries a **one-time claim**, not the secret. The gateway seals the channel secret under the claim and parks it on the relay, which hands it out once and forgets it after ten minutes — the link is dead after use, and the secret itself only ever lives in the URL **fragment** on the phone, never on a server. Both ends derive an AES-256-GCM key (HKDF); every approval request and every tap is sealed with the request id bound into the AAD. The relay stores and forwards blobs it cannot read, and cannot forge — a malicious relay can at worst drop or delay an answer, which is just a deny. A real phone needs the relay behind TLS (service workers require it); `http://localhost:8787` works for a desktop-browser test.

On the phone: scan the QR from inside the app ("+ add a vault" → *Scan a QR code*) or paste the link. Notifications show what is actually being asked — the sealed request rides inside the push, which is end-to-end encrypted, and the app decrypts it on the device — with Approve / Deny right on the lock screen for plain approvals (a switch in the app turns the details off). Several vaults (your laptop, your servers) live side by side under their own names.

Housekeeping: `sandgate pairings` lists what is paired and whether the relay has seen it; `sandgate unpair` revokes the phone channel; `sandgate pair` again rotates it.

Full threat model, including what it does *not* protect against and its
known weaknesses: [SECURITY.md](SECURITY.md).

## Security notes, honestly

- MCP clients launch servers non-interactively, so the vault passphrase must come from the environment. `SANDGATE_PASSPHRASE` (the value, cleartext in your config) protects the vault *at rest* — a stolen `vault.enc` alone is useless. For more, `SANDGATE_PASSPHRASE_CMD` runs a command whose stdout is the passphrase, so it can live in your OS secret store: Windows DPAPI (`ConvertFrom-SecureString` once, decrypt in the command), macOS `security find-generic-password`, Linux `secret-tool lookup`, or any password manager CLI. Either way, a fully compromised machine defeats any local secret store — that threat class is out of scope for all of them.
- Approval taps are only accepted from your own Telegram chat; anything else — including silence — is a deny. Agent-supplied text in approval messages is escaped and truncated.
- Email content handled by `wait_for_verification` is untrusted third-party input. The tool description tells agents so; only the extracted code and hint-filtered links are returned, never the raw body.
- Several agents can wait on you at once: approvals are served by a single dispatcher, first tap wins per request — or the first quorum, if you set one.
- The pairing link is a credential while it lives: ten minutes, one use. After that it is a 404. Someone who finds it inside the window and beats you to it holds the channel — your own claim then fails visibly, which is the cue to run `sandgate pair` again.

## Roadmap

- [x] Generic IMAP backend for verification emails (`sandgate connect-imap`)
- [x] `sandgate audit` — pretty-print the audit trail
- [x] Mobile PWA with end-to-end-encrypted push (`sandgate relay` + `sandgate pair`), multi-vault, on-device history
- [x] `ask_human` — free-text answers (SMS codes on your real number, security questions)
- [x] OS keychain for the vault passphrase (`SANDGATE_PASSPHRASE_CMD`, `sandgate protect`)
- [x] Face ID / Touch ID on approvals, verified server-side (`sandgate enroll-biometric`)
- [x] Blocking SSH approval (`sandgate ssh-guard`)
- [x] Slack approval channel with multiple approvers (`sandgate connect-slack`, `sandgate quorum`)
- [x] `sandgate ask` — the human step from any script
- [x] One-time pairing links, revocation (`sandgate unpair`), QR scanning in the app, lock-screen approvals
- [x] Standalone Linux binaries for servers; SELinux policy for RHEL-family systems
- [ ] Team policies (shared vault, centralized audit)
- [x] Framework guides: [Claude Code](docs/integrations/claude-code.md), [browser-use](docs/integrations/browser-use.md), [Playwright MCP](docs/integrations/playwright-mcp.md), [LangGraph](docs/integrations/langgraph.md)

## License

AGPL-3.0. Part of the [sandprivacy](https://github.com/sandprivacy) suite — your data and your agents, under your control.
