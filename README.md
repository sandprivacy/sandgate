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

## The four tools

- **`request_approval`** — "May I pay €300 on this site?" → push to your phone → approve/deny. No answer = denied.
- **`get_totp`** — the current 6-digit code for a domain. Per-domain policy: `auto` (trusted sites), `approve` (buzz first — the default), or `deny`. The seed itself is never exposed.
- **`create_identity`** — a disposable email inbox so the agent can sign up for services without your real address.
- **`wait_for_verification`** — long-polls that inbox and returns the extracted verification code and links the moment they arrive.

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
3. **Self-hosted.** Runs on your machine; the vault and the audit trail never leave it. The email backend is pluggable ([sandmail](https://sandmail.dev) works out of the box; generic IMAP is on the roadmap).
4. **Everything audited.** If an agent asked for it, it's in the log.

## Roadmap

- [ ] Dedicated mobile PWA with end-to-end-encrypted web push (replaces the Telegram MVP)
- [ ] Generic IMAP backend for verification emails
- [ ] `sandgate audit` — pretty-print and filter the audit trail
- [ ] Team policies (shared vault, multiple approvers)
- [ ] Framework guides: browser-use, LangGraph, Agno

## License

AGPL-3.0. Part of the [sandprivacy](https://github.com/sandprivacy) suite — your data and your agents, under your control.
