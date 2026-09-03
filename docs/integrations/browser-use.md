# sandgate + browser-use

browser-use handles the browser; sandgate handles the human. The
lowest-friction way to combine them today is through Claude Code, with
both running as MCP servers side by side:

```bash
claude mcp add sandgate -e SANDGATE_PASSPHRASE=... -- sandgate serve
# browser-use exposes an MCP server — see their docs for the exact command
```

Then, in a session:

> Open github.com and sign in as demo-user. Use browser-use for the
> browser. When the site asks for a 2FA code, get it from sandgate. If a
> CAPTCHA appears, request my approval and wait.

What happens: browser-use types the password (its own `sensitive_data`
mechanism — the model never sees it), sandgate supplies the 30-second
TOTP code (the seed never leaves the vault, and your phone can gate the
release), and anything unexpected lands on your phone as an approval or
a question.

## Division of labor

| Wall | Who handles it |
|---|---|
| Password fields | browser-use `sensitive_data` |
| TOTP prompts | sandgate `get_totp` (per-domain policy) |
| Email verification / magic links | sandgate `create_identity` + `wait_for_verification` |
| SMS codes on your real number | sandgate `ask_human` |
| "Are you sure?" moments | sandgate `request_approval` |
| CAPTCHAs | sandgate `request_approval` — you solve at the computer, tap to resume |

## Python-native setups

If you drive browser-use from Python rather than an MCP orchestrator,
you can expose sandgate's tools to your agent through any MCP client
library and register them as custom actions. The sandgate side is a
plain stdio MCP server (`sandgate serve` with `SANDGATE_PASSPHRASE` in
the environment); everything else is standard MCP plumbing.
