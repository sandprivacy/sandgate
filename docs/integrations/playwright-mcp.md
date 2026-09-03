# sandgate + Playwright MCP

Microsoft's Playwright MCP server drives a real browser; sandgate stands
at the human walls. Together in Claude Code they make the cleanest
"agent logs into a 2FA-protected site" setup — this is also how the
sandgate demo video is filmed.

```bash
claude mcp add sandgate -e SANDGATE_PASSPHRASE=... -- sandgate serve
claude mcp add playwright -- npx @playwright/mcp@latest
```

Store the site's TOTP seed once (from the "can't scan the QR?" setup key
shown when you enable 2FA):

```bash
sandgate add-totp github.com JBSWY3DPEHPK3PXP
```

Then, in a session:

> With playwright, go to github.com/login and sign in as demo-user with
> password <...>. When the two-factor prompt appears, get the current
> code from sandgate and enter it.

The login proceeds, the 2FA screen appears, your phone buzzes ("2FA code
for github.com"), you tap Approve, the agent types the 30-second code
and is in. The seed itself never left the encrypted vault, and the whole
exchange is one line in `sandgate audit`.

Use a dedicated demo/test account for anything you record or automate
routinely, and set `sandgate policy <domain> auto` for domains where the
tap adds nothing.
