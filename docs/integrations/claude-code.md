# sandgate + Claude Code

The two-minute setup. Claude Code launches sandgate as an MCP server and
gets its five tools.

```bash
npm install -g @sandprivacy/sandgate
sandgate init                       # vault passphrase, optional backends
sandgate pair https://relay.sandgate.dev   # pair your phone (or self-host the relay)
sandgate add-totp github.com <base32-seed> # optional: your 2FA seeds

claude mcp add sandgate -e SANDGATE_PASSPHRASE=your-passphrase -- sandgate serve
```

Open a new Claude Code session — the tools are read at server start.

## Try it

- `Use sandgate to ask my approval before deleting anything in this repo.`
- `Ask me (via sandgate) which environment to deploy to.`
- `Log into my account; when 2FA comes up, get the code from sandgate.`

Your phone buzzes; you decide; the agent continues. `sandgate audit` shows
the trail.

## Tips

- The passphrase lives in the MCP server config, not in the model's
  context. Rotate it by re-running `claude mcp add` with the new value.
- Per-domain 2FA policy: `sandgate policy github.com auto` for trusted
  sites (no tap), `deny` to hard-block.
- A useful line for your `CLAUDE.md`: "Before any purchase, deletion, or
  message sent on my behalf, request approval through sandgate."
