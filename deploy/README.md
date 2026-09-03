# Deploying a public relay (relay.sandgate.dev)

The relay is stateless apart from `~/.sandgate/relay/relay-state.json` (VAPID keys + push subscriptions). It binds plain HTTP on localhost; TLS is terminated in front of it — phones require HTTPS for service workers and push.

## Option A — Cloudflare Tunnel (recommended when the domain is on Cloudflare)

No open ports, free TLS, works from any box (a VPS, or even a desktop for staging).

```bash
# on the relay host
npm i -g @sandprivacy/sandgate
sandgate relay 8787          # keep it running (see systemd unit below)

cloudflared tunnel login
cloudflared tunnel create sandgate-relay
cloudflared tunnel route dns sandgate-relay relay.sandgate.dev
cloudflared tunnel run --url http://localhost:8787 sandgate-relay
```

Cloudflare handles the certificate; `https://relay.sandgate.dev` is live as soon as the tunnel is up.

## Option B — Caddy on a VPS

```
# /etc/caddy/Caddyfile
relay.sandgate.dev {
    reverse_proxy localhost:8787
}
```

Point a DNS A record at the VPS; Caddy provisions TLS automatically.

## Keeping the relay up (systemd)

```ini
# /etc/systemd/system/sandgate-relay.service
[Unit]
Description=sandgate relay
After=network.target

[Service]
ExecStart=/usr/bin/sandgate relay 8787
Restart=always
RestartSec=3
User=sandgate
Environment=SANDGATE_HOME=/var/lib/sandgate

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -m -d /var/lib/sandgate sandgate
sudo systemctl enable --now sandgate-relay
```

## Notes

- The relay sees only sealed blobs (see "Security notes" in the main README); hosting it does not give the host access to any request content or decision.
- Back up `relay-state.json` if you care about not re-pairing phones after a rebuild; losing it only means users run `sandgate pair` again.
- One relay serves any number of users; each pairing is isolated by an unguessable pair id and its own end-to-end key.
