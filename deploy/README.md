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

## Watching it

- `GET /api/health` — `{ok, uptime_sec, pairings, active_requests}` for an uptime check.
- `GET /api/metrics` — Prometheus text: requests, decisions, push sent/failed, claims issued/collected, rate-limited calls, active requests, pairings. Nothing per user.
- Rate limits: 12 requests/min and 5 undecided per pairing (against flooding a phone), 240 API calls/min per client address (against invented pair ids). Behind a proxy the first `X-Forwarded-For` hop is the client.

## Backing it up

`relay-state.json` holds the VAPID key pair and every push subscription. Lose it and every phone must re-run `sandgate pair` (and, for servers, `ssh-guard pair`); nothing else is lost. Copy it with the rest of the host's backups, mode 0600:

```bash
cp /var/lib/sandgate/relay/relay-state.json /backup/sandgate-relay-state.json
```

## Notes

- The relay sees only sealed blobs (see "Security notes" in the main README); hosting it does not give the host access to any request content or decision.
- Back up `relay-state.json` if you care about not re-pairing phones after a rebuild; losing it only means users run `sandgate pair` again.
- One relay serves any number of users; each pairing is isolated by an unguessable pair id and its own end-to-end key.
