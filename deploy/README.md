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
- Rate limits: 12 requests/min and 5 undecided (unexpired) per pairing, against flooding a phone; 240 API calls/min per client address for pairings not in use, against invented pair ids. Calls about pairings in use are not counted there. `sandgate_relay_rate_limited_total` climbing fast means real clients are being refused — look at how the relay sees addresses.
- Client addresses: behind Cloudflare (proxied DNS straight to the VPS, or cloudflared on the host), the relay takes `CF-Connecting-IP` when the connection comes from Cloudflare's published ranges or from a local proxy. Behind another proxy on the host or the private network, the first `X-Forwarded-For` hop. Anything else connecting directly is taken at its own address. Before 0.9.1, Cloudflare's edge was not recognised: every phone, gateway and server shared a few edge addresses and one limit.

## Upgrading

The relay also serves the phone app, so upgrading the relay is how a fix
to the app reaches phones: restart it on the new version, and the page
and its worker (served `Cache-Control: no-cache`) load fresh on the next
open. What a phone has paired lives in the phone's own storage for the
relay's origin — an upgrade does not touch it; changing the domain does.

Keep `relay-state.json` across the upgrade (same `SANDGATE_HOME`, or the
same volume in Docker). Regenerated VAPID keys do not fail loudly: every
existing push subscription simply stops ringing.

## Backing it up

`relay-state.json` holds the VAPID key pair and every push subscription. Lose it and every phone must re-run `sandgate pair` (and, for servers, `ssh-guard pair`); nothing else is lost. Copy it with the rest of the host's backups, mode 0600:

```bash
cp /var/lib/sandgate/relay/relay-state.json /backup/sandgate-relay-state.json
```

## Notes

- The relay sees only sealed blobs (see "Security notes" in the main README); hosting it does not give the host access to any request content or decision.
- Back up `relay-state.json` if you care about not re-pairing phones after a rebuild; losing it only means users run `sandgate pair` again.
- One relay serves any number of users; each pairing is isolated by an unguessable pair id and its own end-to-end key.
