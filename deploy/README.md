# Deploying a public relay (relay.sandgate.dev)

The relay is stateless apart from `~/.sandgate/relay/relay-state.json` (VAPID keys, push subscriptions, the last heartbeat of each server). It speaks plain HTTP, on every interface unless `SANDGATE_RELAY_HOST` says otherwise (`127.0.0.1` behind a proxy on the same host); TLS is terminated in front of it — phones require HTTPS for service workers and push. See "Locking the host down" below before going public.

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

- `GET /api/health` — `{ok, version, server}` for an uptime check. Public, so it says nothing about use. `server` is the last release that changed what a server runs: the app offers servers an update against that, so a release that only touches the app or the relay does not ask every server to swap its binary.
- `GET /api/metrics` — Prometheus text: requests, decisions, push sent/failed, claims issued/collected, rate-limited calls, active requests, pairings, uptime. Nothing per user. **Off unless you set a token**, and then only with it:

  ```bash
  openssl rand -hex 32                       # once; keep it with your secrets
  # systemd: Environment=SANDGATE_METRICS_TOKEN=…   docker: -e SANDGATE_METRICS_TOKEN=…
  curl -H "Authorization: Bearer $TOKEN" https://relay.sandgate.dev/api/metrics
  ```

  Without the token, with a wrong one, or with none configured, the answer is the same 404. Wrong tokens count against the caller's per-address limit. A token shorter than 24 characters is refused at startup (metrics stay off, and the log says so). The header only: a token in a URL ends up in access logs. Before 0.9.1 these counters were public, which told anyone how much the relay was used and told an attacker whether their flood was being refused.
- Rate limits: 12 requests/min and 5 undecided (unexpired) per pairing, against flooding a phone; 240 API calls/min per client address for pairings not in use, against invented pair ids. Calls about pairings in use are not counted there. 60 new entries on disk per address and hour (a device subscribing to a vault it had not subscribed to, a server's first heartbeat), against filling the state file; at most 20,000 subscribed pairings and 5,000 servers. An IPv6 client counts per /64, the block one subscriber is given: per address, rotating the last bits walked around every limit. `sandgate_relay_rate_limited_total` climbing fast means real clients are being refused — look at how the relay sees addresses.
- A server that has not sent a heartbeat for 30 days is forgotten (its phone stops showing it).
- Client addresses:
  - From Cloudflare's published ranges (proxied DNS straight to the relay port): `CF-Connecting-IP`, which Cloudflare sets itself.
  - From a proxy on the host or the private network (nginx, Caddy, cloudflared): `X-Forwarded-For` **read from the right**, past the private addresses of your own proxies. A proxy appends what it saw after whatever the client wrote, so only the right end is trustworthy; before 0.9.1 the relay read the first entry, which any client could choose. If that hop is a Cloudflare address (nginx behind Cloudflare), `CF-Connecting-IP` names the client; reached directly, nginx's copy of that header is ignored.
  - Anything else connecting directly is taken at its own address; header values that are not addresses are ignored.
  - A TCP-level forwarder that rewrites no headers (socat, docker's userland proxy on loopback) makes every client look local, forged headers included. Publish the port normally (docker's default for outside traffic keeps the real address) or put an HTTP proxy in front.
  - Before 0.9.1, Cloudflare's edge was not recognised: every phone, gateway and server shared a few edge addresses and one limit.

## Locking the host down

The relay cannot read a request or forge a decision: everything that
matters is sealed end to end. What it does hold is **the phone app
itself** — the page and its worker, which hold the pairing secrets on the
phone. Whoever can alter what the relay serves can steal them. So:

- **TLS all the way to the relay.** Behind Cloudflare, the SSL/TLS mode
  must be **Full (strict)** (with a Cloudflare origin certificate on the
  host, e.g. Caddy or nginx), or the traffic must come through
  `cloudflared`. In **Flexible** mode, Cloudflare reaches the relay over
  plain HTTP across the internet, and anyone on that path can rewrite the
  app as it goes by. Check it in the Cloudflare dashboard: SSL/TLS →
  Overview.
- **Close the plain-HTTP port to the world.** Only your proxy (or
  Cloudflare) should reach it. With a proxy on the host, run the relay
  with `SANDGATE_RELAY_HOST=127.0.0.1` (in Docker: publish
  `-p 127.0.0.1:8787:8787`). With Cloudflare connecting straight to the
  port, allow only Cloudflare's ranges (cloudflare.com/ips) to it in the
  firewall. Note that Docker-published ports bypass `ufw`: filter them in
  the `DOCKER-USER` iptables chain, or publish on 127.0.0.1.
- **Keep `relay-state.json` mode 0600** (the relay writes it so) and out
  of images and repositories: it holds the VAPID private key.

What the relay already refuses on its own:

- Pushes go only to the browsers' push services (Google FCM, Apple,
  Mozilla, Microsoft WNS). A push subscription is a URL the client hands
  over and the relay then POSTs to; before 0.9.1 any https URL was
  accepted, so a stranger could make the relay knock on a service inside
  its own network. A self-hosted push service is added with
  `SANDGATE_PUSH_HOSTS=push.example.org` (comma-separated).
- The page cannot be framed by another site (`frame-ancestors 'none'`,
  `X-Frame-Options: DENY`), types are not sniffed, and no referrer
  leaves.

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
