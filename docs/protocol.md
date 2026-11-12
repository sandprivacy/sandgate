# The sandgate wire protocol

Everything a client needs to be a sandgate approver: the phone app, a
second implementation, a watch, a desk button. The relay is a blind
courier — it forwards sealed blobs and holds no key — so a client is
defined entirely by the crypto below and eight HTTP calls.

Test vectors: [`protocol-vectors.json`](protocol-vectors.json). Verify
your crypto against them **before** writing any UI; a client that gets
the AAD wrong fails silently, looking like a network problem.

## 1. Crypto

**Key derivation.** The 32-byte pairing secret arrives base64url. Both
sides derive AES-256-GCM keys with HKDF-SHA256:

| Purpose | salt | info | key |
|---|---|---|---|
| Requests and decisions | `sandgate-pwa-v1` | `approval-channel` | 32 bytes |
| One-time pairing claim | `sandgate-pwa-v1` | `pairing-claim` | 32 bytes |

**Sealing.** AES-256-GCM, 12-byte random IV, the 16-byte tag **appended
to the ciphertext** (the WebCrypto layout). Plaintext is UTF-8 JSON. On
the wire:

```json
{ "iv": "<base64url, 12 bytes>", "ct": "<base64url, ciphertext || tag>" }
```

**Additional authenticated data** binds every message to one request and
one direction. Get this wrong and decryption fails, which is the point:

| Message | AAD |
|---|---|
| Request (gateway → phone) | `req:<requestId>` |
| Decision (phone → gateway) | `dec:<requestId>` |
| Pairing claim | `claim:<pairId>` |

Base64url everywhere means unpadded, `-` and `_`. Ids are 8–64
characters of `[A-Za-z0-9_-]`.

## 2. Pairing

The link the gateway prints:

```
https://<relay>/#p=<pairId>&c=<claimSecret>&n=<display name>
```

`c=` is a **one-time claim**, not the channel secret. Collect it once:

```
GET /api/claim?pairId=<pairId>   →  200 { "payload": <sealed> }  |  404 (used or expired)
```

Open the payload with the claim key and AAD `claim:<pairId>`; inside is
`{ "secret": "<channel secret>", "name": "<display name>" }`. Store
`{ pairId, secret, name }` and never send the secret anywhere again. The
relay drops the blob after the first read, and after ten minutes.

Older gateways print `#p=<pairId>&s=<secret>` — the secret directly.
Accept both; prefer `c=`.

A client may hold several pairings (a laptop, several servers) and shows
their requests together.

## 3. Requests and decisions

```
POST /api/hello        { pairId }                       announce presence
GET  /api/pending?pairId=<id>                           → [ { requestId, payload, ts, decisions, needed } ]
GET  /api/pending?pairIds=<id>,<id>,…                   → { byPair: { <id>: [ … ] } }   (≤ 64 ids)
POST /api/decision     { pairId, requestId, payload }    → 200 | 404 (expired, abandoned, unknown)
GET  /api/events?pairId=<id>  |  ?pairIds=<id>,…        Server-Sent Events: "request", "decision", "status"
                                                        data: { "pairId": … } names the vault that changed
POST /api/subscribe    { pairId, subscription }          Web Push only (see §5)
POST /api/unsubscribe  { pairId, endpoint }              this device stops ringing for that vault
```

A device with several vaults should use the `pairIds` forms: one stream
and one read, whatever the number of vaults. Poll `/api/pending` on load,
whenever an SSE event arrives and whenever the stream (re)opens; keep a
slow poll even with a live stream (a stream can look open on a dead
network). A failed read says nothing about the requests: keep showing
them. A request stays listed until enough decisions arrive (`decisions`
of `needed`) or until it expires, so a client must remember which ones
**it** answered and stop showing those.

The gateway posts `{ pairId, requestId, payload, needed, ttlSec }` to
`/api/request`. `ttlSec` is how long it will wait: past it the request is
no longer listed nor counted against the pairing's limit (a gateway
killed mid-wait never calls `/api/abandon`). Posting the same
`requestId` again is a no-op, so a gateway may retry a request whose
answer it never received.

**Retrying.** A 5xx, a dropped connection and a `429` whose body says
`"retryable": true` (the per-address limit) are transient: retry with
backoff, with the same sealed payload. A `429` without it is the
per-pairing flood guard, and final. The per-address limit applies only
to calls about pairings the relay does not know in use; the client
address is the peer; from Cloudflare's published ranges,
`CF-Connecting-IP`; from a local proxy, the rightmost `X-Forwarded-For`
hop that is not a private address (and `CF-Connecting-IP` when that hop
is Cloudflare's). Never the leftmost hop: the client writes that one.

**Request plaintext** (sealed, AAD `req:<requestId>`):

```jsonc
{
  "kind": "approval" | "input" | "enroll",
  "title": "SSH login: root@vps-prod",
  "body": "From 82.x.x.x. Approve to let this session in.",  // optional
  "timeoutSec": 60,
  "ts": 1757030400000,          // ms; the card expires at ts + timeoutSec
  "requireBiometric": false,
  "credentialId": "<base64url>", // present when requireBiometric
  "quorum": 1                    // devices that must approve
}
```

**Decision plaintext** (sealed, AAD `dec:<requestId>`):

```jsonc
{
  "requestId": "<same id>",
  "approved": true,
  "answer": "482913",        // kind "input" only, when approved
  "ts": 1757030410000,
  "deviceId": "<random, stable per device>",  // quorums count distinct devices
  "assertion": { ... },      // when requireBiometric — see §4
  "enrollment": { ... }      // kind "enroll" only — see §4
}
```

Rules that are not negotiable, because the gateway enforces them:

- A decision without a valid assertion, when `requireBiometric` is set,
  is **refused** — including for a typed answer. Sign, then send.
- `approved: false` is final for the whole request, whatever the quorum.
- Silence is a refusal. Nothing to send when the timer runs out.

## 4. Biometrics — plain WebAuthn

The challenge is derived from the request id by both sides:

```
challenge = base64url( SHA-256( "sandgate-webauthn-v1:" + requestId ) )
```

**Enrolment** (`kind: "enroll"`) creates a platform credential — rp id =
the relay's hostname, ES256 (`alg: -7`), `userVerification: "required"`
— and returns:

```json
{ "credentialId": "<b64u>", "publicKeySpki": "<b64u DER SPKI>", "clientDataJSON": "<b64u>" }
```

**Assertion** returns the four standard fields:

```json
{ "credentialId": "<b64u>", "authenticatorData": "<b64u>", "clientDataJSON": "<b64u>", "signature": "<b64u>" }
```

The gateway checks the ceremony type, the challenge, the origin
(`https://<relay host>`), the rp id hash, the user-presence and
user-verification flags, and the ECDSA signature over
`authenticatorData || SHA-256(clientDataJSON)`.

**This is ordinary WebAuthn**, which matters for native clients: an iOS
app using `ASAuthorizationPlatformPublicKeyCredentialProvider` with the
relay's hostname as relying party produces assertions this verifier
accepts with no change — and, because it is the same relying party, it
can use a passkey the web app enrolled. It needs the relay to serve

```
GET /.well-known/apple-app-site-association
{ "webcredentials": { "apps": ["<TEAMID>.<bundle id>"] } }
```

which the relay does when `SANDGATE_APPLE_APP` is set, and the app to
carry the `webcredentials:<relay host>` associated domain.

## 5. Waking the device

Web clients use Web Push (VAPID key from `GET /api/vapid`, subscription
posted to `/api/subscribe`). The push payload carries the sealed request
so a service worker can show the real title — Web Push payloads are
themselves end-to-end encrypted, so no push service sees it:

```json
{ "type": "approval", "pairId": "…", "requestId": "…", "payload": { "iv": "…", "ct": "…" } }
{ "type": "server", "pairId": "…", "state": "offline" | "online", "since": 1700000000000 }
```

The relay accepts a subscription only if its endpoint is `https` on the
default port at a browser push service (`fcm.googleapis.com`,
`*.push.apple.com`, `*.push.services.mozilla.com`, `*.notify.windows.com`,
plus what the operator lists in `SANDGATE_PUSH_HOSTS`), with `keys.p256dh`
and `keys.auth` as strings; it keeps those three fields and nothing else.
Anything else is a 400: the relay POSTs to that URL, and must not be
pointed at its own network.

Every device that subscribed to a pairing is pushed to (a pairing kept
one subscription before 0.9.1, so a second device silently took the
pushes from the first). Pushes go out with `Urgency: high`, and with a
TTL equal to the request's `ttlSec` (sent by the gateway in
`POST /api/request`; 600 s by default, clamped to 30–3600). A push
service answering 404 or 410 drops the subscription.

A native client cannot use this: APNs and FCM need the app's own
credentials. Two honest options, neither of which weakens the channel:

1. **Foreground only** — SSE while the app is open. No infrastructure,
   no wake-up.
2. **A wake-up proxy** — the relay tells a push service "device X has
   something", and the app fetches the sealed request from its own
   relay. The proxy learns that a device should wake, never what is
   asked or answered. This is how self-hosted Bitwarden and Home
   Assistant handle iOS, and it must be opt-in and documented.

## 6. Housekeeping

```
GET  /api/pair-status?pairId=<id>   { subscribed, seen, claimed, claimPending }
POST /api/abandon { pairId, requestId }   a gateway that stopped waiting
GET  /api/health                    { ok, version, server }   (server: last release that changed ssh-guard)
GET  /api/metrics                   Prometheus text, operator only: Authorization: Bearer <token>, else 404
```

Server heartbeats (`sandgate ssh-guard heartbeat`, every 5 minutes):

```
POST   /api/status { pairId, payload, intervalSec }   payload = seal(status, aad "status:<pairId>")
GET    /api/status?pairId=<id>   → { status: { payload, receivedAt, intervalSec } | null, now, quietAfterMs }
DELETE /api/status { pairId }    uninstall: stopped on purpose, not dead
```

The relay keeps the latest blob only and refuses one closer than 20 s
to the previous (429). It can read nothing but *when* a pairing last
spoke: past `quietAfterMs` (three missed beats plus a minute, at least
ten minutes) it pushes `{ type: "server", state: "offline" }` once, and
`"online"` when the next beat arrives. The app ages a status by the
relay's clock, unless the sealed `ts` is more than ten minutes older
than `receivedAt` — an old heartbeat replayed does not pass for a live
server. The SSE stream also carries a `status` event.

A status not refreshed for 30 days is forgotten.

Rate limits: 12 requests/minute and 5 undecided per pairing; 240 API
calls/minute per client address for pairings not in use; 60 new
subscribed pairings or first heartbeats per address and hour. IPv6
addresses count per /64. A client that polls sensibly never meets them.

## 7. What a client must never do

- Send the pairing secret anywhere. It stays on the device.
- Show an approval it cannot decrypt — a blob that fails to open is not
  a request, it is noise or an attack.
- Approve on the user's behalf, batch approvals, or remember a "yes" for
  next time. Every tap is one decision.
- Send an approval for a `requireBiometric` request without an
  assertion. The gateway refuses it, and the user sees a failure they
  cannot explain.
