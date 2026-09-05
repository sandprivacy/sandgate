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
POST /api/decision     { pairId, requestId, payload }    → 200
GET  /api/events?pairId=<id>                            Server-Sent Events: "request", "decision"
POST /api/subscribe    { pairId, subscription }          Web Push only (see §5)
```

Poll `/api/pending` on load and whenever an SSE event arrives; fall back
to polling every few seconds if SSE is unavailable. A request stays
listed until enough decisions arrive (`decisions` of `needed`), so a
client must remember which ones **it** answered and stop showing those.

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
```

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
GET  /api/health                    { ok, uptime_sec, pairings, active_requests }
GET  /api/metrics                   Prometheus text
```

Rate limits: 12 requests/minute and 5 undecided per pairing; 240 API
calls/minute per client address. A client that polls sensibly never
meets them.

## 7. What a client must never do

- Send the pairing secret anywhere. It stays on the device.
- Show an approval it cannot decrypt — a blob that fails to open is not
  a request, it is noise or an attack.
- Approve on the user's behalf, batch approvals, or remember a "yes" for
  next time. Every tap is one decision.
- Send an approval for a `requireBiometric` request without an
  assertion. The gateway refuses it, and the user sees a failure they
  cannot explain.
