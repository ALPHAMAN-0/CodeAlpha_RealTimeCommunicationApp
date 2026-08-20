# Security design

This document states what the system protects, what it does not, and why. It is
written to be checkable rather than reassuring — every claim below corresponds to
code you can read and, in most cases, a test that fails if it stops being true.

## Threat model

| # | Attack | Mitigation | Residual risk |
|---|---|---|---|
| 1 | **Stolen refresh token** (malware, stolen laptop, backup) | Rotation on every use; reuse detection revokes the whole family and disconnects every socket on that session; 14 d sliding / 30 d absolute cap; `__Host-` + `HttpOnly` + `Secure` + `SameSite=Strict`; only `sha256` stored server-side | The thief has ≤10 min of API access before the victim's next refresh trips detection. Detection is retroactive, not preventive. |
| 2 | **Stolen access token** | 10-minute TTL; held only in a JS closure, never in `localStorage`; `iss`/`aud` pinned; EdDSA with a `kid` | Not revocable within its 10-minute window. Accepted. |
| 3 | **XSS exfiltrating E2EE keys** — *the highest-impact threat here* | Identity private keys are **non-extractable** `CryptoKey` handles in IndexedDB; epoch keys unwrapped `extractable: false`; strict CSP with no `unsafe-inline` and `default-src 'none'`; Trusted Types (report-only); no `dangerouslySetInnerHTML`; uploads never served from the app origin unhardened | An XSS that survives can **use** the keys while the page is alive, and can exfiltrate decrypted plaintext. It cannot steal the long-term key for offline or future decryption. That is a real reduction, not elimination. |
| 4 | **Socket event spoofing / joining a room you are not in** | Handshake JWT verification; `socket.data.userId` stamped server-side and never read from a payload; `room:join` checks DB membership before `socket.join()`; every later handler re-checks DB membership **and** `socket.rooms`; targeted `emit` to a resolved socket rather than a room broadcast for signalling; `.strict()` Zod on every payload | Membership is cached for 30 s, but the cache is invalidated explicitly on every change, so removal takes effect immediately. |
| 5 | **Malicious room member** | Per-sender ECDSA signatures prevent impersonating another member; rekey on removal cuts off future messages; a new epoch on join prevents reading history; the member list is visible to all so silent additions are noticeable | A current member can read, screenshot and re-share everything. **Out of scope** — no E2EE system solves this, and any "screenshot prevention" claim would be a lie. |
| 6 | **File upload as a malware vector** | Files are ciphertext, so there is no server-side execution risk; storage names are server-generated ids with zero user input in the path; served only as `application/octet-stream` with `Content-Disposition: attachment`, `nosniff` and `CSP: default-src 'none'; sandbox`; downloads flow through `blob:` URLs, never a same-origin navigation; client-side magic-byte sniffing warns on an extension/content mismatch | **No server-side antivirus is possible on E2EE attachments.** This is the explicit, documented cost. The alternative (server-visible files + ClamAV) is a coherent design we did not choose. |
| 7 | **DoS by whiteboard or message flood** | Per-socket token buckets with byte budgets; `maxHttpBufferSize` 1 MB; stroke point caps; 40 ms client coalescing; escalation to disconnect and then a per-user connect ban; a 10 000-op board ceiling | Distributed floods from many authenticated accounts, and L3/L4 attacks, are **out of scope** — there is no CDN or WAF here. |
| 8 | **DoS via password hashing** | A semaphore caps concurrent Argon2 at `4 × CPU` with `503 + Retry-After`; layered login limits per IP *and* per account | Accepted for this deployment size. |
| 9 | **User enumeration** | Identical `401` for unknown-email and wrong-password; a dummy Argon2 verify equalises timing; `/kdf-params` returns a **deterministic** fake salt for unknown addresses | Timing is equalised, not proven constant-time end to end. |
| 10 | **MITM on key exchange** (server substitutes a public key) | Safety-number UI; TOFU pinning with a blocking "security code changed" banner that pauses sending; append-only signed key log where each rotation is counter-signed by the key it replaces | A server that is malicious **from first contact** wins unless users compare safety numbers. This is TOFU plus tamper-evidence, **not** key transparency. |
| 11 | **Server tampering with message metadata** | AAD binds `clientMsgId`, `conversationId`, `senderId`, `recipientId`, `keyVersion`, `sentAt` and `contentType`; per-sender ECDSA signature; the UI displays the client's authenticated `sentAt`, never the server's `createdAt` | The server can still **drop** or **reorder** messages. A per-sender hash chain would make that detectable; it is not implemented. |
| 12 | **Message replay** | Unique index on `(conversationId, clientMsgId)`; client-side dedupe; ±5 min `sentAt` skew rejection | Accepted. **AAD alone does not prevent replay** and this design does not pretend otherwise. |
| 13 | **CSRF on the cookie-backed refresh route** | `SameSite=Strict` + POST-only + `Sec-Fetch-Site` check + exact `Origin` match + HMAC-bound double-submit token + no CORS headers on `/api/auth/*` at all | Very low. |
| 14 | **Cross-site WebSocket hijacking** | Sockets never authenticate by cookie; the token travels in the handshake `auth` payload; an `allowRequest` origin gate; a separate Socket.IO CORS allowlist | Low. |
| 15 | **NoSQL operator injection** | Typed Zod parsing at every boundary; `strict: 'throw'`; `strictQuery`; `$where`/`$function` never used | Low. See the note on `sanitizeFilter` below. |
| 16 | **Participant IP disclosure via ICE** | Documented **in the call UI**, not just here; an optional room-wide relay-only mode via authenticated coturn with 300 s HMAC credentials | The default mode does leak IPs to peers. That is inherent to a mesh; the honest response is a visible notice and a toggle, not silence. |
| 17 | **TURN abused as an SSRF or scanning pivot** | `use-auth-secret` with short-lived credentials; `denied-peer-ip` for every RFC1918, loopback and link-local range; per-user and total quotas | Low. |
| 18 | **Malicious server ships backdoored JavaScript** | Strict CSP, content-hashed immutable assets | **Out of scope and unfixable in a browser app.** This is the fundamental limit of browser-delivered E2EE. |
| 19 | Compromised endpoint, keylogger, physical access, coercion | — | **Out of scope.** |
| 20 | Metadata and traffic analysis (who talks to whom, when, how much) | `lastSeen` coarsened to one minute; IPs hashed in logs | **Largely out of scope.** |

## What the encryption does and does not give you

| Missing property | Consequence | What we do instead |
|---|---|---|
| **No double ratchet** — no per-message forward secrecy, no post-compromise security | Compromising a device today exposes the whole current epoch | Rekey on every membership change, plus an age ceiling. The upgrade path is MLS (RFC 9420) or libsignal, explicitly out of scope. Hand-rolling a ratchet under deadline produces something *worse* than a clean, honestly-scoped epoch scheme. |
| **No deniability** | ECDSA signatures are transferable proof that Alice wrote a message | Accepted, and it is the right trade: without signatures any group member could forge as any other. |
| **Multi-device is painful** | One identity key per account, not per device. A lost device means a password change plus key rotation plus a full rekey | Documented. Per-device keys signed by an identity key is the real fix and is not built. |
| **MITM on first contact** | A malicious server can hand you a fabricated key before you have ever pinned the real one | Safety numbers, TOFU pinning, a signed append-only key log. Not key transparency. |
| **Server serves the JavaScript** | A compromised server can push backdoored crypto tomorrow | The fundamental limit. Strict CSP and content-hashed assets are partial; claiming more would be dishonest. |
| **Metadata is visible** | The server sees who talks to whom, when, and how often | Not addressed. |

## What is encrypted, and what is not

**End-to-end encrypted:** message bodies; attachment bytes *and* their filenames and MIME types (carried inside the message plaintext, because "Q3_layoffs.xlsx" leaks plenty on its own); whiteboard stroke geometry, colour and width; group titles.

**Server-visible by necessity:** conversation membership (encrypting a routing table the server must read would be theatre); presence; typing; message ids, sequence numbers, sender and conversation ids (all bound into the AAD, so tampering is *detectable*); read receipts; SDP and ICE candidates (transient, never persisted); whiteboard op *kind* and *stroke id* — the server needs those to authorize an undo, prune on clear and serve a late joiner, none of which is possible on opaque bytes.

**Server-visible but encrypted at rest:** email addresses, as AES-256-GCM sealed fields with an HMAC blind index so login remains a single query.

**End-to-end encrypted by construction:** audio, video and screen share. DTLS-SRTP is mandatory in WebRTC and in a mesh the media never touches our server. See the caveat in the next section.

## Media encryption: the caveat nobody mentions

WebRTC media genuinely is end-to-end encrypted. But the DTLS handshake authenticates against certificate fingerprints **carried in SDP that our signalling server relays**, so a malicious server could substitute its own and sit in the middle of the media undetected.

The app closes this: after connecting, it hashes both peers' DTLS fingerprints into a *call verification code* which participants compare out of band. Very few hobby projects do this; it is a real defence, not decoration.

## Encryption at rest: honest scope

Non-E2EE fields use application-level AES-256-GCM with AAD bound to `collection ‖ field ‖ documentId`, so a ciphertext cannot be copied from one document into another.

**We deliberately do not use MongoDB CSFLE.** With the `local` KMS provider the master key sits in the same `.env` as `MONGO_URI`, so CSFLE would add a native dependency, a schema map and a `mongocryptd` deployment step in exchange for exactly zero additional security — while breaking the one-command startup this project promises.

**What this protects:** a stolen database dump or backup. **What it does not protect:** compromise of the application host, which holds the key. There is no KMS in this project.

## A note on `sanitizeFilter`

Mongoose's `sanitizeFilter` is commonly recommended and is deliberately **off** here. It works by wrapping any filter value containing `$`-prefixed keys in `$eq` — and it cannot tell whose operator it is looking at, so it mangles the server's own `$in` and `$gt` exactly as readily as an injected `$ne`.

Living with it means wrapping every legitimate operator in `mongoose.trusted()` at dozens of sites, and that has a *worse* failure mode than going without: a developer who wraps a **user-supplied** value in `trusted()` reintroduces the vulnerability while appearing to have done the safe thing, and it reviews as correct.

The actual defence is typed parsing at every boundary. Every filter value in this codebase originates from a Zod-parsed primitive, and `z.string().email()` cannot become `{$ne: null}` no matter what arrives on the wire. That is enforced structurally by `validate()` for HTTP and `defineHandler` for sockets, and asserted by tests at both layers.

`express-mongo-sanitize` is also unused: it is unmaintained, and it assigns to `req.query`, which is a getter in Express 5.

## Security theatre we deliberately avoided

Knowing what *not* to build is part of the design.

1. **AES-KW for key wrapping**, chosen because the API is spelled `wrapKey`. It has no nonce and no associated data, so a wrapped blob can be swapped between users or rolled back to a retired version. AES-GCM with an AAD binding `userId` and `keyVersion` is simpler *and* strictly stronger.
2. **"AAD prevents replay."** It does not. Replay protection is a unique index plus client dedupe.
3. **Searchable or deterministic encryption for server-side message search.** It leaks word frequency and co-occurrence and is broken by frequency analysis on natural-language corpora. Search runs client-side instead.
4. **MongoDB CSFLE with a `local` KMS provider** — see above.
5. **Calling at-rest encryption "KMS-backed."** It protects a stolen dump. We say exactly that.
6. **A hand-rolled double ratchet.** A subtly broken ratchet is worse than a correct, honestly-scoped epoch scheme.
7. **A "signature" computed with the shared group key.** That is a MAC: every member could forge as every other. Per-sender ECDSA or it is not sender authentication.
8. **Client-side password hashing "so the server never sees the password"** — meaningless unless the derivation is domain-separated *and* the server re-hashes the proof, because whatever you send simply becomes the password. Both are done here.
9. **Public STUN servers "for privacy."** STUN's entire job is to discover and reveal your public IP to peers. Only relay-only mode hides it.
10. **Claiming media is E2EE without addressing the DTLS fingerprint relay** — see above.
11. **A CSP containing `'unsafe-inline'` in `script-src`**, presented as hardening. That disables the main thing CSP is for.

## Reporting

This is an educational project and not a production messenger. If you find a flaw, open an issue describing it.
