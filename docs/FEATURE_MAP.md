# Feature → file map

The CodeAlpha Task 4 brief, mapped to the code that implements it. Written so a
reviewer with ten minutes can find the evidence instead of hunting for it.

## Required features

### Real-time chat
| Concern | File |
|---|---|
| Wire contract | [`packages/shared/src/events/client-to-server.ts`](../packages/shared/src/events/client-to-server.ts) |
| Idempotent send, sequence allocation | [`apps/server/src/services/message.service.ts`](../apps/server/src/services/message.service.ts) |
| Handler with the full authorization chain | [`apps/server/src/realtime/handlers/message.ts`](../apps/server/src/realtime/handlers/message.ts) |
| Per-sender ordering mutex | [`apps/server/src/realtime/SerialQueue.ts`](../apps/server/src/realtime/SerialQueue.ts) |
| Persisted outbox, retry state machine | [`apps/web/src/realtime/Outbox.ts`](../apps/web/src/realtime/Outbox.ts) |
| Insert-by-seq timeline | [`apps/web/src/stores/messages.store.ts`](../apps/web/src/stores/messages.store.ts) |
| Reconnect backfill | [`apps/server/src/realtime/handlers/sync.ts`](../apps/server/src/realtime/handlers/sync.ts), [`apps/web/src/realtime/bindings.ts`](../apps/web/src/realtime/bindings.ts) |
| Receipts as watermarks | [`apps/server/src/realtime/handlers/receipt.ts`](../apps/server/src/realtime/handlers/receipt.ts) |
| Typing, with server-side expiry | [`apps/server/src/realtime/handlers/typing.ts`](../apps/server/src/realtime/handlers/typing.ts) |
| Multi-tab presence refcount | [`apps/server/src/services/presence.service.ts`](../apps/server/src/services/presence.service.ts), [`apps/server/src/realtime/sidIndex.ts`](../apps/server/src/realtime/sidIndex.ts) |
| Chat UI | [`apps/web/src/features/chat/ChatView.tsx`](../apps/web/src/features/chat/ChatView.tsx) |

### Video calling (multi-user)
| Concern | File |
|---|---|
| Perfect negotiation, fixed transceivers | [`apps/web/src/rtc/PeerLink.ts`](../apps/web/src/rtc/PeerLink.ts) |
| Mesh lifecycle, adaptive bitrate | [`apps/web/src/rtc/MeshManager.ts`](../apps/web/src/rtc/MeshManager.ts) |
| Signalling authorization | [`apps/server/src/realtime/handlers/rtc.ts`](../apps/server/src/realtime/handlers/rtc.ts) |
| Participant cap | [`apps/server/src/realtime/registry/CallRegistry.ts`](../apps/server/src/realtime/registry/CallRegistry.ts) |
| ICE / ephemeral TURN credentials | [`apps/server/src/http/routes/rtc.routes.ts`](../apps/server/src/http/routes/rtc.routes.ts) |
| Call UI, verification codes | [`apps/web/src/features/call/CallPanel.tsx`](../apps/web/src/features/call/CallPanel.tsx) |

### Screen sharing
Renegotiation-free via `replaceTrack` on a pre-created transceiver:
[`PeerLink.setLocalTrack`](../apps/web/src/rtc/PeerLink.ts) ·
[`MeshManager.startScreenShare`](../apps/web/src/rtc/MeshManager.ts) ·
[`localMedia.startScreenShare`](../apps/web/src/rtc/localMedia.ts)

### File sharing
| Concern | File |
|---|---|
| Chunked client-side encryption, positional AAD | [`packages/crypto/src/file.ts`](../packages/crypto/src/file.ts) |
| Upload / authenticated download | [`apps/server/src/http/routes/files.routes.ts`](../apps/server/src/http/routes/files.routes.ts) |
| Membership-based authorization | [`apps/server/src/services/attachment.service.ts`](../apps/server/src/services/attachment.service.ts) |
| Storage seam (GridFS + local disk) | [`apps/server/src/storage/`](../apps/server/src/storage/) |
| Send, download, magic-byte sniffing | [`apps/web/src/realtime/chat.ts`](../apps/web/src/realtime/chat.ts), [`ChatView.tsx`](../apps/web/src/features/chat/ChatView.tsx) |

### Whiteboard
| Concern | File |
|---|---|
| Total-ordered op log, per-author undo | [`apps/server/src/services/whiteboard.service.ts`](../apps/server/src/services/whiteboard.service.ts) |
| Handlers, byte budget, volatile cursors | [`apps/server/src/realtime/handlers/whiteboard.ts`](../apps/server/src/realtime/handlers/whiteboard.ts) |
| Stroke coalescing | [`apps/web/src/whiteboard/StrokeBatcher.ts`](../apps/web/src/whiteboard/StrokeBatcher.ts) |
| Two-canvas renderer | [`apps/web/src/whiteboard/CanvasRenderer.ts`](../apps/web/src/whiteboard/CanvasRenderer.ts) |
| Stroke encryption | [`apps/web/src/whiteboard/crypto.ts`](../apps/web/src/whiteboard/crypto.ts) |
| UI | [`apps/web/src/features/whiteboard/WhiteboardPanel.tsx`](../apps/web/src/features/whiteboard/WhiteboardPanel.tsx) |

### Data encryption
| Concern | File |
|---|---|
| AEAD primitives | [`packages/crypto/src/aead.ts`](../packages/crypto/src/aead.ts) |
| Canonical AAD packing | [`packages/crypto/src/aad.ts`](../packages/crypto/src/aad.ts) |
| Identity keys, wrapping, signed key log | [`packages/crypto/src/identity.ts`](../packages/crypto/src/identity.ts) |
| Password KDF, domain separation, recovery code | [`packages/crypto/src/account.ts`](../packages/crypto/src/account.ts) |
| 1:1 messages | [`packages/crypto/src/dm.ts`](../packages/crypto/src/dm.ts) |
| Group epochs, rekey | [`packages/crypto/src/group.ts`](../packages/crypto/src/group.ts) |
| Safety numbers, call fingerprints | [`packages/crypto/src/fingerprint.ts`](../packages/crypto/src/fingerprint.ts) |
| Non-extractable key storage, TOFU pins | [`apps/web/src/crypto/keystore.ts`](../apps/web/src/crypto/keystore.ts) |
| At-rest sealed fields, blind index | [`apps/server/src/crypto/sealedField.ts`](../apps/server/src/crypto/sealedField.ts) |
| Epoch orchestration | [`apps/server/src/services/epoch.service.ts`](../apps/server/src/services/epoch.service.ts) |

### User authentication
| Concern | File |
|---|---|
| Rotation, reuse detection, grace window | [`apps/server/src/services/auth.service.ts`](../apps/server/src/services/auth.service.ts) |
| Argon2id, concurrency cap, timing equalisation | [`apps/server/src/crypto/passwords.ts`](../apps/server/src/crypto/passwords.ts) |
| Tokens, CSRF binding, fake salts | [`apps/server/src/crypto/tokens.ts`](../apps/server/src/crypto/tokens.ts) |
| Routes and cookie policy | [`apps/server/src/http/routes/auth.routes.ts`](../apps/server/src/http/routes/auth.routes.ts) |
| CSRF middleware | [`apps/server/src/http/middleware/csrf.ts`](../apps/server/src/http/middleware/csrf.ts) |
| Socket handshake, mid-connection renewal | [`apps/server/src/realtime/authMiddleware.ts`](../apps/server/src/realtime/authMiddleware.ts) |
| Client session, single-flight refresh | [`apps/web/src/crypto/session.ts`](../apps/web/src/crypto/session.ts), [`apps/web/src/lib/api.ts`](../apps/web/src/lib/api.ts) |
| Auth + recovery-code UI | [`apps/web/src/features/auth/AuthScreen.tsx`](../apps/web/src/features/auth/AuthScreen.tsx) |

## Cross-cutting

| Concern | File |
|---|---|
| Fail-fast environment validation | [`apps/server/src/config/env.ts`](../apps/server/src/config/env.ts) |
| CSP, CORS (both allowlists), rate limits | [`apps/server/src/http/security.ts`](../apps/server/src/http/security.ts) |
| The one handler wrapper | [`apps/server/src/realtime/handler.ts`](../apps/server/src/realtime/handler.ts) |
| Redacting logger | [`apps/server/src/config/logger.ts`](../apps/server/src/config/logger.ts) |
| Demo seed | [`apps/server/src/scripts/seed.ts`](../apps/server/src/scripts/seed.ts) |

## Tests worth reading

| What it proves | File |
|---|---|
| AAD binding — one test per bound field | [`packages/crypto/src/messaging.test.ts`](../packages/crypto/src/messaging.test.ts) |
| A group member cannot forge as another | same file, `group sender authentication` |
| Rekey isolation both directions | same file, `rekey isolation` |
| Chunk truncation and reordering fail | [`packages/crypto/src/file.test.ts`](../packages/crypto/src/file.test.ts) |
| Key-log chain rejects an injected key | [`packages/crypto/src/identity.test.ts`](../packages/crypto/src/identity.test.ts) |
| Idempotent send, sequential and concurrent | [`apps/server/src/__tests__/chat.integration.test.ts`](../apps/server/src/__tests__/chat.integration.test.ts) |
| The server stores only ciphertext | same file |
| Reconnect backfill, both directions | same file |
| Every declared event has a handler | [`apps/server/src/__tests__/realtime.integration.test.ts`](../apps/server/src/__tests__/realtime.integration.test.ts) |
| Signalling authorization | same file |
