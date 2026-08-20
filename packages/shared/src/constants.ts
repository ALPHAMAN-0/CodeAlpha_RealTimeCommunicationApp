/**
 * Limits and timings imported by BOTH client and server.
 *
 * The point of the shared import is that a client can never optimistically
 * accept something the server will reject, and a reviewer can find every
 * magic number in one file.
 */

export const CRYPTO_ALG = 'RTC/v1' as const;
/** Human-readable, goes in docs and in the UI's "about encryption" panel. */
export const CRYPTO_ALG_FULL = 'RTC/v1: ECDH-P256 + HKDF-SHA256 + AES-256-GCM' as const;

export const LIMITS = {
  DISPLAY_NAME_MAX: 40,
  EMAIL_MAX: 254,
  /** Plaintext cap. Ciphertext is larger; SOCKET_PAYLOAD_MAX is the real ceiling. */
  MESSAGE_TEXT_MAX: 4_000,
  /** base64url ciphertext cap for one message envelope. */
  CIPHERTEXT_MAX: 16_384,
  HISTORY_PAGE_MAX: 100,
  HISTORY_PAGE_DEFAULT: 50,
  SYNC_PER_CONV_MAX: 200,
  SYNC_CURSORS_MAX: 50,
  ROOM_TITLE_MAX: 80,
  GROUP_MEMBERS_MAX: 32,

  WB_POINTS_PER_CHUNK_MAX: 64,
  WB_SYNC_PAGE: 500,
  /** Ops retained per board before the oldest are dropped and `truncated` is set. */
  WB_OPS_MAX: 10_000,

  UPLOAD_BYTES_MAX: 25 * 1024 * 1024,
  /** Client-side encryption chunk. WebCrypto has no streaming AES-GCM. */
  FILE_CHUNK_BYTES: 256 * 1024,
  FILENAME_MAX: 200,

  /** Engine.IO rejects a larger frame before any handler sees it. */
  SOCKET_PAYLOAD_MAX: 1024 * 1024,
  SDP_MAX: 64_000,
  ICE_CANDIDATE_MAX: 1_024,
} as const;

export const CALL = {
  /**
   * Mesh hard cap. At n=4 that's 6 peer connections and 3 upstream encodings
   * per client (~3.6 Mbps up). n=8 would need 8.4 Mbps up, which exceeds a
   * typical consumer uplink — see docs/WEBRTC.md for where an SFU takes over.
   */
  MAX_PARTICIPANTS: 4,
  /**
   * Transceivers are created in EXACTLY this order on both peers, so incoming
   * tracks identify themselves by index and screen share needs no
   * renegotiation. Changing this order is a breaking wire change.
   */
  TRACK_SLOTS: ['mic', 'camera', 'screen'] as const,
} as const;

export type TrackSlot = (typeof CALL.TRACK_SLOTS)[number];

export const VIDEO_PROFILES = {
  /** n <= 2 */
  high: { width: 1280, height: 720, maxBitrate: 1_200_000 },
  /** n >= 3 — mesh uplink scales with n-1, so step down early. */
  low: { width: 640, height: 360, maxBitrate: 500_000 },
  /** The sharer's camera while a screen share is active (rendered as a thumbnail). */
  thumb: { width: 320, height: 180, maxBitrate: 150_000 },
} as const;

export const THROTTLE = {
  TYPING_START_MS: 3_000,
  TYPING_EXPIRE_MS: 5_000,
  WB_FLUSH_MS: 40,
  WB_CURSOR_MS: 100,
  PRESENCE_OFFLINE_GRACE_MS: 5_000,
  READ_RECEIPT_DEBOUNCE_MS: 400,
  /** Reject a client `sentAt` skewed further than this from server time. */
  CLOCK_SKEW_MAX_MS: 5 * 60 * 1000,
  /** Warn the client this long before its access token expires. */
  TOKEN_RENEW_LEAD_MS: 60_000,
  /** Grace after `auth:expiring` before the socket is dropped. */
  TOKEN_RENEW_GRACE_MS: 60_000,
} as const;

/** Per-socket token buckets. `points` is the burst; refill is points/durationMs. */
export const RATE = {
  'message:send': { points: 20, durationMs: 10_000 },
  'message:history': { points: 30, durationMs: 10_000 },
  'message:delete': { points: 20, durationMs: 60_000 },
  'wb:op': { points: 300, durationMs: 3_000 },
  'wb:sync': { points: 10, durationMs: 10_000 },
  'wb:cursor': { points: 200, durationMs: 10_000 },
  'typing:start': { points: 8, durationMs: 5_000 },
  'typing:stop': { points: 8, durationMs: 5_000 },
  'room:join': { points: 20, durationMs: 60_000 },
  'room:leave': { points: 20, durationMs: 60_000 },
  'rtc:describe': { points: 40, durationMs: 10_000 },
  'rtc:ice': { points: 300, durationMs: 10_000 },
  'rtc:media-state': { points: 40, durationMs: 10_000 },
  'call:join': { points: 10, durationMs: 60_000 },
  'call:leave': { points: 10, durationMs: 60_000 },
  'sync:since': { points: 6, durationMs: 10_000 },
  'presence:query': { points: 20, durationMs: 10_000 },
  'receipt:read': { points: 60, durationMs: 10_000 },
  'receipt:delivered': { points: 60, durationMs: 10_000 },
  'session:reauth': { points: 5, durationMs: 600_000 },
  'file:upload-progress': { points: 120, durationMs: 10_000 },
} as const;

export type RateLimitedEvent = keyof typeof RATE;

/** Catch-all bucket, applied to every event in addition to its own. */
export const RATE_GLOBAL = { points: 400, durationMs: 4_000 } as const;

/** Byte budget per socket for whiteboard traffic, on top of the op bucket. */
export const WB_BYTE_BUDGET = { bytes: 64 * 1024, durationMs: 1_000 } as const;

export const RATE_ESCALATION = {
  /** Violations within the window before the socket is disconnected. */
  VIOLATIONS_BEFORE_DISCONNECT: 3,
  VIOLATION_WINDOW_MS: 60_000,
  /** Disconnects within the window before the USER is refused new handshakes. */
  DISCONNECTS_BEFORE_BAN: 3,
  DISCONNECT_WINDOW_MS: 300_000,
  BAN_MS: 300_000,
} as const;

/** Whiteboard logical drawing surface. Integers only — never send CSS pixels. */
export const WB_CANVAS = { width: 4096, height: 2304 } as const;

/** Socket.IO room name helpers. Prefixed so namespaces can never collide. */
export const roomKey = (conversationId: string) => `conv:${conversationId}`;
export const userKey = (userId: string) => `user:${userId}`;
export const callKey = (conversationId: string) => `call:${conversationId}`;
export const sidKey = (sessionId: string) => `sid:${sessionId}`;
