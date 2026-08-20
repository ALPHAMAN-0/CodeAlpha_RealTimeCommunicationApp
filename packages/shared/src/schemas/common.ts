import { z } from 'zod';
import type {
  UserId, ConversationId, MessageId, AttachmentId, SocketId, StrokeId, ClientMsgId,
} from '../ids.js';
import { LIMITS } from '../constants.js';

const OID_RE = /^[0-9a-f]{24}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/**
 * Exact unpadded base64url length for `n` bytes.
 *
 * Unpadded base64url is a bijection on length, so a fixed-size field can be
 * pinned exactly rather than bounded loosely. Padding is impossible here
 * because '=' is not in B64URL_RE.
 */
const b64urlLen = (bytes: number) => Math.ceil((bytes * 4) / 3);

/**
 * base64url of an EXACT byte length — for IVs, salts, keys and signatures.
 *
 * Exactness matters: a 12-byte AES-GCM IV field that quietly accepts 13 bytes
 * accepts a value no correct client would send, which means it is only ever
 * reached by a malformed or hostile one.
 */
export const b64urlExact = (bytes: number, label = 'value') =>
  z
    .string()
    .length(b64urlLen(bytes), `${label} must be exactly ${bytes} bytes`)
    .regex(B64URL_RE, `${label} must be base64url`);

/**
 * base64url with an explicit byte ceiling.
 *
 * Every binary field on the wire is bounded. An unbounded ciphertext field is
 * a memory-exhaustion vector, and Zod is the right place to close it.
 */
export const b64url = (maxBytes: number, label = 'value') =>
  z
    .string()
    .max(b64urlLen(maxBytes), `${label} exceeds ${maxBytes} bytes`)
    .regex(B64URL_RE, `${label} must be base64url`);

export const userId = () =>
  z.string().regex(OID_RE, 'invalid user id').transform((v) => v as UserId);
export const conversationId = () =>
  z.string().regex(OID_RE, 'invalid conversation id').transform((v) => v as ConversationId);
export const messageId = () =>
  z.string().regex(OID_RE, 'invalid message id').transform((v) => v as MessageId);
export const attachmentId = () =>
  z.string().regex(OID_RE, 'invalid attachment id').transform((v) => v as AttachmentId);
export const clientMsgId = () =>
  z.string().regex(UUID_RE, 'clientMsgId must be a UUID').transform((v) => v as ClientMsgId);
export const strokeId = () =>
  z.string().regex(UUID_RE, 'strokeId must be a UUID').transform((v) => v as StrokeId);
/** Socket.IO ids are opaque short strings, not UUIDs. */
export const socketId = () =>
  z.string().min(8).max(64).regex(/^[A-Za-z0-9_-]+$/).transform((v) => v as SocketId);

/** Per-conversation sequence cursor. */
export const seq = () => z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);

/** Epoch-ms timestamp supplied by a client. Range-checked, never trusted. */
export const clientTimestamp = () => z.number().int().min(0).max(4_102_444_800_000);

export const email = () =>
  z.string().trim().toLowerCase().min(3).max(LIMITS.EMAIL_MAX).email('invalid email');

export const displayName = () => z.string().trim().min(1).max(LIMITS.DISPLAY_NAME_MAX);

/**
 * Guards against operator-injection reaching a query position.
 *
 * Typed parsing is the real defense (a `z.string()` cannot become
 * `{$ne: null}`); this is the belt-and-braces layer for free-form keys.
 */
export const safeKey = () =>
  z
    .string()
    .min(1)
    .max(64)
    .refine((v) => !v.startsWith('$') && !v.includes('.'), 'key may not start with $ or contain .');
