import { z } from 'zod';
import { LIMITS } from '../constants.js';
import type { FilePayload } from '../domain/message.js';
import { attachmentId, b64urlExact } from './common.js';

/** Longest name a mainstream filesystem will hold, in UTF-16 code units. */
const FILENAME_UNITS_MAX = 255;
/** RFC 6838 caps a type and a subtype at 127 characters each. */
const MIME_MAX = 255;
/** Chunks in a file of the largest size a client will send. */
const CHUNKS_MAX = Math.ceil(LIMITS.UPLOAD_BYTES_MAX / LIMITS.FILE_CHUNK_BYTES);

/**
 * The decrypted body of a `kind: 'file'` message.
 *
 * This is the one payload the server can never validate: it is sealed by one
 * member and opened by another, so nothing in `socketSchemas` ever sees it. A
 * hostile member can put any JSON at all inside a correctly signed envelope,
 * which makes the RECEIVING client the trust boundary. The shape is checked
 * here before a single field reaches the renderer or the chunk decryptor —
 * `filename: {}` would otherwise throw during render and take the whole
 * conversation view down for everyone in the room.
 *
 * Unknown keys are stripped rather than rejected, unlike the wire schemas:
 * two members can be running different client versions, and a field added
 * later must not make an attachment unreadable for the older one.
 */
export const filePayloadSchema = z.object({
  attachmentId: attachmentId(),
  /** Bound into every chunk's AAD. Absent only on payloads that predate it. */
  fileId: z.string().min(1).max(64).optional(),
  filename: z.string().min(1).max(FILENAME_UNITS_MAX),
  mime: z.string().max(MIME_MAX),
  plainSize: z.number().int().min(0).max(LIMITS.UPLOAD_BYTES_MAX),
  chunkCount: z.number().int().min(1).max(CHUNKS_MAX),
  ivPrefix: b64urlExact(4, 'ivPrefix'),
  sha256: b64urlExact(32, 'sha256'),
  fileKey: b64urlExact(32, 'fileKey'),
  caption: z.string().max(LIMITS.MESSAGE_TEXT_MAX).optional(),
});

/**
 * Parse the plaintext of a file message.
 *
 * Throws on anything that is not a well-formed payload, including text that
 * is not JSON at all. Callers treat that exactly like a failed decryption:
 * the message is shown as unreadable instead of being trusted.
 */
export const parseFilePayload = (plaintext: string): FilePayload =>
  filePayloadSchema.parse(JSON.parse(plaintext));
