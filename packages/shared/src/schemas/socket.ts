import { z } from 'zod';
import { LIMITS } from '../constants.js';
import {
  attachmentId, clientMsgId, conversationId, messageId, seq, socketId,
  strokeId, userId, clientTimestamp,
} from './common.js';
import { cipherEnvelopeSchema, epochRecordSchema } from './crypto.js';

const mediaStateSchema = z.strictObject({
  audio: z.boolean(),
  video: z.boolean(),
  screen: z.boolean(),
});

const conversationRef = z.strictObject({ conversationId: conversationId() });

export const socketSchemas = {
  // ── session ───────────────────────────────────────────────────────────────
  'session:reauth': z.strictObject({
    accessToken: z.string().min(20).max(4096),
  }),

  // ── rooms ─────────────────────────────────────────────────────────────────
  'room:join': conversationRef,
  'room:leave': conversationRef,

  // ── chat ──────────────────────────────────────────────────────────────────
  'message:send': z.strictObject({
    conversationId: conversationId(),
    clientMsgId: clientMsgId(),
    kind: z.enum(['text', 'file']),
    envelope: cipherEnvelopeSchema,
    sentAt: clientTimestamp(),
    attachmentId: attachmentId().optional(),
    replyToId: messageId().optional(),
  }).refine(
    // A file message without an attachment pointer is meaningless, and an
    // attachment on a text message would never be rendered.
    (v) => (v.kind === 'file') === (v.attachmentId !== undefined),
    { message: 'attachmentId is required for kind "file" and forbidden otherwise' },
  ),

  'message:history': z.strictObject({
    conversationId: conversationId(),
    beforeSeq: seq().optional(),
    limit: z.number().int().min(1).max(LIMITS.HISTORY_PAGE_MAX).optional(),
  }),

  'message:delete': z.strictObject({
    conversationId: conversationId(),
    messageId: messageId(),
  }),

  // ── backfill ──────────────────────────────────────────────────────────────
  'sync:since': z.strictObject({
    cursors: z
      .array(z.strictObject({ conversationId: conversationId(), lastSeq: seq() }))
      .min(1)
      .max(LIMITS.SYNC_CURSORS_MAX),
  }),

  // ── receipts ──────────────────────────────────────────────────────────────
  'receipt:delivered': z.strictObject({ conversationId: conversationId(), seq: seq() }),
  'receipt:read': z.strictObject({ conversationId: conversationId(), seq: seq() }),

  // ── typing ────────────────────────────────────────────────────────────────
  'typing:start': conversationRef,
  'typing:stop': conversationRef,

  // ── presence ──────────────────────────────────────────────────────────────
  'presence:query': z.strictObject({
    userIds: z.array(userId()).min(1).max(200),
  }),

  // ── calls ─────────────────────────────────────────────────────────────────
  'call:join': z.strictObject({
    conversationId: conversationId(),
    media: mediaStateSchema,
  }),
  'call:leave': conversationRef,

  /**
   * SDP is size-capped and passed through UNPARSED. An SDP mangler is a
   * parser attack surface and a source of subtle interop breakage; membership
   * authorization in the handler is what makes pass-through safe.
   */
  'rtc:describe': z.strictObject({
    conversationId: conversationId(),
    to: socketId(),
    description: z.strictObject({
      type: z.enum(['offer', 'answer', 'pranswer', 'rollback']),
      sdp: z.string().max(LIMITS.SDP_MAX).optional(),
    }),
  }),

  'rtc:ice': z.strictObject({
    conversationId: conversationId(),
    to: socketId(),
    candidate: z.strictObject({
      candidate: z.string().max(LIMITS.ICE_CANDIDATE_MAX),
      sdpMid: z.string().max(64).nullish(),
      sdpMLineIndex: z.number().int().min(0).max(64).nullish(),
      usernameFragment: z.string().max(256).nullish(),
    }),
  }),

  'rtc:media-state': z.strictObject({
    conversationId: conversationId(),
    state: mediaStateSchema,
  }),

  // ── whiteboard ────────────────────────────────────────────────────────────
  'wb:op': z.strictObject({
    conversationId: conversationId(),
    kind: z.enum(['stroke', 'undo', 'redo', 'clear']),
    strokeId: strokeId().optional(),
    chunk: z.number().int().min(0).max(100_000).optional(),
    done: z.boolean().optional(),
    envelope: cipherEnvelopeSchema.optional(),
  }).superRefine((v, ctx) => {
    // The op kind and its fields must agree, or the server would store ops it
    // can neither authorize (undo without a strokeId) nor replay.
    if (v.kind === 'stroke') {
      if (!v.envelope) ctx.addIssue({ code: 'custom', message: 'stroke requires an envelope' });
      if (!v.strokeId) ctx.addIssue({ code: 'custom', message: 'stroke requires a strokeId' });
      if (v.chunk === undefined) ctx.addIssue({ code: 'custom', message: 'stroke requires a chunk index' });
    }
    if ((v.kind === 'undo' || v.kind === 'redo') && !v.strokeId) {
      ctx.addIssue({ code: 'custom', message: `${v.kind} requires a strokeId` });
    }
    if (v.kind === 'clear' && (v.envelope || v.strokeId)) {
      ctx.addIssue({ code: 'custom', message: 'clear takes no strokeId or envelope' });
    }
  }),

  'wb:sync': z.strictObject({
    conversationId: conversationId(),
    sinceSeq: seq(),
  }),

  'wb:cursor': z.strictObject({
    conversationId: conversationId(),
    x: z.number().int().min(0).max(LIMITS.SOCKET_PAYLOAD_MAX),
    y: z.number().int().min(0).max(LIMITS.SOCKET_PAYLOAD_MAX),
  }),

  // ── group keys ────────────────────────────────────────────────────────────
  'epoch:publish': z.strictObject({
    conversationId: conversationId(),
    epoch: epochRecordSchema,
  }),
  'epoch:get': z.strictObject({
    conversationId: conversationId(),
    epoch: z.number().int().min(1).max(1_000_000),
  }),

  // ── files ─────────────────────────────────────────────────────────────────
  'file:upload-progress': z.strictObject({
    conversationId: conversationId(),
    clientMsgId: clientMsgId(),
    progress: z.number().min(0).max(1),
  }),
} as const;

export type SocketSchemas = typeof socketSchemas;
export type ValidatedEvent = keyof SocketSchemas;

/**
 * Every client->server event name that must have a schema.
 *
 * A test asserts this list matches both the ClientToServerEvents interface and
 * the handlers actually registered on the server, so an unvalidated event
 * cannot be added quietly six months from now.
 */
export const VALIDATED_EVENTS = Object.keys(socketSchemas) as ValidatedEvent[];
