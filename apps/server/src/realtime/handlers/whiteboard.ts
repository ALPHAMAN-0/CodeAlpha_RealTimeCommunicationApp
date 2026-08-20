import {
  WB_CANVAS, asUserId, roomKey, socketSchemas,
  type CipherEnvelope, type ConversationId, type Seq, type StrokeId,
  type WhiteboardOpKind, type WhiteboardOpRecord,
} from '@rtc/shared';
import { appendOp, syncOps } from '../../services/whiteboard.service.js';
import { checkWhiteboardBytes } from '../buckets.js';
import { defineHandler } from '../handler.js';
import { RtcError } from '@rtc/shared';
import type { TypedServer, TypedSocket } from '../types.js';

interface OpPayload {
  conversationId: ConversationId;
  kind: WhiteboardOpKind;
  strokeId?: StrokeId;
  chunk?: number;
  done?: boolean;
  envelope?: CipherEnvelope;
}

export function registerWhiteboardHandlers(io: TypedServer, socket: TypedSocket): void {
  /**
   * Append a whiteboard op.
   *
   * `serialize: true` for the same reason as messages: the sequence number is
   * allocated across an await, and the op log's total order is the board's
   * only source of truth.
   */
  defineHandler<OpPayload, { seq: Seq }>(
    io, socket, 'wb:op', socketSchemas['wb:op'],
    { requiresMembership: true, requiresJoined: true, serialize: true },
    async ({ payload }) => {
      /**
       * A byte budget on top of the op-count bucket.
       *
       * Counting ops alone is not enough: 200 ops of 4 bytes and 200 ops of
       * 200 KB are the same op count and wildly different amounts of work.
       */
      const bytes = payload.envelope ? payload.envelope.ct.length : 64;
      const verdict = await checkWhiteboardBytes(socket.id, bytes);
      if (!verdict.allowed) {
        throw new RtcError('RATE_LIMITED', 'Drawing too fast', { retryAfterMs: verdict.retryAfterMs });
      }

      const conversationId = String(payload.conversationId);
      const { record, clearedAtSeq } = await appendOp({
        conversationId,
        authorId: socket.data.userId,
        kind: payload.kind,
        ...(payload.strokeId ? { strokeId: String(payload.strokeId) } : {}),
        ...(payload.chunk !== undefined ? { chunk: payload.chunk } : {}),
        ...(payload.done !== undefined ? { done: payload.done } : {}),
        ...(payload.envelope ? { envelope: payload.envelope } : {}),
      });

      if (clearedAtSeq !== undefined) {
        // Everyone, including the clearer's other tabs, and attributed so the
        // UI can name who wiped the board.
        io.to(roomKey(conversationId)).emit('wb:reset', {
          conversationId: payload.conversationId,
          clearedAtSeq,
          byUserId: asUserId(socket.data.userId),
        });
      } else {
        // Excludes this socket: it already rendered the stroke locally, and
        // waiting for the server would make the pen feel detached from the cursor.
        socket.to(roomKey(conversationId)).emit('wb:op', {
          conversationId: payload.conversationId,
          record,
        });
      }
      return { seq: record.seq };
    },
  );

  defineHandler<
    { conversationId: ConversationId; sinceSeq: Seq },
    { ops: WhiteboardOpRecord[]; hasMore: boolean; latestSeq: Seq; truncated: boolean }
  >(
    io, socket, 'wb:sync', socketSchemas['wb:sync'],
    { requiresMembership: true },
    ({ payload }) => syncOps(String(payload.conversationId), payload.sinceSeq),
  );

  /**
   * Live cursors.
   *
   * The one whiteboard signal that is neither persisted nor sequenced, and
   * `volatile` so it is DROPPED rather than queued under backpressure — a
   * stale cursor position is worthless, and buffering them would delay the
   * strokes that actually matter.
   */
  defineHandler<{ conversationId: ConversationId; x: number; y: number }, null>(
    io, socket, 'wb:cursor', socketSchemas['wb:cursor'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      // Clamp rather than reject: an out-of-range cursor is a rounding artefact
      // at a viewport edge, not an attack, and dropping it would make remote
      // cursors stutter near the border.
      const x = Math.min(Math.max(0, payload.x), WB_CANVAS.width);
      const y = Math.min(Math.max(0, payload.y), WB_CANVAS.height);
      socket.volatile.to(roomKey(String(payload.conversationId))).emit('wb:cursor', {
        conversationId: payload.conversationId,
        userId: asUserId(socket.data.userId),
        x,
        y,
      });
      return null;
    },
  );
}
