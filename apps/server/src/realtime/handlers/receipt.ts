import { asUserId, roomKey, socketSchemas, type ConversationId, type Seq } from '@rtc/shared';
import { setWatermark } from '../../services/conversation.service.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

/**
 * Read and delivery receipts as WATERMARKS.
 *
 * Not `readBy: [userId]` arrays on each message: in a group of n that would be
 * O(messages × members) updates and unbounded document growth on the hottest
 * collection. "Read by 3" is instead derived by comparing these two numbers
 * against the already-loaded participant list, which keeps messages
 * append-only and immutable.
 */
export function registerReceiptHandlers(io: TypedServer, socket: TypedSocket): void {
  const announce = (conversationId: string, readSeq: number, deliveredSeq: number) => {
    io.to(roomKey(conversationId)).emit('receipt:updated', {
      conversationId: conversationId as never,
      userId: asUserId(socket.data.userId),
      readSeq,
      deliveredSeq,
    });
  };

  defineHandler<{ conversationId: ConversationId; seq: Seq }, null>(
    io, socket, 'receipt:delivered', socketSchemas['receipt:delivered'],
    { requiresMembership: true },
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      const w = await setWatermark(conversationId, socket.data.userId, 'lastDeliveredSeq', payload.seq);
      announce(conversationId, w.readSeq, w.deliveredSeq);
      return null;
    },
  );

  defineHandler<{ conversationId: ConversationId; seq: Seq }, { unread: number }>(
    io, socket, 'receipt:read', socketSchemas['receipt:read'],
    { requiresMembership: true },
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      // Reading implies delivery, so advance both — otherwise a client that
      // only ever reports reads leaves delivery permanently behind.
      await setWatermark(conversationId, socket.data.userId, 'lastDeliveredSeq', payload.seq);
      const w = await setWatermark(conversationId, socket.data.userId, 'lastReadSeq', payload.seq);
      announce(conversationId, w.readSeq, w.deliveredSeq);
      return { unread: w.unread };
    },
  );
}
