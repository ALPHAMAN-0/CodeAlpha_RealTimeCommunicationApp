import { asUserId, socketSchemas, type ConversationId, type MessageDTO, type PresenceDTO, type Seq } from '@rtc/shared';
import { memberIdsOf, watermarksFor } from '../../services/conversation.service.js';
import { getSince } from '../../services/message.service.js';
import { queryPresence } from '../../services/presence.service.js';
import { isMember } from '../membership.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

interface SyncPayload {
  cursors: Array<{ conversationId: ConversationId; lastSeq: Seq }>;
}

/**
 * Reconnect backfill.
 *
 * Batched across every open conversation so a reconnect costs one round trip
 * instead of one per room, and run on EVERY connect — not only when
 * connectionStateRecovery missed, because that recovery buffer is bounded and
 * process-local and must never be the thing correctness depends on.
 */
export function registerSyncHandlers(io: TypedServer, socket: TypedSocket): void {
  defineHandler<SyncPayload, {
    serverTime: number;
    conversations: Array<{
      conversationId: ConversationId;
      messages: MessageDTO[];
      hasMore: boolean;
      latestSeq: Seq;
      watermarks: Array<{ userId: ReturnType<typeof asUserId>; deliveredSeq: Seq; readSeq: Seq }>;
      presence: PresenceDTO[];
    }>;
  }>(
    io, socket, 'sync:since', socketSchemas['sync:since'],
    // Membership is checked PER CURSOR below, since this payload names many
    // conversations rather than one.
    {},
    async ({ payload }) => {
      const results = [];
      for (const cursor of payload.cursors) {
        const conversationId = String(cursor.conversationId);
        if (!(await isMember(socket.data.userId, conversationId))) continue; // silently skip
        const { messages, hasMore } = await getSince(conversationId, cursor.lastSeq);
        const watermarks = await watermarksFor(conversationId);
        const presence = await queryPresence(await memberIdsOf(conversationId));
        results.push({
          conversationId: cursor.conversationId,
          messages,
          hasMore,
          latestSeq: messages.length > 0 ? messages[messages.length - 1]!.seq : cursor.lastSeq,
          watermarks: watermarks.map((w) => ({
            userId: asUserId(w.userId),
            deliveredSeq: w.deliveredSeq,
            readSeq: w.readSeq,
          })),
          presence,
        });
      }
      return { serverTime: Date.now(), conversations: results };
    },
  );
}
