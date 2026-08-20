import { asUserId, roomKey, socketSchemas, type ClientMsgId, type ConversationId } from '@rtc/shared';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

/**
 * Upload progress relay.
 *
 * Purely cosmetic — it lets peers see "Alice is sending a file… 40%" while a
 * large attachment uploads over REST. `volatile` because a stale progress
 * percentage is worthless: dropping it under backpressure is strictly better
 * than queueing it ahead of the messages that matter.
 */
export function registerFileHandlers(io: TypedServer, socket: TypedSocket): void {
  defineHandler<{ conversationId: ConversationId; clientMsgId: ClientMsgId; progress: number }, null>(
    io, socket, 'file:upload-progress', socketSchemas['file:upload-progress'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      socket.volatile.to(roomKey(String(payload.conversationId))).emit('file:upload-progress', {
        conversationId: payload.conversationId,
        userId: asUserId(socket.data.userId),
        clientMsgId: payload.clientMsgId,
        progress: payload.progress,
      });
      return null;
    },
  );
}
