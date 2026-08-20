import {
  RtcError, roomKey, socketSchemas,
  type CipherEnvelope, type ClientMsgId, type ConversationId,
  type MessageDTO, type MessageId, type Seq,
} from '@rtc/shared';
import { deleteMessage, getHistory, sendMessage } from '../../services/message.service.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

interface SendPayload {
  conversationId: ConversationId;
  clientMsgId: ClientMsgId;
  kind: 'text' | 'file';
  envelope: CipherEnvelope;
  sentAt: number;
  attachmentId?: string;
  replyToId?: string;
}

export function registerMessageHandlers(io: TypedServer, socket: TypedSocket): void {
  /**
   * Send a message.
   *
   * `serialize: true` is load-bearing. Socket.IO dispatches in arrival order,
   * but this handler awaits, so two rapid sends from the same socket could
   * otherwise interleave inside sequence allocation and the sender's own
   * messages would render out of order for everyone.
   */
  defineHandler<SendPayload, {
    messageId: MessageId; clientMsgId: ClientMsgId; seq: Seq; createdAt: number; deduped: boolean;
  }>(
    io, socket, 'message:send', socketSchemas['message:send'],
    { requiresMembership: true, requiresJoined: true, serialize: true },
    async ({ payload }) => {
      const { message, deduped } = await sendMessage({
        conversationId: String(payload.conversationId),
        senderId: socket.data.userId,
        clientMsgId: String(payload.clientMsgId),
        kind: payload.kind,
        envelope: payload.envelope,
        sentAt: payload.sentAt,
        ...(payload.attachmentId ? { attachmentId: String(payload.attachmentId) } : {}),
        ...(payload.replyToId ? { replyToId: String(payload.replyToId) } : {}),
      });

      /**
       * Fan out only for a genuinely new row.
       *
       * A replay must not re-broadcast: receivers dedupe on message id so it
       * would be harmless, but it would waste a round trip per retry and make
       * traffic graphs lie about how much is actually being said.
       *
       * `socket.to(...)` excludes THIS socket but still reaches the sender's
       * other tabs, which need the message like anyone else. This socket gets
       * it through the ack.
       */
      if (!deduped) {
        socket.to(roomKey(String(payload.conversationId))).emit('message:new', { message });
      }

      return {
        messageId: message.id,
        clientMsgId: message.clientMsgId,
        seq: message.seq,
        createdAt: message.createdAt,
        deduped,
      };
    },
  );

  defineHandler<
    { conversationId: ConversationId; beforeSeq?: number; limit?: number },
    { messages: MessageDTO[]; hasMore: boolean; oldestSeq: Seq | null }
  >(
    io, socket, 'message:history', socketSchemas['message:history'],
    { requiresMembership: true },
    ({ payload }) =>
      getHistory(String(payload.conversationId), {
        ...(payload.beforeSeq !== undefined ? { beforeSeq: payload.beforeSeq } : {}),
        ...(payload.limit !== undefined ? { limit: payload.limit } : {}),
      }),
  );

  defineHandler<
    { conversationId: ConversationId; messageId: MessageId },
    { messageId: MessageId; deletedAt: number }
  >(
    io, socket, 'message:delete', socketSchemas['message:delete'],
    { requiresMembership: true, requiresJoined: true },
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      const { seq, deletedAt } = await deleteMessage(
        conversationId, String(payload.messageId), socket.data.userId,
      );
      // Everyone, including the sender's other tabs.
      io.to(roomKey(conversationId)).emit('message:deleted', {
        conversationId: payload.conversationId,
        messageId: payload.messageId,
        seq,
        deletedAt,
      });
      return { messageId: payload.messageId, deletedAt };
    },
  );
}

export { RtcError };
