import {
  asConversationId, roomKey, socketSchemas, type ConversationId,
} from '@rtc/shared';
import { getCurrentEpoch, requireRekey } from '../../services/epoch.service.js';
import { getJoinState } from '../../services/conversation.service.js';
import { queryPresence } from '../../services/presence.service.js';
import { peersOf } from '../registry/CallRegistry.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

export function registerRoomHandlers(io: TypedServer, socket: TypedSocket): void {
  /**
   * Join a conversation.
   *
   * Idempotent: re-joining returns fresh state rather than an error, because a
   * client that reconnects mid-render must be able to re-sync without special
   * casing.
   *
   * Note `requiresMembership` but not `requiresJoined` — this IS the
   * authorization gate that adds the room to `socket.data.rooms`, so every
   * later handler can rely on that set meaning something.
   */
  defineHandler<{ conversationId: ConversationId }, unknown>(
    io, socket, 'room:join', socketSchemas['room:join'],
    { requiresMembership: true },
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      const state = await getJoinState(conversationId, socket.data.userId);

      await socket.join(roomKey(conversationId));
      socket.data.rooms.add(asConversationId(conversationId));

      const presence = await queryPresence(state.participants.map((p) => String(p.userId)));
      const epoch = state.conversation.type === 'group'
        ? await getCurrentEpoch(conversationId)
        : undefined;

      /**
       * If the group is waiting on a rekey and nobody was online when the
       * membership changed, the requirement was only recorded. Re-announcing
       * it on join is what lets the first member back in actually perform it.
       */
      if (state.conversation.rekeyPending) {
        void requireRekey(io, conversationId, 'member_added');
      }

      const peers = peersOf(conversationId);
      return {
        ...state,
        presence,
        call: { active: peers.length > 0, peers },
        ...(epoch ? { epoch } : {}),
      };
    },
  );

  defineHandler<{ conversationId: ConversationId }, null>(
    io, socket, 'room:leave', socketSchemas['room:leave'], {},
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      await socket.leave(roomKey(conversationId));
      socket.data.rooms.delete(asConversationId(conversationId));
      return null;
    },
  );
}
