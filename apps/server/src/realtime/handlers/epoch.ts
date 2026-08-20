import { roomKey, socketSchemas, type ConversationId, type EpochRecord } from '@rtc/shared';
import { getEpoch, publishEpoch } from '../../services/epoch.service.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

export function registerEpochHandlers(io: TypedServer, socket: TypedSocket): void {
  /**
   * Publish the next group key epoch.
   *
   * Requires membership: only a member can key a room. The server validates
   * structure (right epoch number, every current member wrapped exactly once)
   * but not signatures — clients verify those themselves, because this server
   * is untrusted by design and a server-side check would only look reassuring.
   */
  defineHandler<{ conversationId: ConversationId; epoch: EpochRecord }, { epoch: number }>(
    io, socket, 'epoch:publish', socketSchemas['epoch:publish'],
    { requiresMembership: true },
    async ({ payload }) => {
      const conversationId = String(payload.conversationId);
      const result = await publishEpoch(conversationId, socket.data.userId, payload.epoch);
      // Everyone, including the publisher's other tabs, needs the new key.
      io.to(roomKey(conversationId)).emit('epoch:new', {
        conversationId: payload.conversationId,
        epoch: payload.epoch,
      });
      return result;
    },
  );

  /** Fetch an older epoch, e.g. to decrypt history after a reload. */
  defineHandler<{ conversationId: ConversationId; epoch: number }, { epoch: EpochRecord }>(
    io, socket, 'epoch:get', socketSchemas['epoch:get'],
    { requiresMembership: true },
    async ({ payload }) => ({
      epoch: await getEpoch(String(payload.conversationId), payload.epoch),
    }),
  );
}
