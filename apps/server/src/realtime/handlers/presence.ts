import { socketSchemas, type PresenceDTO, type UserId } from '@rtc/shared';
import { queryPresence } from '../../services/presence.service.js';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

export function registerPresenceHandlers(io: TypedServer, socket: TypedSocket): void {
  defineHandler<{ userIds: UserId[] }, { presence: PresenceDTO[] }>(
    io, socket, 'presence:query', socketSchemas['presence:query'], {},
    async ({ payload }) => ({ presence: await queryPresence(payload.userIds) }),
  );
}
