import { socketSchemas } from '@rtc/shared';
import { defineHandler } from '../handler.js';
import { renewSocketToken } from '../authMiddleware.js';
import type { TypedServer, TypedSocket } from '../types.js';

export function registerSessionHandlers(io: TypedServer, socket: TypedSocket): void {
  /**
   * Renew the access token on a live socket.
   *
   * This exists so token refresh does not require a reconnect — reconnecting
   * would tear down every PeerConnection in the call.
   */
  defineHandler<{ accessToken: string }, { userId: string; expiresAt: number }>(
    io, socket, 'session:reauth', socketSchemas['session:reauth'], {},
    async ({ payload }) => {
      const ok = await renewSocketToken(socket, payload.accessToken);
      if (!ok) {
        socket.emit('session:expired', { reason: 'token-expired' });
        socket.disconnect(true);
        throw new Error('reauth failed');
      }
      return { userId: socket.data.userId, expiresAt: socket.data.tokenExpiresAt };
    },
  );
}
