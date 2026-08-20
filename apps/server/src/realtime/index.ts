import type { Server as HttpServer } from 'node:http';
import { Server } from 'socket.io';
import { LIMITS } from '@rtc/shared';
import { env } from '../config/env.js';
import { log } from '../config/logger.js';
import { onSessionRevoked } from '../services/auth.service.js';
import { handleConnect, handleDisconnect } from '../services/presence.service.js';
import { clearExpiry, installAuth, revokeSession } from './authMiddleware.js';
import { forgetSocket } from './buckets.js';
import { releaseQueues } from './handler.js';
import { registerAllHandlers } from './handlers/index.js';
import { activeCallCount, removeSocketEverywhere } from './registry/CallRegistry.js';
import * as sidIndex from './sidIndex.js';
import type { TypedServer } from './types.js';

export function createIo(httpServer: HttpServer): TypedServer {
  const io: TypedServer = new Server(httpServer, {
    path: '/socket.io',
    serveClient: false,
    // Engine.IO rejects an oversized frame before any handler runs.
    maxHttpBufferSize: LIMITS.SOCKET_PAYLOAD_MAX,
    pingInterval: 20_000,
    pingTimeout: 25_000,
    /**
     * An optimisation, never the correctness mechanism. It makes a brief
     * network blip invisible, but its buffer is bounded and process-local, so
     * the client still runs `sync:since` on EVERY connect.
     */
    connectionStateRecovery: { maxDisconnectionDuration: 120_000, skipMiddlewares: false },
    cors: { origin: env.ALLOWED_ORIGINS, credentials: false },
    /**
     * Socket.IO does NOT inherit Express's CORS configuration. This gate
     * rejects a disallowed origin at the HTTP upgrade, before any Engine.IO
     * parsing — forgetting it is the most common Socket.IO security bug.
     */
    allowRequest: (req, cb) => {
      const origin = req.headers.origin;
      cb(null, !origin || env.ALLOWED_ORIGINS.includes(origin));
    },
    cleanupEmptyChildNamespaces: true,
  });

  installAuth(io);

  // Logout and refresh-reuse detection must drop live sockets immediately,
  // not wait out the access token's remaining lifetime.
  onSessionRevoked((sessionId, reason) => revokeSession(sessionId, reason));

  io.on('connection', (socket) => {
    log.debug({ socketId: socket.id, userId: socket.data.userId }, 'socket connected');
    registerAllHandlers(io, socket);
    void handleConnect(io, socket.data.userId);

    socket.on('disconnect', (reason) => {
      log.debug({ socketId: socket.id, userId: socket.data.userId, reason }, 'socket disconnected');
      clearExpiry(socket);
      // Drop this socket from any call it was in, so peers stop trying to
      // negotiate with a connection that is gone.
      removeSocketEverywhere(socket.id);
      sidIndex.remove(socket);
      releaseQueues(socket.id);
      forgetSocket(socket.id);
      handleDisconnect(io, socket.data.userId);
    });
  });

  return io;
}

export const ioStats = (io: TypedServer) => ({
  sockets: () => ({ connected: sidIndex.totalSockets(), rooms: io.sockets.adapter.rooms.size }),
  activeCalls: activeCallCount,
});
