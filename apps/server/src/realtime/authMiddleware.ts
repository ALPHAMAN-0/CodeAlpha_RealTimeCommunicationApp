import { z } from 'zod';
import { THROTTLE, asUserId } from '@rtc/shared';
import { securityLog } from '../config/logger.js';
import { verifyAccessToken } from '../crypto/tokens.js';
import { User } from '../db/models/index.js';
import { isBanned } from './buckets.js';
import * as sidIndex from './sidIndex.js';
import type { TypedServer, TypedSocket } from './types.js';

const handshakeAuth = z.object({ token: z.string().min(20).max(4096) });

/**
 * Sockets authenticate with the in-memory access token from the handshake
 * `auth` payload — NEVER with a cookie.
 *
 * Cookies are attached to cross-site WebSocket handshakes and there is no
 * preflight to stop them, so cookie-authenticated sockets invite cross-site
 * WebSocket hijacking. Putting the token in `auth` (which travels in the
 * Engine.IO handshake body, not the query string, so it stays out of proxy
 * logs) avoids the whole class.
 */
export function installAuth(io: TypedServer): void {
  io.use((socket, next) => {
    const parsed = handshakeAuth.safeParse(socket.handshake.auth);
    if (!parsed.success) {
      next(new Error('AUTH_FAILED'));
      return;
    }
    verifyAccessToken(parsed.data.token)
      .then(async (claims) => {
        if (isBanned(claims.sub)) {
          securityLog.warn({ userId: claims.sub }, 'handshake refused: rate ban');
          next(new Error('RATE_BANNED'));
          return;
        }
        const user = await User.findById(claims.sub).select({ displayName: 1, avatarColor: 1 }).lean();
        if (!user) {
          next(new Error('AUTH_FAILED'));
          return;
        }

        // Identity is stamped by the server here and never read from a client
        // payload anywhere else. That single rule removes the entire
        // "spoof senderId" class of bug.
        socket.data.userId = asUserId(claims.sub);
        socket.data.sessionId = claims.sid;
        socket.data.displayName = user.displayName;
        socket.data.avatarColor = user.avatarColor;
        socket.data.tokenExpiresAt = (claims.exp ?? 0) * 1000;
        socket.data.rooms = new Set();
        socket.data.calls = new Set();

        sidIndex.add(socket as TypedSocket);
        armExpiry(socket as TypedSocket);
        next();
      })
      .catch(() => next(new Error('AUTH_FAILED')));
  });
}

interface Timers {
  warn?: NodeJS.Timeout;
  grace?: NodeJS.Timeout;
}
const timers = new WeakMap<object, Timers>();

/**
 * Warn before the access token expires, then drop the socket if it is not
 * renewed.
 *
 * A long-lived socket must not outlive its authorization — but it must also
 * not be torn down every ten minutes, because that would take the whole
 * WebRTC mesh with it. Hence warn-then-grace rather than hard expiry.
 */
export function armExpiry(socket: TypedSocket): void {
  const existing = timers.get(socket) ?? {};
  clearTimeout(existing.warn);
  clearTimeout(existing.grace);

  const msLeft = socket.data.tokenExpiresAt - Date.now();
  const warn = setTimeout(
    () => {
      socket.emit('auth:expiring', {
        expiresAt: socket.data.tokenExpiresAt,
        graceMs: THROTTLE.TOKEN_RENEW_GRACE_MS,
      });
      const grace = setTimeout(() => {
        socket.emit('session:expired', { reason: 'token-expired' });
        socket.disconnect(true);
      }, THROTTLE.TOKEN_RENEW_GRACE_MS);
      timers.set(socket, { ...timers.get(socket), grace });
    },
    Math.max(0, msLeft - THROTTLE.TOKEN_RENEW_LEAD_MS),
  );
  timers.set(socket, { warn });
}

export function clearExpiry(socket: TypedSocket): void {
  const t = timers.get(socket);
  if (t) {
    clearTimeout(t.warn);
    clearTimeout(t.grace);
    timers.delete(socket);
  }
}

/**
 * Renew in place after the client refreshed its access token.
 *
 * The renewed token must belong to the SAME user and session. Allowing the
 * identity on a live socket to change would let one account inherit another's
 * joined rooms and call membership.
 */
export async function renewSocketToken(socket: TypedSocket, token: string): Promise<boolean> {
  try {
    const claims = await verifyAccessToken(token);
    if (claims.sub !== socket.data.userId || claims.sid !== socket.data.sessionId) {
      securityLog.error({ userId: socket.data.userId }, 'reauth identity mismatch: disconnecting');
      socket.disconnect(true);
      return false;
    }
    socket.data.tokenExpiresAt = (claims.exp ?? 0) * 1000;
    armExpiry(socket);
    return true;
  } catch {
    return false;
  }
}

/**
 * Kill every socket on a revoked session.
 *
 * Wired to the auth service via `onSessionRevoked`, so logout and refresh-reuse
 * detection take effect immediately instead of waiting out the access token.
 */
export function revokeSession(sessionId: string, reason: 'revoked' | 'rate-banned'): void {
  for (const socket of sidIndex.forSession(sessionId)) {
    socket.emit('session:expired', { reason });
    socket.disconnect(true);
  }
}
