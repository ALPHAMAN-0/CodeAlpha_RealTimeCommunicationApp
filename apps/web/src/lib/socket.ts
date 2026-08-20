import { io, type Socket } from 'socket.io-client';
import type { Ack, ClientToServerEvents, ServerToClientEvents } from '@rtc/shared';
import { getAccessToken, refreshSession } from './api.js';

export type AppSocket = Socket<ServerToClientEvents, ClientToServerEvents>;

/**
 * The one socket instance.
 *
 * `retries: 0` is deliberate. Socket.IO can buffer and retry unacked packets
 * itself, which is tempting and wrong here: that buffer is in-memory only so
 * it does not survive a reload, and it offers no hook to reconcile optimistic
 * UI. The localStorage-backed Outbox does both. Two retry mechanisms would
 * double-send, so there is exactly one, and it is ours.
 */
export const socket: AppSocket = io({
  path: '/socket.io',
  transports: ['websocket', 'polling'],
  // WebSocket first, but still able to fall back behind a hostile proxy.
  tryAllTransports: true,
  reconnection: true,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 500,
  reconnectionDelayMax: 5_000,
  // Jitter: without it every client reconnects in lockstep and stampedes a
  // restarting server.
  randomizationFactor: 0.5,
  timeout: 10_000,
  autoConnect: false,
  retries: 0,
  auth: (cb) => cb({ token: getAccessToken() ?? '' }),
});

export function connectSocket(): void {
  if (!socket.connected) socket.connect();
}

export function disconnectSocket(): void {
  socket.disconnect();
}

export class SocketError extends Error {
  constructor(readonly code: string, message: string, readonly retryAfterMs?: number) {
    super(message);
    this.name = 'SocketError';
  }
}

/** Emit and await a typed ack, throwing a typed error on failure. */
export function emit<T>(event: keyof ClientToServerEvents, payload: unknown, timeoutMs = 10_000): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new SocketError('TIMEOUT', `${event} timed out`)), timeoutMs);
    (socket as unknown as {
      emit: (e: string, p: unknown, ack: (r: Ack<unknown>) => void) => void;
    }).emit(event as string, payload, (ack) => {
      clearTimeout(timer);
      if (ack.ok) resolve(ack.data as T);
      else reject(new SocketError(ack.error.code, ack.error.message, ack.error.retryAfterMs));
    });
  });
}

/** Emit without caring about the outcome — typing, cursors, progress. */
export function emitVolatile(event: keyof ClientToServerEvents, payload: unknown): void {
  (socket as unknown as { emit: (e: string, p: unknown) => void }).emit(event as string, payload);
}

/**
 * Renew the access token on the live socket instead of reconnecting.
 *
 * A reconnect would tear down every PeerConnection in an active call, so a
 * ten-minute token would mean a dropped call every ten minutes.
 */
export function installTokenRenewal(): () => void {
  const onExpiring = async () => {
    if (!(await refreshSession())) return;
    const token = getAccessToken();
    if (!token) return;
    await emit('session:reauth', { accessToken: token }).catch(() => undefined);
  };
  socket.on('auth:expiring', onExpiring);
  return () => socket.off('auth:expiring', onExpiring);
}
