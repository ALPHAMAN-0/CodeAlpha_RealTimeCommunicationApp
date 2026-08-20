import type { TypedSocket } from './types.js';

/**
 * session id -> live sockets.
 *
 * Revocation has to be able to find every socket belonging to a killed
 * session. Without this index, revoking a refresh-token family would leave
 * already-connected sockets happily authenticated until their access token
 * expired — up to ten minutes of access after an explicit logout.
 */
const bySession = new Map<string, Set<TypedSocket>>();
const byUser = new Map<string, Set<TypedSocket>>();

export function add(socket: TypedSocket): void {
  const { sessionId, userId } = socket.data;
  let sockets = bySession.get(sessionId);
  if (!sockets) bySession.set(sessionId, (sockets = new Set()));
  sockets.add(socket);

  let userSockets = byUser.get(userId);
  if (!userSockets) byUser.set(userId, (userSockets = new Set()));
  userSockets.add(socket);
}

export function remove(socket: TypedSocket): void {
  const { sessionId, userId } = socket.data;
  const sockets = bySession.get(sessionId);
  if (sockets) {
    sockets.delete(socket);
    if (sockets.size === 0) bySession.delete(sessionId);
  }
  const userSockets = byUser.get(userId);
  if (userSockets) {
    userSockets.delete(socket);
    if (userSockets.size === 0) byUser.delete(userId);
  }
}

export const forSession = (sessionId: string): TypedSocket[] => [...(bySession.get(sessionId) ?? [])];
export const forUser = (userId: string): TypedSocket[] => [...(byUser.get(userId) ?? [])];

/**
 * How many live sockets a user has.
 *
 * This is the refcount that makes multi-tab presence correct: closing one of
 * two tabs must NOT mark the user offline.
 */
export const socketCount = (userId: string): number => byUser.get(userId)?.size ?? 0;
export const isOnline = (userId: string): boolean => socketCount(userId) > 0;
export const onlineUserIds = (): string[] => [...byUser.keys()];
export const totalSockets = (): number => [...byUser.values()].reduce((n, s) => n + s.size, 0);
