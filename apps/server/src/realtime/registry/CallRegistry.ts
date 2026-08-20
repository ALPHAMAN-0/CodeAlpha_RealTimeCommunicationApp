import { env } from '../../config/env.js';
import type { CallPeerDTO, MediaState } from '@rtc/shared';
import { asSocketId, asUserId } from '@rtc/shared';

/**
 * Who is currently in each call.
 *
 * Keyed by SOCKET, not user: one person with two tabs is two independent
 * peers with two independent PeerConnections, and the mesh has to address
 * them separately.
 *
 * In-memory because a call is inherently ephemeral — if this process dies the
 * calls die with it, and persisting participants would only produce ghost
 * peers that never respond to an offer.
 */
interface Entry {
  socketId: string;
  userId: string;
  displayName: string;
  avatarColor: string;
  state: MediaState;
}

const calls = new Map<string, Map<string, Entry>>();

export const peersOf = (conversationId: string): CallPeerDTO[] =>
  [...(calls.get(conversationId)?.values() ?? [])].map((e) => ({
    socketId: asSocketId(e.socketId),
    userId: asUserId(e.userId),
    displayName: e.displayName,
    avatarColor: e.avatarColor,
    state: e.state,
  }));

export const participantCount = (conversationId: string): number =>
  calls.get(conversationId)?.size ?? 0;

/**
 * Add a peer, enforcing the mesh cap.
 *
 * The cap is a hard limit, not a suggestion: at n participants each client
 * uploads n-1 encodes of its own camera, so an unbounded room is a
 * self-inflicted denial of service on every participant's uplink and CPU.
 */
export function addPeer(conversationId: string, entry: Entry): { ok: boolean; full: boolean } {
  let room = calls.get(conversationId);
  if (!room) calls.set(conversationId, (room = new Map()));
  if (room.has(entry.socketId)) {
    room.set(entry.socketId, entry);
    return { ok: true, full: false };
  }
  if (room.size >= env.MAX_CALL_PARTICIPANTS) return { ok: false, full: true };
  room.set(entry.socketId, entry);
  return { ok: true, full: false };
}

export function removePeer(conversationId: string, socketId: string): boolean {
  const room = calls.get(conversationId);
  if (!room) return false;
  const existed = room.delete(socketId);
  if (room.size === 0) calls.delete(conversationId);
  return existed;
}

/** Drop a socket from every call it was in — used on disconnect. */
export function removeSocketEverywhere(socketId: string): string[] {
  const affected: string[] = [];
  for (const [conversationId, room] of calls) {
    if (room.delete(socketId)) {
      affected.push(conversationId);
      if (room.size === 0) calls.delete(conversationId);
    }
  }
  return affected;
}

export function setMediaState(conversationId: string, socketId: string, state: MediaState): boolean {
  const entry = calls.get(conversationId)?.get(socketId);
  if (!entry) return false;
  entry.state = state;
  return true;
}

export const isInCall = (conversationId: string, socketId: string): boolean =>
  calls.get(conversationId)?.has(socketId) ?? false;

export const activeCallCount = (): number => calls.size;

export function __resetCalls(): void {
  calls.clear();
}
