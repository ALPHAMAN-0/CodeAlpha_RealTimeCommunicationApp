import { Types } from 'mongoose';
import { Participant } from '../db/models/index.js';

/**
 * Short-lived membership cache.
 *
 * Membership is the hottest authorization read in the system — every message,
 * every whiteboard op, every SDP relay needs it. A 30-second cache removes
 * that round trip.
 *
 * The window it opens is real and is closed explicitly: `invalidate` is called
 * on every membership change, so a removed member loses signalling access
 * immediately rather than up to 30 seconds later.
 */
const TTL_MS = 30_000;

interface Entry {
  member: boolean;
  at: number;
}

const cache = new Map<string, Entry>();

const key = (userId: string, conversationId: string) => `${userId}|${conversationId}`;

export async function isMember(userId: string, conversationId: string): Promise<boolean> {
  const k = key(userId, conversationId);
  const hit = cache.get(k);
  const now = Date.now();
  if (hit && now - hit.at < TTL_MS) return hit.member;

  if (!Types.ObjectId.isValid(userId) || !Types.ObjectId.isValid(conversationId)) return false;
  const found = await Participant.exists({
    conversationId: new Types.ObjectId(conversationId),
    userId: new Types.ObjectId(userId),
    leftAt: null,
  });
  const member = found !== null;
  cache.set(k, { member, at: now });
  if (cache.size > 10_000) {
    for (const [ck, cv] of cache) if (now - cv.at > TTL_MS) cache.delete(ck);
  }
  return member;
}

/** Call on ANY membership change. This is what keeps the cache safe. */
export function invalidate(userId: string, conversationId: string): void {
  cache.delete(key(userId, conversationId));
}

export function invalidateConversation(conversationId: string): void {
  const suffix = `|${conversationId}`;
  for (const k of cache.keys()) if (k.endsWith(suffix)) cache.delete(k);
}

export function __resetMembershipCache(): void {
  cache.clear();
}
