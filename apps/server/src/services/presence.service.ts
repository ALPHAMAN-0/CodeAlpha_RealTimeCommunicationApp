import { Types } from 'mongoose';
import { THROTTLE, asUserId, roomKey, type PresenceDTO } from '@rtc/shared';
import { Participant, User } from '../db/models/index.js';
import * as sidIndex from '../realtime/sidIndex.js';
import type { TypedServer } from '../realtime/types.js';

/** Coarsen last-seen to the minute. Second-precision activity is surveillance. */
const coarsen = (d: Date): number => Math.floor(d.getTime() / 60_000) * 60_000;

export const toPresenceDTO = (u: {
  _id: Types.ObjectId | string;
  presence: { status: 'online' | 'offline'; lastSeenAt: Date };
}): PresenceDTO => ({
  userId: asUserId(String(u._id)),
  status: u.presence.status,
  lastSeenAt: coarsen(u.presence.lastSeenAt),
});

/** Conversation ids whose members should hear about this user's presence. */
async function audienceRooms(userId: string): Promise<string[]> {
  const rows = await Participant.find({ userId: new Types.ObjectId(userId), leftAt: null })
    .select({ conversationId: 1 })
    .lean();
  return rows.map((r) => roomKey(String(r.conversationId)));
}

async function broadcast(io: TypedServer, userId: string, dto: PresenceDTO): Promise<void> {
  const rooms = await audienceRooms(userId);
  if (rooms.length > 0) io.to(rooms).emit('presence:update', dto);
}

/**
 * Mark a user online — only on their FIRST socket.
 *
 * The refcount lives in sidIndex, which is what makes multi-tab presence
 * correct: opening a second tab must not re-announce, and closing one of two
 * must not mark the user offline.
 */
export async function handleConnect(io: TypedServer, userId: string): Promise<void> {
  if (sidIndex.socketCount(userId) !== 1) return;
  const now = new Date();
  await User.updateOne({ _id: new Types.ObjectId(userId) }, { $set: { presence: { status: 'online', lastSeenAt: now } } });
  await broadcast(io, userId, { userId: asUserId(userId), status: 'online', lastSeenAt: coarsen(now) });
}

const pendingOffline = new Map<string, NodeJS.Timeout>();

/**
 * Mark a user offline after a grace period, and only if they are still gone.
 *
 * The grace absorbs a page refresh, which otherwise shows every peer an
 * offline/online flicker for a user who never actually left.
 */
export function handleDisconnect(io: TypedServer, userId: string): void {
  if (sidIndex.socketCount(userId) > 0) return;
  clearTimeout(pendingOffline.get(userId));
  const timer = setTimeout(() => {
    pendingOffline.delete(userId);
    if (sidIndex.socketCount(userId) > 0) return; // reconnected inside the grace
    const now = new Date();
    void User.updateOne(
      { _id: new Types.ObjectId(userId) },
      { $set: { presence: { status: 'offline', lastSeenAt: now } } },
    )
      .then(() => broadcast(io, userId, { userId: asUserId(userId), status: 'offline', lastSeenAt: coarsen(now) }))
      .catch(() => undefined);
  }, THROTTLE.PRESENCE_OFFLINE_GRACE_MS);
  // Do not hold the process open just to flip a presence flag.
  timer.unref?.();
  pendingOffline.set(userId, timer);
}

export async function queryPresence(userIds: string[]): Promise<PresenceDTO[]> {
  const valid = userIds.filter((id) => Types.ObjectId.isValid(id));
  if (valid.length === 0) return [];
  const users = await User.find({ _id: { $in: valid.map((id) => new Types.ObjectId(id)) } })
    .select({ presence: 1 })
    .lean();
  // Live socket state beats the stored flag: a crashed process can leave a
  // stale 'online' in the database.
  return users.map((u) => {
    const dto = toPresenceDTO(u as never);
    return sidIndex.isOnline(String(u._id)) ? { ...dto, status: 'online' as const } : dto;
  });
}

export function __clearPendingOffline(): void {
  for (const t of pendingOffline.values()) clearTimeout(t);
  pendingOffline.clear();
}
