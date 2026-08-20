import { Types } from 'mongoose';
import { RtcError, roomKey, asUserId, type EpochRecord, type RekeyReason } from '@rtc/shared';
import { securityLog } from '../config/logger.js';
import { Conversation, Epoch } from '../db/models/index.js';
import * as sidIndex from '../realtime/sidIndex.js';
import type { TypedServer } from '../realtime/types.js';

/**
 * Group key epochs.
 *
 * The server stores and relays these but cannot forge one: it holds no
 * member's private key, so it can produce neither a valid per-member wrap nor
 * a valid signature. Members verify both before accepting an epoch, which is
 * what makes it safe for the server to pick the publisher.
 */

/**
 * Nominate the publisher: the ONLINE member with the lowest user id.
 *
 * Deterministic so every client agrees without negotiating, and restricted to
 * online members so the room is not waiting on someone who is asleep. A bad
 * nomination is harmless — the server cannot forge an epoch, so the worst
 * case is a wasted round.
 */
export function pickLeader(memberIds: string[]): string | undefined {
  const online = memberIds.filter((id) => sidIndex.isOnline(id)).sort();
  return online[0];
}

/**
 * Mark a room as needing a new key and tell its members.
 *
 * Called on every membership change. Sending is blocked while pending, so a
 * removed member cannot read the next message and a joiner cannot read the
 * last one.
 */
export async function requireRekey(
  io: TypedServer,
  conversationId: string,
  reason: RekeyReason,
): Promise<void> {
  const conv = await Conversation.findOneAndUpdate(
    { _id: new Types.ObjectId(conversationId), type: 'group' },
    { $set: { rekeyPending: true, rekeyReason: reason } },
    { returnDocument: 'after', projection: { memberIds: 1, epoch: 1 } },
  ).lean();
  if (!conv) return;

  const leader = pickLeader(conv.memberIds.map((m) => String(m)));
  if (!leader) {
    // Nobody is online to publish. The requirement stays on the document, so
    // the first member to connect performs it.
    securityLog.info({ conversationId, reason }, 'rekey queued: no members online');
    return;
  }
  io.to(roomKey(conversationId)).emit('room:rekey-required', {
    conversationId: conversationId as never,
    newEpoch: conv.epoch + 1,
    reason,
    leaderUserId: asUserId(leader),
  });
}

/**
 * Store a member-published epoch.
 *
 * The server validates STRUCTURE, not cryptography — clients must verify the
 * signature themselves regardless, since this server is untrusted by design,
 * and duplicating that check here would only create the illusion that a
 * server-side check means something.
 *
 * What the server does usefully enforce is coverage and monotonicity, below.
 */
export async function publishEpoch(
  conversationId: string,
  publisherId: string,
  record: EpochRecord,
): Promise<{ epoch: number }> {
  const conv = await Conversation.findById(new Types.ObjectId(conversationId))
    .select({ memberIds: 1, epoch: 1, type: 1, rekeyPending: 1 })
    .lean();
  if (!conv) throw new RtcError('NOT_FOUND', 'Conversation not found');
  if (conv.type !== 'group') throw new RtcError('VALIDATION', 'Epochs apply to group conversations only');

  if (String(record.createdBy) !== publisherId) {
    throw new RtcError('FORBIDDEN', 'Epoch creator must be the publisher');
  }
  // Strictly the next epoch: no gaps, and no replacing an existing one.
  if (record.epoch !== conv.epoch + 1) {
    throw new RtcError('CONFLICT', `Expected epoch ${conv.epoch + 1}`);
  }

  /**
   * Every current member must have a wrap, and no one else may.
   *
   * This is the one structural check with real teeth: without it a malicious
   * member could publish an epoch that silently omits someone, permanently
   * locking them out of a room they belong to — a partition attack the
   * cryptography alone does not prevent.
   */
  const members = new Set(conv.memberIds.map((m) => String(m)));
  const wrapped = new Set(record.wraps.map((w) => String(w.userId)));
  if (wrapped.size !== record.wraps.length) {
    throw new RtcError('VALIDATION', 'Duplicate epoch wraps');
  }
  for (const m of members) {
    if (!wrapped.has(m)) throw new RtcError('VALIDATION', `Epoch omits member ${m}`);
  }
  for (const w of wrapped) {
    if (!members.has(w)) throw new RtcError('VALIDATION', `Epoch includes non-member ${w}`);
  }

  try {
    await Epoch.create({
      conversationId: new Types.ObjectId(conversationId),
      epoch: record.epoch,
      ephSpki: record.ephSpki,
      createdBy: new Types.ObjectId(publisherId),
      sig: record.sig,
      reason: record.reason,
      wraps: record.wraps.map((w) => ({
        userId: new Types.ObjectId(String(w.userId)),
        keyVersion: w.keyVersion,
        iv: w.iv,
        wrapped: w.wrapped,
      })),
    });
  } catch (err) {
    // Two members raced to publish. The unique (conversationId, epoch) index
    // decides; the loser retries against the new current epoch.
    if ((err as { code?: number }).code === 11000) {
      throw new RtcError('CONFLICT', 'Another member already published this epoch');
    }
    throw err;
  }

  // Guarded so a slow duplicate cannot move the pointer backwards.
  await Conversation.updateOne(
    { _id: new Types.ObjectId(conversationId), epoch: { $lt: record.epoch } },
    { $set: { epoch: record.epoch, rekeyPending: false }, $unset: { rekeyReason: 1 } },
  );
  securityLog.info({ conversationId, epoch: record.epoch, publisherId, reason: record.reason }, 'epoch published');
  return { epoch: record.epoch };
}

const toRecord = (doc: {
  epoch: number; ephSpki: string; createdBy: unknown; createdAt: Date; sig: string;
  reason: string; wraps: Array<{ userId: unknown; keyVersion: number; iv: string; wrapped: string }>;
}): EpochRecord => ({
  epoch: doc.epoch,
  ephSpki: doc.ephSpki,
  createdBy: asUserId(String(doc.createdBy)),
  createdAt: doc.createdAt.getTime(),
  sig: doc.sig,
  reason: doc.reason as RekeyReason,
  wraps: doc.wraps.map((w) => ({
    userId: asUserId(String(w.userId)),
    keyVersion: w.keyVersion,
    iv: w.iv,
    wrapped: w.wrapped,
  })),
});

export async function getEpoch(conversationId: string, epoch: number): Promise<EpochRecord> {
  const doc = await Epoch.findOne({ conversationId: new Types.ObjectId(conversationId), epoch }).lean();
  if (!doc) throw new RtcError('NOT_FOUND', `Epoch ${epoch} not found`);
  return toRecord(doc as never);
}

/** The current epoch, or undefined for a group that has not been keyed yet. */
export async function getCurrentEpoch(conversationId: string): Promise<EpochRecord | undefined> {
  const doc = await Epoch.findOne({ conversationId: new Types.ObjectId(conversationId) })
    .sort({ epoch: -1 })
    .lean();
  return doc ? toRecord(doc as never) : undefined;
}
