import { Types } from 'mongoose';
import {
  RtcError, type CipherEnvelope, type ConversationDTO, type ParticipantDTO, type Seq,
} from '@rtc/shared';
import { Conversation, Participant, User } from '../db/models/index.js';
import * as membership from '../realtime/membership.js';
import { toConversationDTO, toParticipantDTO } from './mappers.js';

/**
 * Canonical key for a 1:1 conversation: both ids, sorted, joined.
 *
 * Sorting is what makes it canonical — without it, (a,b) and (b,a) produce
 * different keys and the unique index below stops preventing anything.
 */
export const dmKeyFor = (a: string, b: string): string => [a, b].sort().join(':');

/**
 * Get the DM between two users, creating it if needed.
 *
 * Implemented as an upsert against the unique partial index on `dmKey`. A
 * find-then-create would let two users who click each other simultaneously
 * create two conversations, after which their messages split across both and
 * neither sees the full thread — a bug that is invisible in testing and
 * obvious in production.
 */
export async function createOrGetDm(userA: string, userB: string): Promise<ConversationDTO> {
  if (userA === userB) throw new RtcError('VALIDATION', 'Cannot open a conversation with yourself');
  const other = await User.exists({ _id: new Types.ObjectId(userB) });
  if (!other) throw new RtcError('NOT_FOUND', 'User not found');

  const ids = [new Types.ObjectId(userA), new Types.ObjectId(userB)];
  const dmKey = dmKeyFor(userA, userB);

  const conv = await Conversation.findOneAndUpdate(
    { dmKey, type: 'dm' },
    {
      $setOnInsert: {
        type: 'dm',
        dmKey,
        memberIds: ids,
        createdBy: ids[0]!,
        messageSeq: 0,
        whiteboardSeq: 0,
        // DMs derive a key per message from static-static ECDH, so they have
        // no epoch to rotate and are never rekey-pending.
        epoch: 0,
        rekeyPending: false,
        whiteboard: { clearedAtSeq: 0, opCount: 0, truncated: false },
      },
    },
    { returnDocument: 'after', upsert: true },
  );

  // Participant rows are idempotent too, so a racing upsert cannot duplicate them.
  await Promise.all(
    ids.map((userId) =>
      Participant.updateOne(
        { conversationId: conv._id, userId },
        { $setOnInsert: { role: 'member', lastReadSeq: 0, lastDeliveredSeq: 0, joinedAt: new Date() } },
        { upsert: true },
      ),
    ),
  );
  for (const uid of [userA, userB]) membership.invalidate(uid, String(conv._id));
  return toConversationDTO(conv as never);
}

export async function createGroup(
  creatorId: string,
  memberIds: string[],
  titleEnvelope?: CipherEnvelope,
): Promise<ConversationDTO> {
  const unique = [...new Set([creatorId, ...memberIds])];
  const found = await User.countDocuments({ _id: { $in: unique.map((id) => new Types.ObjectId(id)) } });
  if (found !== unique.length) throw new RtcError('VALIDATION', 'One or more members do not exist');

  const conv = await Conversation.create({
    type: 'group',
    memberIds: unique.map((id) => new Types.ObjectId(id)),
    createdBy: new Types.ObjectId(creatorId),
    ...(titleEnvelope ? { titleEnvelope } : {}),
    messageSeq: 0,
    whiteboardSeq: 0,
    // A brand-new group has no key yet. `rekeyPending` blocks sending until
    // the creator publishes epoch 1 — fail closed rather than allowing an
    // unencrypted or stale-key first message.
    epoch: 0,
    rekeyPending: true,
    rekeyReason: 'created',
    whiteboard: { clearedAtSeq: 0, opCount: 0, truncated: false },
  });

  await Participant.insertMany(
    unique.map((id) => ({
      conversationId: conv._id,
      userId: new Types.ObjectId(id),
      role: id === creatorId ? 'owner' : 'member',
      lastReadSeq: 0,
      lastDeliveredSeq: 0,
      joinedAt: new Date(),
    })),
  );
  for (const uid of unique) membership.invalidate(uid, String(conv._id));
  return toConversationDTO(conv as never);
}

export interface ConversationListEntry {
  conversation: ConversationDTO;
  /**
   * Public profiles of every member, returned WITH the list.
   *
   * Without this the sidebar can only label a conversation after joining it,
   * so a freshly-loaded list reads "Direct message" and "Member, Member". One
   * batched lookup here replaces one round trip per conversation.
   */
  members: Array<{ userId: string; displayName: string; avatarColor: string; keyVersion: number }>;
}

export async function listConversations(userId: string): Promise<ConversationListEntry[]> {
  const rows = await Participant.find({ userId: new Types.ObjectId(userId), leftAt: null })
    .select({ conversationId: 1 })
    .lean();
  if (rows.length === 0) return [];

  // Served by the { memberIds, lastMessage.createdAt } index with no
  // in-memory sort.
  const convs = await Conversation.find({ _id: { $in: rows.map((r) => r.conversationId) } })
    .sort({ 'lastMessage.createdAt': -1, createdAt: -1 });

  // One query for every member across every conversation, rather than N.
  const memberIds = [...new Set(convs.flatMap((c) => c.memberIds.map((m) => String(m))))];
  const users = await User.find({ _id: { $in: memberIds.map((id) => new Types.ObjectId(id)) } })
    .select({ displayName: 1, avatarColor: 1, keyVersion: 1 })
    .lean();
  const byId = new Map(users.map((u) => [String(u._id), u]));

  return convs.map((c) => ({
    conversation: toConversationDTO(c as never),
    members: c.memberIds.flatMap((m) => {
      const u = byId.get(String(m));
      return u
        ? [{
            userId: String(m),
            displayName: u.displayName,
            avatarColor: u.avatarColor,
            keyVersion: u.keyVersion,
          }]
        : [];
    }),
  }));
}

export interface JoinState {
  conversation: ConversationDTO;
  participants: ParticipantDTO[];
  latestSeq: Seq;
  yourLastReadSeq: Seq;
  unread: number;
  whiteboardSeq: Seq;
}

export async function getJoinState(conversationId: string, userId: string): Promise<JoinState> {
  const conv = await Conversation.findById(new Types.ObjectId(conversationId));
  if (!conv) throw new RtcError('NOT_FOUND', 'Conversation not found');

  const parts = await Participant.find({ conversationId: conv._id, leftAt: null });
  const users = await User.find({ _id: { $in: parts.map((p) => p.userId) } })
    .select({ displayName: 1, avatarColor: 1, keyVersion: 1 })
    .lean();
  const byId = new Map(users.map((u) => [String(u._id), u]));

  const mine = parts.find((p) => String(p.userId) === userId);
  if (!mine) throw new RtcError('NOT_A_MEMBER', 'Not a member of this conversation');

  return {
    conversation: toConversationDTO(conv as never),
    participants: parts.flatMap((p) => {
      const u = byId.get(String(p.userId));
      return u ? [toParticipantDTO(p, u as never)] : [];
    }),
    latestSeq: conv.messageSeq,
    yourLastReadSeq: mine.lastReadSeq,
    /**
     * Unread is arithmetic, not a query.
     *
     * O(1), no countDocuments, no maintained counter that can drift. Sequence
     * gaps and deletions can inflate it by one or two — a badge reading 4
     * instead of 3 is not a correctness incident, and it is documented rather
     * than papered over with a nightly reconcile job nobody would run.
     */
    unread: Math.max(0, conv.messageSeq - mine.lastReadSeq),
    whiteboardSeq: conv.whiteboardSeq,
  };
}

/**
 * Advance a read or delivery watermark.
 *
 * Monotonic by $max: a late-arriving lower value from a slow tab must never
 * move a watermark backwards and resurrect messages the user already read.
 */
export async function setWatermark(
  conversationId: string,
  userId: string,
  field: 'lastReadSeq' | 'lastDeliveredSeq',
  seq: number,
): Promise<{ readSeq: number; deliveredSeq: number; unread: number }> {
  const conv = await Conversation.findById(new Types.ObjectId(conversationId)).select({ messageSeq: 1 }).lean();
  if (!conv) throw new RtcError('NOT_FOUND', 'Conversation not found');
  // Never allow a watermark past the highest allocated seq.
  const clamped = Math.min(seq, conv.messageSeq);

  const updated = await Participant.findOneAndUpdate(
    { conversationId: new Types.ObjectId(conversationId), userId: new Types.ObjectId(userId) },
    { $max: { [field]: clamped } },
    { returnDocument: 'after', projection: { lastReadSeq: 1, lastDeliveredSeq: 1 } },
  ).lean();
  if (!updated) throw new RtcError('NOT_A_MEMBER', 'Not a member of this conversation');

  return {
    readSeq: updated.lastReadSeq,
    deliveredSeq: updated.lastDeliveredSeq,
    unread: Math.max(0, conv.messageSeq - updated.lastReadSeq),
  };
}

export async function watermarksFor(
  conversationId: string,
): Promise<Array<{ userId: string; readSeq: number; deliveredSeq: number }>> {
  const parts = await Participant.find({ conversationId: new Types.ObjectId(conversationId), leftAt: null })
    .select({ userId: 1, lastReadSeq: 1, lastDeliveredSeq: 1 })
    .lean();
  return parts.map((p) => ({
    userId: String(p.userId),
    readSeq: p.lastReadSeq,
    deliveredSeq: p.lastDeliveredSeq,
  }));
}

export const memberIdsOf = async (conversationId: string): Promise<string[]> => {
  const conv = await Conversation.findById(new Types.ObjectId(conversationId)).select({ memberIds: 1 }).lean();
  return (conv?.memberIds ?? []).map((m) => String(m));
};
