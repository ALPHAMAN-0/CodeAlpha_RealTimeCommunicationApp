import { Types } from 'mongoose';
import {
  LIMITS, RtcError, THROTTLE, type CipherEnvelope, type MessageDTO, type Seq,
} from '@rtc/shared';
import { log } from '../config/logger.js';
import { Conversation, Message, type MessageDoc } from '../db/models/index.js';
import { toMessageDTO } from './mappers.js';

const isDuplicateKey = (e: unknown): boolean => (e as { code?: number }).code === 11000;

export interface SendMessageInput {
  conversationId: string;
  senderId: string;
  clientMsgId: string;
  kind: 'text' | 'file';
  envelope: CipherEnvelope;
  sentAt: number;
  attachmentId?: string;
  replyToId?: string;
}

export interface SendMessageResult {
  message: MessageDTO;
  /** True => this was a replay; no new row was written. */
  deduped: boolean;
}

/**
 * Persist a message exactly once.
 *
 * The guarantee comes from the unique index on
 * (conversationId, clientMsgId) — NOT from this code being careful. That
 * distinction matters: it means a retry is safe even if it races another
 * retry, arrives on a different connection, or lands during a failover.
 *
 * Sequence numbers are allocated with an atomic $inc on the conversation
 * document, which is atomic even on a standalone mongod with no transactions.
 * The consequence is that seq is monotonic but NOT gap-free: a lost duplicate
 * race burns a number. Every reader uses `seq > cursor` range scans and
 * nothing ever expects `cursor + 1`, so gaps are inert.
 */
export async function sendMessage(input: SendMessageInput): Promise<SendMessageResult> {
  const conversationId = new Types.ObjectId(input.conversationId);
  const senderId = new Types.ObjectId(input.senderId);

  // Reject an implausible client clock BEFORE writing. `sentAt` is what the UI
  // displays (it is the value inside the authenticated AAD), so a wild value
  // would reorder the visible timeline.
  const skew = Math.abs(Date.now() - input.sentAt);
  if (skew > THROTTLE.CLOCK_SKEW_MAX_MS) {
    throw new RtcError('VALIDATION', 'Client clock is too far out of sync');
  }

  // Fast path: avoids burning a sequence number on every retry.
  const existing = await Message.findOne({ conversationId, clientMsgId: input.clientMsgId });
  if (existing) {
    return { message: toMessageDTO(existing as never), deduped: true };
  }

  /**
   * Allocate the sequence number and validate acceptability in ONE atomic
   * operation.
   *
   * Every precondition lives in the filter, so a message that is going to be
   * rejected never increments the counter. Checking afterwards would work —
   * gaps are tolerated by design — but it would burn a sequence number on
   * every rejected send, and a client retrying through a rekey would punch a
   * visible hole in the room's numbering for no reason.
   *
   * The preconditions are:
   *  - the sender is a member;
   *  - the room is not mid-rekey. Between a membership change and the next
   *    published epoch there is no current key, so accepting would mean
   *    either encrypting under a key a removed member still holds, or storing
   *    something no member can read. Failing CLOSED is the only correct answer.
   *  - for a group, the envelope names the CURRENT epoch, or no recipient
   *    would know which key to reach for.
   */
  const guard: Record<string, unknown> = {
    _id: conversationId,
    memberIds: senderId,
    rekeyPending: false,
  };
  if (input.envelope.epoch !== undefined) guard.epoch = input.envelope.epoch;

  const conv = await Conversation.findOneAndUpdate(
    guard,
    { $inc: { messageSeq: 1 } },
    { returnDocument: 'after', projection: { messageSeq: 1, rekeyPending: 1, epoch: 1, type: 1 } },
  ).lean();

  if (!conv) {
    // Nothing was incremented. Read once more only to return an accurate
    // reason — the client's retry behaviour depends on which it is.
    const probe = await Conversation.findById(conversationId)
      .select({ memberIds: 1, rekeyPending: 1, epoch: 1, type: 1 })
      .lean();
    if (!probe || !probe.memberIds.some((m) => String(m) === input.senderId)) {
      throw new RtcError('NOT_A_MEMBER', 'Not a member of this conversation');
    }
    if (probe.rekeyPending) {
      throw new RtcError('REKEY_PENDING', 'Room keys are being rotated; try again in a moment');
    }
    throw new RtcError('REKEY_PENDING', 'Message was encrypted under a stale epoch');
  }

  // A group message must carry an epoch at all; a DM must not.
  if (conv.type === 'group' && input.envelope.epoch === undefined) {
    throw new RtcError('VALIDATION', 'Group messages must name their epoch');
  }

  const seq = conv.messageSeq;
  try {
    const created = await Message.create({
      conversationId,
      seq,
      senderId,
      clientMsgId: input.clientMsgId,
      kind: input.kind,
      envelope: input.envelope,
      sentAt: input.sentAt,
      ...(input.attachmentId ? { attachmentId: new Types.ObjectId(input.attachmentId) } : {}),
      ...(input.replyToId ? { replyToId: new Types.ObjectId(input.replyToId) } : {}),
    });

    /**
     * Denormalised pointer for ordering the conversation list.
     *
     * Metadata only — deliberately no text preview, because a plaintext
     * preview beside an encrypted body would leak exactly what the encryption
     * protects. Guarded by `seq < this` so an out-of-order write cannot move
     * the pointer backwards, and fire-and-forget so it never delays the ack.
     */
    void Conversation.updateOne(
      { _id: conversationId, $or: [{ 'lastMessage.seq': { $lt: seq } }, { 'lastMessage.seq': null }] },
      {
        $set: {
          lastMessage: {
            messageId: created._id,
            seq,
            senderId,
            kind: input.kind,
            createdAt: new Date(),
          },
        },
      },
    ).catch((err) => log.warn({ err, conversationId: input.conversationId }, 'lastMessage denorm failed'));

    return { message: toMessageDTO(created as never), deduped: false };
  } catch (err) {
    if (isDuplicateKey(err)) {
      // Lost a race with a concurrent retry of the same clientMsgId. The
      // winner's row is authoritative; the seq allocated here becomes a gap,
      // which the protocol tolerates by design.
      const winner = await Message.findOne({ conversationId, clientMsgId: input.clientMsgId });
      if (winner) return { message: toMessageDTO(winner as never), deduped: true };
    }
    throw err;
  }
}

export interface HistoryPage {
  messages: MessageDTO[];
  hasMore: boolean;
  oldestSeq: Seq | null;
}

/** Backwards scroll. `beforeSeq` is exclusive. */
export async function getHistory(
  conversationId: string,
  opts: { beforeSeq?: number; limit?: number },
): Promise<HistoryPage> {
  const limit = Math.min(opts.limit ?? LIMITS.HISTORY_PAGE_DEFAULT, LIMITS.HISTORY_PAGE_MAX);
  const filter: Record<string, unknown> = { conversationId: new Types.ObjectId(conversationId) };
  if (opts.beforeSeq !== undefined) filter.seq = { $lt: opts.beforeSeq };

  // Fetch one extra to learn whether another page exists without a count().
  const rows = await Message.find(filter).sort({ seq: -1 }).limit(limit + 1);
  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;
  // Return ascending: clients insert by seq, and ascending avoids a reverse.
  const messages = page.map((m) => toMessageDTO(m as never)).reverse();
  return {
    messages,
    hasMore,
    oldestSeq: messages.length > 0 ? messages[0]!.seq : null,
  };
}

/** Forward backfill after a reconnect. `afterSeq` is exclusive. */
export async function getSince(
  conversationId: string,
  afterSeq: number,
  limit = LIMITS.SYNC_PER_CONV_MAX,
): Promise<{ messages: MessageDTO[]; hasMore: boolean }> {
  const rows = await Message.find({
    conversationId: new Types.ObjectId(conversationId),
    seq: { $gt: afterSeq },
  })
    .sort({ seq: 1 })
    .limit(limit + 1);
  const hasMore = rows.length > limit;
  return {
    messages: (hasMore ? rows.slice(0, limit) : rows).map((m) => toMessageDTO(m as never)),
    hasMore,
  };
}

/**
 * Tombstone a message.
 *
 * The row and its sequence number survive: removing it would punch a hole in
 * every client's ordering and in the unread arithmetic. Only the ciphertext is
 * dropped, which is the part that actually needs to disappear.
 */
export async function deleteMessage(
  conversationId: string,
  messageId: string,
  requesterId: string,
): Promise<{ seq: number; deletedAt: number }> {
  const msg = await Message.findOne({
    _id: new Types.ObjectId(messageId),
    conversationId: new Types.ObjectId(conversationId),
  }).select({ senderId: 1, seq: 1, deletedAt: 1 });
  if (!msg) throw new RtcError('NOT_FOUND', 'Message not found');
  if (String(msg.senderId) !== requesterId) {
    throw new RtcError('FORBIDDEN', 'You can only delete your own messages');
  }
  const deletedAt = msg.deletedAt ?? new Date();
  if (!msg.deletedAt) {
    await Message.updateOne(
      { _id: msg._id },
      { $set: { deletedAt }, $unset: { envelope: 1, attachmentId: 1 } },
    );
  }
  return { seq: msg.seq, deletedAt: deletedAt.getTime() };
}

export const messageById = (id: string): Promise<MessageDoc | null> =>
  Message.findById(new Types.ObjectId(id));
