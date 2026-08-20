import { Types } from 'mongoose';
import {
  LIMITS, RtcError, asUserId, type CipherEnvelope, type WhiteboardOpKind, type WhiteboardOpRecord,
} from '@rtc/shared';
import { log } from '../config/logger.js';
import { Conversation, WhiteboardOp } from '../db/models/index.js';

export interface AppendOpInput {
  conversationId: string;
  authorId: string;
  kind: WhiteboardOpKind;
  strokeId?: string;
  chunk?: number;
  done?: boolean;
  envelope?: CipherEnvelope;
}

const toRecord = (doc: {
  seq: number; authorId: unknown; kind: string; strokeId?: string | null;
  chunk?: number | null; done?: boolean | null; envelope?: unknown; createdAt: Date;
}): WhiteboardOpRecord => ({
  seq: doc.seq,
  authorId: asUserId(String(doc.authorId)),
  kind: doc.kind as WhiteboardOpKind,
  ...(doc.strokeId ? { strokeId: doc.strokeId as never } : {}),
  ...(doc.chunk !== null && doc.chunk !== undefined ? { chunk: doc.chunk } : {}),
  ...(doc.done !== null && doc.done !== undefined ? { done: doc.done } : {}),
  ...(doc.envelope ? { envelope: doc.envelope as CipherEnvelope } : {}),
  at: doc.createdAt.getTime(),
});

/**
 * Append one op to the board's totally-ordered log.
 *
 * The log IS the board: any client that replays it in seq order renders a
 * pixel-identical result. That single property is what gives late-join,
 * refresh-survival and undo from one mechanism instead of three.
 */
export async function appendOp(input: AppendOpInput): Promise<{ record: WhiteboardOpRecord; clearedAtSeq?: number }> {
  const conversationId = new Types.ObjectId(input.conversationId);

  /**
   * Undo and redo are authorized PER AUTHOR.
   *
   * Global undo means Bob presses Ctrl+Z and erases Alice's work, which users
   * hate and which no amount of UI explains away.
   */
  if (input.kind === 'undo' || input.kind === 'redo') {
    const stroke = await WhiteboardOp.findOne({
      conversationId, strokeId: input.strokeId, kind: 'stroke',
    }).select({ authorId: 1 }).lean();
    if (!stroke) throw new RtcError('NOT_FOUND', 'Stroke not found');
    if (String(stroke.authorId) !== input.authorId) {
      throw new RtcError('FORBIDDEN', 'You can only undo your own strokes');
    }
  }

  const conv = await Conversation.findOneAndUpdate(
    { _id: conversationId, memberIds: new Types.ObjectId(input.authorId) },
    { $inc: { whiteboardSeq: 1, 'whiteboard.opCount': 1 } },
    { returnDocument: 'after', projection: { whiteboardSeq: 1, whiteboard: 1 } },
  ).lean();
  if (!conv) throw new RtcError('NOT_A_MEMBER', 'Not a member of this conversation');

  const seq = conv.whiteboardSeq;
  const doc = await WhiteboardOp.create({
    conversationId,
    seq,
    authorId: new Types.ObjectId(input.authorId),
    kind: input.kind,
    ...(input.strokeId ? { strokeId: input.strokeId } : {}),
    ...(input.chunk !== undefined ? { chunk: input.chunk } : {}),
    ...(input.done !== undefined ? { done: input.done } : {}),
    ...(input.envelope ? { envelope: input.envelope } : {}),
  });

  if (input.kind === 'clear') {
    // Destructive and NOT undoable, which is why the UI requires an explicit
    // confirmation and everyone is told who did it. Attributed destruction
    // beats mysterious destruction.
    await Conversation.updateOne(
      { _id: conversationId },
      { $set: { 'whiteboard.clearedAtSeq': seq, 'whiteboard.opCount': 0, 'whiteboard.truncated': false } },
    );
    void WhiteboardOp.deleteMany({ conversationId, seq: { $lt: seq } }).catch((err) =>
      log.warn({ err, conversationId: input.conversationId }, 'whiteboard prune failed'),
    );
    return { record: toRecord(doc as never), clearedAtSeq: seq };
  }

  /**
   * Cap the log and say so.
   *
   * v1 drops the oldest ops and sets `truncated`, which the UI surfaces as
   * "earlier history trimmed". Silently dropping them would make the board
   * quietly diverge between a long-lived client and a fresh one — the worst
   * of both outcomes. Encrypted client-generated snapshots are the v2 fix.
   */
  if ((conv.whiteboard?.opCount ?? 0) > LIMITS.WB_OPS_MAX) {
    const excess = (conv.whiteboard?.opCount ?? 0) - LIMITS.WB_OPS_MAX;
    const oldest = await WhiteboardOp.find({ conversationId })
      .sort({ seq: 1 })
      .limit(excess)
      .select({ _id: 1 })
      .lean();
    if (oldest.length > 0) {
      await WhiteboardOp.deleteMany({ _id: { $in: oldest.map((o) => o._id) } });
      await Conversation.updateOne(
        { _id: conversationId },
        { $set: { 'whiteboard.truncated': true }, $inc: { 'whiteboard.opCount': -oldest.length } },
      );
    }
  }

  return { record: toRecord(doc as never) };
}

export async function syncOps(
  conversationId: string,
  sinceSeq: number,
): Promise<{ ops: WhiteboardOpRecord[]; hasMore: boolean; latestSeq: number; truncated: boolean }> {
  const oid = new Types.ObjectId(conversationId);
  const conv = await Conversation.findById(oid).select({ whiteboardSeq: 1, whiteboard: 1 }).lean();
  if (!conv) throw new RtcError('NOT_FOUND', 'Conversation not found');

  // Never replay ops from before the last clear: they were logically erased
  // and re-rendering them would resurrect a cleared board for a late joiner.
  const floor = Math.max(sinceSeq, conv.whiteboard?.clearedAtSeq ?? 0);
  const rows = await WhiteboardOp.find({ conversationId: oid, seq: { $gt: floor } })
    .sort({ seq: 1 })
    .limit(LIMITS.WB_SYNC_PAGE + 1)
    .lean();

  const hasMore = rows.length > LIMITS.WB_SYNC_PAGE;
  const page = hasMore ? rows.slice(0, LIMITS.WB_SYNC_PAGE) : rows;
  return {
    ops: page.map((r) => toRecord(r as never)),
    hasMore,
    latestSeq: conv.whiteboardSeq,
    truncated: conv.whiteboard?.truncated ?? false,
  };
}
