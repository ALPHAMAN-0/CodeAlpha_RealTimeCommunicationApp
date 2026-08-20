import { Types } from 'mongoose';
import type { Readable } from 'node:stream';
import { RtcError } from '@rtc/shared';
import { log } from '../config/logger.js';
import { Attachment, Message, Participant } from '../db/models/index.js';
import { storage } from '../storage/index.js';

/** Uploads never claimed by a message are reaped after this long. */
const ORPHAN_GRACE_MS = 15 * 60 * 1000;

export async function createAttachment(input: {
  conversationId: string;
  uploaderId: string;
  stream: Readable;
}): Promise<{ attachmentId: string; cipherSize: number }> {
  const { storageId, size } = await storage().put({ stream: input.stream, filename: 'blob' });
  const doc = await Attachment.create({
    conversationId: new Types.ObjectId(input.conversationId),
    uploaderId: new Types.ObjectId(input.uploaderId),
    storageId,
    cipherSize: size,
  });
  return { attachmentId: String(doc._id), cipherSize: size };
}

export interface DownloadTarget {
  storageId: string;
  cipherSize: number;
}

/**
 * Authorize a download.
 *
 * The criterion is CURRENT MEMBERSHIP of the conversation the file was shared
 * in — not ownership, and emphatically not "knows the id". That is why this is
 * an authenticated route rather than a signed URL: a signed URL keeps working
 * for its whole TTL even after someone is removed from the room, and URLs leak
 * into Referer headers, browser history, proxy logs and screenshots.
 */
export async function authorizeDownload(attachmentId: string, userId: string): Promise<DownloadTarget> {
  if (!Types.ObjectId.isValid(attachmentId)) throw new RtcError('NOT_FOUND', 'Not found');
  const att = await Attachment.findById(new Types.ObjectId(attachmentId))
    .select({ conversationId: 1, storageId: 1, cipherSize: 1, messageId: 1 })
    .lean();
  if (!att) throw new RtcError('NOT_FOUND', 'Not found');

  const member = await Participant.exists({
    conversationId: att.conversationId,
    userId: new Types.ObjectId(userId),
    leftAt: null,
  });
  if (!member) throw new RtcError('FORBIDDEN', 'Not a member of this conversation');

  return { storageId: att.storageId, cipherSize: att.cipherSize };
}

/** Bind an upload to the message that references it, so it stops being an orphan. */
export async function claimAttachment(attachmentId: string, messageId: string): Promise<void> {
  await Attachment.updateOne(
    { _id: new Types.ObjectId(attachmentId) },
    { $set: { messageId: new Types.ObjectId(messageId) } },
  );
}

/**
 * Delete uploads that were never referenced by a message.
 *
 * Decoupling upload from send means a failed send retries without re-uploading
 * bytes — the deliberate trade is that an abandoned compose leaves a blob
 * behind, so something has to collect them.
 */
export async function reapOrphans(now = Date.now()): Promise<number> {
  const cutoff = new Date(now - ORPHAN_GRACE_MS);
  const orphans = await Attachment.find({ messageId: null, createdAt: { $lt: cutoff } })
    .select({ storageId: 1 })
    .limit(500)
    .lean();
  for (const o of orphans) {
    await storage().delete(o.storageId);
    await Attachment.deleteOne({ _id: o._id });
  }
  if (orphans.length > 0) log.info({ count: orphans.length }, 'reaped orphaned attachments');
  return orphans.length;
}

/** Attachment ids referenced by a conversation, for the files tab. */
export async function listAttachments(conversationId: string): Promise<Array<{ id: string; messageId: string | null; cipherSize: number; createdAt: number }>> {
  const rows = await Attachment.find({ conversationId: new Types.ObjectId(conversationId) })
    .sort({ createdAt: -1 })
    .limit(200)
    .lean();
  return rows.map((r) => ({
    id: String(r._id),
    messageId: r.messageId ? String(r.messageId) : null,
    cipherSize: r.cipherSize,
    createdAt: new Date(r.createdAt as unknown as string).getTime(),
  }));
}

export const messageReferences = (attachmentId: string): Promise<boolean> =>
  Message.exists({ attachmentId: new Types.ObjectId(attachmentId) }).then((r) => r !== null);
