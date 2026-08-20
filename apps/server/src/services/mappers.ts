import type { Types } from 'mongoose';
import {
  asAttachmentId, asClientMsgId, asConversationId, asMessageId, asUserId,
  type ConversationDTO, type MessageDTO, type ParticipantDTO,
} from '@rtc/shared';
import type { ConversationDoc, MessageDoc, ParticipantDoc } from '../db/models/index.js';

type WithId<T> = T & { _id: Types.ObjectId };
const id = (v: unknown): string => String(v);

export const toMessageDTO = (m: WithId<MessageDoc>): MessageDTO => ({
  id: asMessageId(id(m._id)),
  conversationId: asConversationId(id(m.conversationId)),
  seq: m.seq,
  senderId: asUserId(id(m.senderId)),
  clientMsgId: asClientMsgId(m.clientMsgId),
  kind: m.kind,
  // A tombstoned message keeps its slot in the timeline but loses its body.
  ...(m.envelope && !m.deletedAt ? { envelope: m.envelope as MessageDTO['envelope'] } : {}),
  ...(m.system?.code
    ? {
        system: {
          code: m.system.code,
          actorId: asUserId(id(m.system.actorId)),
          ...(m.system.targetId ? { targetId: asUserId(id(m.system.targetId)) } : {}),
        },
      }
    : {}),
  ...(m.attachmentId ? { attachmentId: asAttachmentId(id(m.attachmentId)) } : {}),
  ...(m.replyToId ? { replyToId: asMessageId(id(m.replyToId)) } : {}),
  sentAt: m.sentAt,
  createdAt: new Date(m.createdAt as unknown as string).getTime(),
  ...(m.deletedAt ? { deletedAt: m.deletedAt.getTime() } : {}),
});

export const toConversationDTO = (c: WithId<ConversationDoc>): ConversationDTO => ({
  id: asConversationId(id(c._id)),
  type: c.type,
  ...(c.titleEnvelope ? { titleEnvelope: c.titleEnvelope as ConversationDTO['titleEnvelope'] } : {}),
  memberIds: c.memberIds.map((m) => asUserId(id(m))),
  createdBy: asUserId(id(c.createdBy)),
  createdAt: new Date(c.createdAt as unknown as string).getTime(),
  messageSeq: c.messageSeq,
  whiteboardSeq: c.whiteboardSeq,
  epoch: c.epoch,
  rekeyPending: c.rekeyPending,
  ...(c.lastMessage?.messageId
    ? {
        lastMessage: {
          messageId: asMessageId(id(c.lastMessage.messageId)),
          seq: c.lastMessage.seq ?? 0,
          senderId: asUserId(id(c.lastMessage.senderId)),
          kind: c.lastMessage.kind ?? 'text',
          createdAt: c.lastMessage.createdAt ? c.lastMessage.createdAt.getTime() : 0,
        },
      }
    : {}),
});

export const toParticipantDTO = (
  p: ParticipantDoc,
  user: { displayName: string; avatarColor: string; keyVersion: number },
): ParticipantDTO => ({
  userId: asUserId(id(p.userId)),
  displayName: user.displayName,
  avatarColor: user.avatarColor,
  keyVersion: user.keyVersion,
  role: p.role,
  lastReadSeq: p.lastReadSeq,
  lastDeliveredSeq: p.lastDeliveredSeq,
  joinedAt: p.joinedAt.getTime(),
});
