import type { ConversationId, UserId, Seq, MessageId } from '../ids.js';
import type { CipherEnvelope } from './crypto.js';

export interface ConversationDTO {
  id: ConversationId;
  type: 'dm' | 'group';
  /**
   * Group title, E2EE under the current epoch key. Non-members see only a
   * UUID. Re-encrypted by the rekey leader on every epoch change.
   */
  titleEnvelope?: CipherEnvelope;
  memberIds: UserId[];
  createdBy: UserId;
  createdAt: number;
  /** Highest allocated message seq. `unread = messageSeq - lastReadSeq`. */
  messageSeq: Seq;
  whiteboardSeq: Seq;
  /** Current group epoch. 0 for DMs, which derive keys per message instead. */
  epoch: number;
  /** True => sending is blocked until a member publishes the next epoch. */
  rekeyPending: boolean;
  /**
   * Metadata only — deliberately NO plaintext preview. Denormalizing a preview
   * next to an encrypted body would leak exactly what the encryption protects.
   * Clients render previews from their own decrypted cache.
   */
  lastMessage?: {
    messageId: MessageId;
    seq: Seq;
    senderId: UserId;
    kind: MessageKind;
    createdAt: number;
  };
}

export type MessageKind = 'text' | 'file' | 'system';

export interface ParticipantDTO {
  userId: UserId;
  displayName: string;
  avatarColor: string;
  keyVersion: number;
  role: 'owner' | 'member';
  lastReadSeq: Seq;
  lastDeliveredSeq: Seq;
  joinedAt: number;
}
