import type { AttachmentId, ConversationId, UserId } from '../ids.js';

/**
 * Server-side view of an attachment. Note what is absent: filename and MIME
 * type. The server holds ciphertext of unknown provenance and says so — the
 * download route serves everything as application/octet-stream.
 */
export interface AttachmentDTO {
  id: AttachmentId;
  conversationId: ConversationId;
  uploaderId: UserId;
  /** Size of the CIPHERTEXT on disk, not the plaintext. */
  cipherSize: number;
  createdAt: number;
}
