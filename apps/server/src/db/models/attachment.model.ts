import { Schema, model, type InferSchemaType, type Model } from 'mongoose';

/**
 * An uploaded file's server-side record.
 *
 * Note what is NOT here: filename and MIME type. Both are end-to-end
 * encrypted inside the accompanying message, because "Q3_layoffs.xlsx" leaks
 * plenty on its own. The server holds high-entropy bytes of unknown
 * provenance and serves them as application/octet-stream.
 */
const attachmentSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    uploaderId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    /** GridFS file id. Server-generated: no user input ever reaches a path. */
    storageId: { type: String, required: true },
    /** Size of the CIPHERTEXT, which is all the server can measure. */
    cipherSize: { type: Number, required: true },
    /** Set once a message references it; unreferenced uploads are reaped. */
    messageId: { type: Schema.Types.ObjectId, ref: 'Message' },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);

attachmentSchema.index({ conversationId: 1, createdAt: -1 });
// Finds uploads that were never attached to a message, for the orphan reaper.
attachmentSchema.index({ messageId: 1, createdAt: 1 }, { sparse: true });

export type AttachmentDoc = InferSchemaType<typeof attachmentSchema>;
export const Attachment: Model<AttachmentDoc> = model<AttachmentDoc>('Attachment', attachmentSchema);
