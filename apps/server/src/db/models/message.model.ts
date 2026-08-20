import { Schema, model, type InferSchemaType, type Model } from 'mongoose';
import { envelopeSchema } from './envelope.schema.js';

/** Append-only and immutable after insert, apart from the delete tombstone. */
const messageSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    /** Server-assigned order. Monotonic per conversation, not gap-free. */
    seq: { type: Number, required: true },
    senderId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    /**
     * Client-minted UUID, never regenerated on retry.
     *
     * The unique index on (conversationId, clientMsgId) IS the exactly-once
     * guarantee: a replayed send cannot create a second row.
     */
    clientMsgId: { type: String, required: true },
    kind: { type: String, required: true, enum: ['text', 'file', 'system'] },

    /** Ciphertext. Absent for system messages and once tombstoned. */
    envelope: { type: envelopeSchema },

    /**
     * System events are server-generated, so they are NOT encrypted and do
     * not pretend to be — the server performed the action and already knows
     * every field here.
     */
    system: {
      code: {
        type: String,
        enum: [
          'member_added', 'member_removed', 'member_left',
          'conversation_created', 'call_started', 'call_ended', 'rekeyed',
        ],
      },
      actorId: { type: Schema.Types.ObjectId, ref: 'User' },
      targetId: { type: Schema.Types.ObjectId, ref: 'User' },
    },

    /** Pointer only. Filename, MIME and the file key live inside the envelope. */
    attachmentId: { type: Schema.Types.ObjectId, ref: 'Attachment' },
    replyToId: { type: Schema.Types.ObjectId, ref: 'Message' },

    /**
     * The CLIENT's clock, authenticated inside the envelope's AAD. This is
     * what the UI displays. `createdAt` is assigned after the sender signed,
     * so it is unauthenticated and used only for ordering sanity.
     */
    sentAt: { type: Number, required: true },
    deletedAt: { type: Date },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);

// One index serves history pagination (seq < cursor), reconnect backfill
// (seq > cursor) and seq uniqueness.
messageSchema.index({ conversationId: 1, seq: -1 }, { unique: true });
messageSchema.index({ conversationId: 1, clientMsgId: 1 }, { unique: true });
messageSchema.index({ conversationId: 1, attachmentId: 1 }, { sparse: true });

export type MessageDoc = InferSchemaType<typeof messageSchema>;
export const Message: Model<MessageDoc> = model<MessageDoc>('Message', messageSchema);
