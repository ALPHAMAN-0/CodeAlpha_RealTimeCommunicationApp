import { Schema, model, type InferSchemaType, type Model } from 'mongoose';
import { envelopeSchema } from './envelope.schema.js';

const conversationSchema = new Schema(
  {
    type: { type: String, required: true, enum: ['dm', 'group'] },
    /**
     * Sorted member ids joined by ':' — DMs only.
     *
     * Without a unique index on this, two users clicking each other at the
     * same moment create two DMs and their messages split across both.
     */
    dmKey: { type: String },
    /** Sealed group title. Non-members see only an id. */
    titleEnvelope: { type: envelopeSchema },
    /** Denormalised for a single-query conversation list and fast authorization. */
    memberIds: { type: [Schema.Types.ObjectId], required: true, ref: 'User' },
    createdBy: { type: Schema.Types.ObjectId, required: true, ref: 'User' },

    /**
     * Atomic $inc source of message order.
     *
     * Monotonic, NOT gap-free: a lost duplicate race burns a number. Every
     * reader uses `seq > cursor` range scans, so gaps are inert.
     */
    messageSeq: { type: Number, required: true, default: 0 },
    whiteboardSeq: { type: Number, required: true, default: 0 },

    /** Current group key epoch. 0 for DMs, which derive per-message instead. */
    epoch: { type: Number, required: true, default: 0 },
    /**
     * True between a membership change and the next published epoch. Clients
     * fail CLOSED while set — never fall back to a superseded key.
     */
    rekeyPending: { type: Boolean, required: true, default: false },
    rekeyReason: { type: String },

    whiteboard: {
      /** Ops at or below this seq are logically gone. */
      clearedAtSeq: { type: Number, required: true, default: 0 },
      opCount: { type: Number, required: true, default: 0 },
      /** Set once the op log has hit its cap and dropped its oldest entries. */
      truncated: { type: Boolean, required: true, default: false },
    },

    /**
     * METADATA ONLY — deliberately no text preview.
     *
     * Denormalising a plaintext preview beside an encrypted body would leak
     * exactly what the encryption protects. Clients render previews from
     * their own decrypted cache instead.
     */
    lastMessage: {
      messageId: { type: Schema.Types.ObjectId },
      seq: { type: Number },
      senderId: { type: Schema.Types.ObjectId },
      kind: { type: String, enum: ['text', 'file', 'system'] },
      createdAt: { type: Date },
    },
  },
  { timestamps: true, strict: 'throw' },
);

// Serves `find({memberIds: me}).sort({'lastMessage.createdAt': -1})` — the
// conversation list — as one multikey index scan with no in-memory sort.
conversationSchema.index({ memberIds: 1, 'lastMessage.createdAt': -1 });
conversationSchema.index({ dmKey: 1 }, { unique: true, partialFilterExpression: { type: 'dm' } });

export type ConversationDoc = InferSchemaType<typeof conversationSchema>;
export const Conversation: Model<ConversationDoc> = model<ConversationDoc>('Conversation', conversationSchema);
