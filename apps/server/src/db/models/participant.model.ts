import { Schema, model, type InferSchemaType, type Model } from 'mongoose';

/**
 * Membership plus read state, as its own collection rather than an array on
 * the conversation.
 *
 * Read watermarks update on every receipt from every member. As a subdocument
 * array that would mean constantly rewriting the hot conversation document,
 * contending with the atomic $inc that allocates message sequence numbers.
 * Split out, each user's watermark is an independent single-document update.
 */
const participantSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    role: { type: String, required: true, enum: ['owner', 'member'], default: 'member' },

    /**
     * Watermarks, not per-message arrays.
     *
     * `readBy: [userId]` on each message would be O(messages × members)
     * updates and unbounded document growth on the hottest collection. "Read
     * by 3" is derived by comparing these against the already-loaded
     * participant list, and unread becomes arithmetic:
     * `conversation.messageSeq - lastReadSeq`, with no counter to drift.
     */
    lastReadSeq: { type: Number, required: true, default: 0 },
    lastDeliveredSeq: { type: Number, required: true, default: 0 },

    joinedAt: { type: Date, required: true, default: () => new Date() },
    /** Set on removal so history stays attributable without a live membership. */
    leftAt: { type: Date },
    mutedUntil: { type: Date },
  },
  { timestamps: true, strict: 'throw' },
);

// The hottest read in the system: "is this user a member of this conversation".
participantSchema.index({ conversationId: 1, userId: 1 }, { unique: true });
participantSchema.index({ userId: 1, conversationId: 1 });

export type ParticipantDoc = InferSchemaType<typeof participantSchema>;
export const Participant: Model<ParticipantDoc> = model<ParticipantDoc>('Participant', participantSchema);
