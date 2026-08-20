import { Schema, model, type InferSchemaType, type Model } from 'mongoose';

/**
 * A group room's key epoch: one random room key, wrapped once per member.
 *
 * The server stores and relays these but cannot forge one — it holds no
 * member's private key, so it can produce neither a valid wrap nor a valid
 * signature. A bad rekey-leader nomination therefore costs at most a wasted
 * epoch, never a readable room.
 */
const epochSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    epoch: { type: Number, required: true },
    /** Ephemeral ECDH public key the per-member wraps were derived from. */
    ephSpki: { type: String, required: true },
    createdBy: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    /** Creator's signature over the whole record. Verified by members. */
    sig: { type: String, required: true },
    reason: {
      type: String,
      required: true,
      enum: ['created', 'member_added', 'member_removed', 'key_rotated', 'age'],
    },
    wraps: {
      type: [
        new Schema(
          {
            userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
            keyVersion: { type: Number, required: true },
            iv: { type: String, required: true },
            wrapped: { type: String, required: true },
          },
          { _id: false },
        ),
      ],
      required: true,
    },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);

epochSchema.index({ conversationId: 1, epoch: -1 }, { unique: true });

export type EpochDoc = InferSchemaType<typeof epochSchema>;
export const Epoch: Model<EpochDoc> = model<EpochDoc>('Epoch', epochSchema);
