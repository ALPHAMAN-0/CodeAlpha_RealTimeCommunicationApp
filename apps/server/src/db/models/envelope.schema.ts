import { Schema } from 'mongoose';

/**
 * A sealed payload as persisted.
 *
 * Every field here is opaque to the server. It is stored, indexed by its
 * surrounding metadata, fanned out, and never interpreted.
 */
export const envelopeSchema = new Schema(
  {
    alg: { type: String, required: true, enum: ['RTC/v1'] },
    salt: { type: String, required: true },
    iv: { type: String, required: true },
    ct: { type: String, required: true },
    /** Per-sender ECDSA signature. Verified by RECIPIENTS, not by us. */
    sig: { type: String, required: true },
    senderKeyVersion: { type: Number, required: true },
    epoch: { type: Number },
  },
  { _id: false },
);
