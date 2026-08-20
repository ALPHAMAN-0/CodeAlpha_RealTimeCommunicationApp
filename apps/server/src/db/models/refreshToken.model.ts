import { Schema, model, type InferSchemaType, type Model } from 'mongoose';

/**
 * One refresh token. Rotated on every use, with reuse detection.
 *
 * Only the SHA-256 of the token is stored — a database dump must not yield
 * working sessions.
 */
const refreshTokenSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    /** All tokens descended from one login. Revoked together on reuse. */
    familyId: { type: String, required: true },
    tokenHash: { type: String, required: true },
    prevTokenHash: { type: String },

    issuedAt: { type: Date, required: true, default: () => new Date() },
    /** Sliding expiry for this individual token. */
    expiresAt: { type: Date, required: true },
    /** Hard ceiling for the whole family, so a session cannot slide forever. */
    familyExpiresAt: { type: Date, required: true },

    /** Set the moment this token is exchanged. A second use is the alarm. */
    usedAt: { type: Date },
    replacedByHash: { type: String },
    revokedAt: { type: Date },
    revokedReason: { type: String, enum: ['logout', 'logout-all', 'reuse', 'password-change', 'expired'] },

    /** Hashed, so anomaly detection does not require a plaintext IP log. */
    uaHash: { type: String },
    ipHash: { type: String },
  },
  { strict: 'throw' },
);

refreshTokenSchema.index({ tokenHash: 1 }, { unique: true });
// TTL sweep: expired rows delete themselves rather than accumulating.
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
refreshTokenSchema.index({ userId: 1, familyId: 1 });

export type RefreshTokenDoc = InferSchemaType<typeof refreshTokenSchema>;
export const RefreshToken: Model<RefreshTokenDoc> = model<RefreshTokenDoc>('RefreshToken', refreshTokenSchema);
