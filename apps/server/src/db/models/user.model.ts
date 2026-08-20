import { Schema, model, type InferSchemaType, type Model } from 'mongoose';

/**
 * A user account.
 *
 * The email is stored sealed (AES-256-GCM) with a separate HMAC blind index
 * for lookup, so a database dump yields neither addresses nor a usable
 * login credential.
 */
const publicKeyRecordSchema = new Schema(
  {
    keyVersion: { type: Number, required: true },
    spkiEcdh: { type: String, required: true },
    spkiEcdsa: { type: String, required: true },
    createdAt: { type: Number, required: true },
    selfSig: { type: String, required: true },
    prevSig: { type: String },
  },
  { _id: false },
);

const wrappedIdentitySchema = new Schema(
  {
    keyVersion: { type: Number, required: true },
    iv: { type: String, required: true },
    wrapped: { type: String, required: true },
    kdfSalt: { type: String, required: true },
    kdfParams: {
      kdf: { type: String, required: true, enum: ['argon2id', 'pbkdf2'] },
      memoryKiB: { type: Number },
      iterations: { type: Number, required: true },
      parallelism: { type: Number },
    },
  },
  { _id: false },
);

const userSchema = new Schema(
  {
    /** Sealed field; never queryable. */
    emailSealed: { type: Buffer, required: true },
    /** HMAC of the normalised email. The only way to find an account. */
    emailIndex: { type: Buffer, required: true },
    displayName: { type: String, required: true, maxlength: 40 },
    /** Derived from the id at creation — no avatar uploads needed for a demo. */
    avatarColor: { type: String, required: true },

    /** Argon2id over the client-derived authProof. */
    proofHash: { type: String, required: true },
    /** Client's KDF salt and params, needed before it can derive anything. */
    kdfSalt: { type: String, required: true },
    kdfParams: {
      kdf: { type: String, required: true, enum: ['argon2id', 'pbkdf2'] },
      memoryKiB: { type: Number },
      iterations: { type: Number, required: true },
      parallelism: { type: Number },
    },

    /**
     * Append-only identity key log. The server refuses deletions and refuses
     * to lower a version, so tampering shows up as a broken signature chain
     * on the client.
     */
    keyLog: { type: [publicKeyRecordSchema], required: true, default: [] },
    keyVersion: { type: Number, required: true, default: 1 },
    /** Opaque to the server: wrapped under a key it never sees. */
    passwordWrap: { type: wrappedIdentitySchema, required: true },
    recoveryWrap: { type: wrappedIdentitySchema, required: true },

    presence: {
      status: { type: String, required: true, enum: ['online', 'offline'], default: 'offline' },
      lastSeenAt: { type: Date, required: true, default: () => new Date() },
    },

    /** Consecutive failed logins, for per-account progressive lockout. */
    failedLogins: { type: Number, required: true, default: 0 },
    lockedUntil: { type: Date },
  },
  { timestamps: true, strict: 'throw' },
);

// Unique lookup on the blind index. Login stays one indexed query even though
// the address itself is encrypted at rest.
userSchema.index({ emailIndex: 1 }, { unique: true });
userSchema.index({ 'presence.status': 1, 'presence.lastSeenAt': -1 });

export type UserDoc = InferSchemaType<typeof userSchema>;
export const User: Model<UserDoc> = model<UserDoc>('User', userSchema);
