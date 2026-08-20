import { z } from 'zod';
import { b64url, b64urlExact, displayName, email } from './common.js';
import { kdfParamsSchema, publicKeyRecordSchema, wrappedIdentitySchema } from './crypto.js';

/**
 * `authProof` is derived in the browser from the password via Argon2id+HKDF,
 * so the server never sees the password itself. It is still password-
 * EQUIVALENT, so the server re-hashes it with server-side Argon2id — treating
 * it as a plain token would make a DB leak a direct login credential.
 */
const authProof = () => b64urlExact(32, 'authProof');

export const registerBodySchema = z.strictObject({
  /**
   * The account id, generated CLIENT-side as a 24-hex ObjectId.
   *
   * This is not an oversight — it resolves a real ordering problem. The
   * identity key record is signed over the account id, so that Bob's valid
   * key record cannot be replayed into Alice's key log. But the client must
   * sign before it registers, so it cannot wait for a server-assigned id.
   *
   * The alternatives are worse: a second round trip leaves a window where an
   * account exists with no keys, and binding the signature to the email
   * instead would break the moment an address changes. Mongo supports
   * client-generated _id by design, ids here are not secrets, and the unique
   * index rejects the astronomically unlikely collision.
   */
  userId: z.string().regex(/^[0-9a-f]{24}$/, 'invalid account id'),
  email: email(),
  displayName: displayName(),
  authProof: authProof(),
  kdfSalt: b64urlExact(32, 'kdfSalt'),
  kdfParams: kdfParamsSchema,
  identity: z.strictObject({
    publicKeys: publicKeyRecordSchema,
    /** Wrapped under the password-derived KEK. */
    passwordWrap: wrappedIdentitySchema,
    /** Wrapped under a one-time recovery code, so a reset can restore history. */
    recoveryWrap: wrappedIdentitySchema,
  }),
});

export const loginBodySchema = z.strictObject({
  email: email(),
  authProof: authProof(),
});

/** POST, not GET, so an email never lands in an access log or a Referer header. */
export const kdfParamsBodySchema = z.strictObject({ email: email() });

export const changePasswordBodySchema = z.strictObject({
  oldAuthProof: authProof(),
  newAuthProof: authProof(),
  kdfSalt: b64urlExact(32, 'kdfSalt'),
  kdfParams: kdfParamsSchema,
  /** Re-wrapped client-side under the new KEK; applied in the same write. */
  passwordWrap: wrappedIdentitySchema,
});

export const publishKeysBodySchema = z.strictObject({
  publicKeys: publicKeyRecordSchema,
  passwordWrap: wrappedIdentitySchema,
});

export const createConversationBodySchema = z.strictObject({
  type: z.enum(['dm', 'group']),
  memberIds: z.array(z.string().regex(/^[0-9a-f]{24}$/)).min(1).max(32),
  /** Sealed group title. Omitted for DMs, which have no title. */
  titleEnvelope: z
    .strictObject({
      alg: z.literal('RTC/v1'),
      salt: b64urlExact(32, 'salt'),
      iv: b64urlExact(12, 'iv'),
      ct: b64url(4096, 'ct').min(1),
      sig: b64urlExact(64, 'sig'),
      senderKeyVersion: z.number().int().min(1),
      epoch: z.number().int().min(0).optional(),
    })
    .optional(),
});

export const objectIdParamSchema = z.strictObject({
  id: z.string().regex(/^[0-9a-f]{24}$/, 'invalid id'),
});

/**
 * Inferred request-body types.
 *
 * Exported so handlers name a type instead of writing an inline
 * `import('zod').output<...>` annotation, which is both unreadable and
 * duplicated at every call site.
 */
export type RegisterBody = z.output<typeof registerBodySchema>;
export type LoginBody = z.output<typeof loginBodySchema>;
export type KdfParamsBody = z.output<typeof kdfParamsBodySchema>;
export type ChangePasswordBody = z.output<typeof changePasswordBodySchema>;
export type PublishKeysBody = z.output<typeof publishKeysBodySchema>;
export type CreateConversationBody = z.output<typeof createConversationBodySchema>;
