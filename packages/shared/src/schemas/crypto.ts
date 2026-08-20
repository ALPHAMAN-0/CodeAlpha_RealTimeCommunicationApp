import { z } from 'zod';
import { LIMITS } from '../constants.js';
import { b64url, b64urlExact, userId } from './common.js';

/** Wire schema for a sealed payload. Mirrors domain/crypto.ts CipherEnvelope. */
export const cipherEnvelopeSchema = z.strictObject({
  alg: z.literal('RTC/v1'),
  salt: b64urlExact(32, 'salt'),
  iv: b64urlExact(12, 'iv'),
  ct: b64url(LIMITS.CIPHERTEXT_MAX, 'ciphertext').min(1),
  /** ECDSA P-256 signature, raw r||s = 64 bytes. */
  sig: b64urlExact(64, 'sig'),
  senderKeyVersion: z.number().int().min(1).max(10_000),
  epoch: z.number().int().min(0).max(1_000_000).optional(),
});

export const kdfParamsSchema = z.strictObject({
  kdf: z.enum(['argon2id', 'pbkdf2']),
  memoryKiB: z.number().int().min(8192).max(1_048_576).optional(),
  iterations: z.number().int().min(1).max(1_000_000),
  parallelism: z.number().int().min(1).max(16).optional(),
});

export const publicKeyRecordSchema = z.strictObject({
  keyVersion: z.number().int().min(1).max(10_000),
  spkiEcdh: b64url(200, 'spkiEcdh').min(1),
  spkiEcdsa: b64url(200, 'spkiEcdsa').min(1),
  createdAt: z.number().int().min(0),
  selfSig: b64urlExact(64, 'selfSig'),
  prevSig: b64urlExact(64, 'prevSig').optional(),
});

export const wrappedIdentitySchema = z.strictObject({
  keyVersion: z.number().int().min(1).max(10_000),
  iv: b64urlExact(12, 'iv'),
  wrapped: b64url(1024, 'wrapped').min(1),
  kdfSalt: b64urlExact(32, 'kdfSalt'),
  kdfParams: kdfParamsSchema,
});

export const epochWrapSchema = z.strictObject({
  userId: userId(),
  keyVersion: z.number().int().min(1).max(10_000),
  iv: b64urlExact(12, 'iv'),
  wrapped: b64url(256, 'wrapped').min(1),
});

export const epochRecordSchema = z.strictObject({
  epoch: z.number().int().min(1).max(1_000_000),
  ephSpki: b64url(200, 'ephSpki').min(1),
  createdBy: userId(),
  createdAt: z.number().int().min(0),
  sig: b64urlExact(64, 'sig'),
  wraps: z.array(epochWrapSchema).min(1).max(64),
  reason: z.enum(['created', 'member_added', 'member_removed', 'key_rotated', 'age']),
});
