/**
 * Test-only helpers. Not exported from the package index.
 *
 * KDF params here are deliberately weak (8 MiB / 1 pass) so the suite runs in
 * seconds. Production uses DEFAULT_KDF_PARAMS — a test that took 1s per
 * derivation would simply not get written, which is a worse outcome than
 * testing the pipeline at reduced cost.
 */
import type { KdfParams } from '@rtc/shared';
import { deriveAccountSecrets, newKdfSalt } from './account.js';
import { generateIdentity, exportPublicKeys, openIdentity, sealIdentity } from './identity.js';
import type { IdentityPrivate } from './identity.js';

export const FAST_KDF: KdfParams = { kdf: 'argon2id', memoryKiB: 8192, iterations: 1, parallelism: 1 };

export interface TestUser {
  userId: string;
  keyVersion: number;
  priv: IdentityPrivate;
  pub: { spkiEcdh: string; spkiEcdsa: string };
  /** Kept so tests can re-derive and exercise the unwrap path. */
  password: string;
  kdfSalt: Uint8Array;
}

/** Build a user the way registration does: generate, wrap, unwrap non-extractable. */
export async function makeUser(userId: string, password = 'correct horse battery staple'): Promise<TestUser> {
  const kp = await generateIdentity();
  const pub = await exportPublicKeys(kp);
  const kdfSalt = newKdfSalt();
  const { kek } = await deriveAccountSecrets(password, kdfSalt, FAST_KDF);
  const wrap = await sealIdentity(kp, kek, {
    userId,
    keyVersion: 1,
    kdfSalt,
    kdfParams: FAST_KDF,
    purpose: 'password',
  });
  const priv = await openIdentity(wrap, kek, { userId, purpose: 'password' });
  return { userId, keyVersion: 1, priv, pub, password, kdfSalt };
}

/** 24-hex ids, so test values are shaped like the real Mongo ObjectIds. */
export const oid = (seed: string): string =>
  seed.padEnd(24, '0').slice(0, 24).replace(/[^0-9a-f]/g, '1');
