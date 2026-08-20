import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';
import { env, keyBuf } from '../config/env.js';

/**
 * Application-level AES-256-GCM for the fields that CANNOT be end-to-end
 * encrypted — currently just email addresses, which the server must be able
 * to look up.
 *
 * Deliberately NOT MongoDB CSFLE. With the `local` KMS provider the master
 * key sits in the same .env as MONGO_URI, so CSFLE would add a native
 * dependency, a schema map and a mongocryptd deployment step in exchange for
 * exactly zero additional security — while breaking the one-command startup
 * this project promises. Shipping it to look enterprise-grade would be
 * security theatre.
 *
 * Honest scope, repeated in SECURITY.md: this protects a stolen database dump
 * or backup. It does not protect against compromise of the application host,
 * because that host holds the key.
 *
 * Wire format: [1B version][12B IV][ciphertext ‖ 16B tag]
 */
const VERSION = 1;
const IV_LEN = 12;
const TAG_LEN = 16;

const dek = () => keyBuf(env.DATA_ENCRYPTION_KEY).subarray(0, 32);

/**
 * AAD binds the value to its exact location, so a ciphertext cannot be copied
 * from one document's field into another's — for instance moving one user's
 * sealed email onto another user's row.
 */
const aadFor = (collection: string, field: string, docId: string): Buffer =>
  Buffer.from(`${collection}|${field}|${docId}`, 'utf8');

export function sealField(plaintext: string, collection: string, field: string, docId: string): Buffer {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', dek(), iv, { authTagLength: TAG_LEN });
  cipher.setAAD(aadFor(collection, field, docId));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([Buffer.of(VERSION), iv, ct, cipher.getAuthTag()]);
}

export function openField(blob: Buffer, collection: string, field: string, docId: string): string {
  if (blob.length < 1 + IV_LEN + TAG_LEN) throw new Error('sealed field too short');
  const version = blob[0];
  if (version !== VERSION) throw new Error(`unsupported sealed field version ${version}`);
  const iv = blob.subarray(1, 1 + IV_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(1 + IV_LEN, blob.length - TAG_LEN);
  const decipher = createDecipheriv('aes-256-gcm', dek(), iv, { authTagLength: TAG_LEN });
  decipher.setAAD(aadFor(collection, field, docId));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * Deterministic HMAC index, so "find the account for this email" stays a
 * single indexed query against encrypted data.
 *
 * This leaks equality and nothing else — two identical emails produce the
 * same index. That is a well-understood, bounded trade and exactly the right
 * primitive for a unique-lookup column. It is emphatically NOT a general
 * "searchable encryption" scheme, and it is not used as one.
 */
export const blindIndex = (value: string): Buffer =>
  createHmac('sha256', keyBuf(env.BLIND_INDEX_KEY))
    .update(value.normalize('NFKC').toLowerCase().trim())
    .digest();
