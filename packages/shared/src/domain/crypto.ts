import type { UserId } from '../ids.js';

/**
 * A sealed payload as it crosses the wire and sits in Mongo.
 *
 * The server stores this verbatim and can decrypt exactly none of it. All
 * binary fields are base64url (no padding) so they survive JSON transport.
 */
export interface CipherEnvelope {
  /** Algorithm version. Never ship unversioned crypto. */
  alg: 'RTC/v1';
  /** HKDF salt, 32 bytes. Fresh per message. */
  salt: string;
  /** AES-GCM IV, 12 bytes. Fresh per message. */
  iv: string;
  /** AES-256-GCM ciphertext with the 16-byte tag appended. */
  ct: string;
  /**
   * ECDSA P-256 signature over SHA-256(aad ‖ iv ‖ ct) by the sender's
   * identity signing key.
   *
   * Mandatory, not decoration: in a group every member holds the epoch key,
   * so a GCM tag only proves "someone in this room wrote this". Without this
   * signature any member can forge a message attributed to any other.
   */
  sig: string;
  /** Which version of the sender's identity key signed and derived this. */
  senderKeyVersion: number;
  /** Group messages only: which epoch key `ct` was sealed under. */
  epoch?: number;
}

/** What the AAD binds. Reconstructed by the reader from server-visible columns. */
export type ContentType =
  | 'text/plain'
  | 'application/rtc-file-v1'
  | 'application/rtc-wb-v1';

/** Argon2id parameters, published per account so any device can re-derive. */
export interface KdfParams {
  /** `argon2id` normally; `pbkdf2` only where wasm is blocked. */
  kdf: 'argon2id' | 'pbkdf2';
  /**
   * Argon2id memory in KiB (65536 = 64 MiB). Absent for pbkdf2.
   *
   * Explicitly `| undefined` because exactOptionalPropertyTypes is on and
   * Zod's `.optional()` produces exactly that — without it, every parsed
   * value would need a cast at the boundary.
   */
  memoryKiB?: number | undefined;
  iterations: number;
  parallelism?: number | undefined;
}

/** One entry in a user's append-only identity key log. */
export interface PublicKeyRecord {
  keyVersion: number;
  /** ECDH P-256 public key, SPKI, base64url. */
  spkiEcdh: string;
  /** ECDSA P-256 public key, SPKI, base64url. */
  spkiEcdsa: string;
  createdAt: number;
  /** Signed by this key version's own signing key. */
  selfSig: string;
  /**
   * Signed by the PREVIOUS version's signing key. Absent only on v1.
   * This is what chains the log: a server-injected key breaks the chain.
   */
  prevSig?: string;
}

export interface PublicKeyBundle {
  userId: UserId;
  current: PublicKeyRecord;
  /** Full history, ascending. Lets a client verify the chain itself. */
  log: PublicKeyRecord[];
}

/** The wrapped private key blob the server stores but cannot open. */
export interface WrappedIdentity {
  keyVersion: number;
  /** AES-256-GCM over PKCS#8, AAD-bound to userId ‖ keyVersion ‖ kdfParams. */
  iv: string;
  wrapped: string;
  kdfSalt: string;
  kdfParams: KdfParams;
}

/** One member's copy of a group epoch key. */
export interface EpochWrap {
  userId: UserId;
  /** Which of the member's key versions this was wrapped to. */
  keyVersion: number;
  iv: string;
  wrapped: string;
}

/**
 * A group room's key epoch. Rekeyed on every membership change so a joiner
 * cannot read history and a removed member cannot read the future.
 */
export interface EpochRecord {
  epoch: number;
  /** Ephemeral ECDH public key the wraps were derived from (static-ephemeral). */
  ephSpki: string;
  createdBy: UserId;
  createdAt: number;
  /** Signature by the creator over roomId ‖ epoch ‖ ephSpki ‖ wraps. */
  sig: string;
  wraps: EpochWrap[];
  reason: RekeyReason;
}

export type RekeyReason =
  | 'created'
  | 'member_added'
  | 'member_removed'
  | 'key_rotated'
  | 'age';
