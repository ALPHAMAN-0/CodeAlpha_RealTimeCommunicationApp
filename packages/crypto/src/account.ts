import { argon2id, createSHA256, pbkdf2 as wasmPbkdf2 } from 'hash-wasm';
import type { KdfParams } from '@rtc/shared';
import { deriveBits, importHkdfRoot } from './aead.js';
import { randomBytes, toArrayBuffer, zero } from './bytes.js';

/**
 * Argon2id parameters for the account KDF.
 *
 * 64 MiB / t=3 is chosen because the KEK derived here is the ONLY thing
 * between a dump of the server's wrapped-key blobs and every user's entire
 * message history. That is exactly the place where memory hardness earns its
 * cost. PBKDF2 at OWASP's 600k iterations is roughly three orders of
 * magnitude cheaper to attack per dollar on GPUs.
 */
export const DEFAULT_KDF_PARAMS: KdfParams = {
  kdf: 'argon2id',
  memoryKiB: 65_536,
  iterations: 3,
  parallelism: 1,
};

/** Declared fallback for environments where wasm is blocked by policy. */
export const PBKDF2_FALLBACK_PARAMS: KdfParams = {
  kdf: 'pbkdf2',
  iterations: 600_000,
};

const MASTER_BYTES = 64;

export interface AccountSecrets {
  /**
   * Sent to the server, which re-hashes it with server-side Argon2id.
   *
   * It must be re-hashed: `authProof` is password-EQUIVALENT, so storing it
   * directly would make a database leak a set of working login credentials.
   * "We hash on the client so the server never sees the password" is only
   * meaningful with this domain separation plus server-side rehashing —
   * otherwise whatever you send simply becomes the password.
   */
  authProof: Uint8Array;
  /** Wraps the identity keys. NEVER leaves the browser. */
  kek: CryptoKey;
}

async function stretch(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  if (params.kdf === 'argon2id') {
    return argon2id({
      password,
      salt,
      parallelism: params.parallelism ?? 1,
      iterations: params.iterations,
      memorySize: params.memoryKiB ?? 65_536,
      hashLength: MASTER_BYTES,
      outputType: 'binary',
    });
  }
  return wasmPbkdf2({
    password,
    salt,
    iterations: params.iterations,
    hashLength: MASTER_BYTES,
    hashFunction: createSHA256(),
    outputType: 'binary',
  });
}

/**
 * One password, two independent secrets, via HKDF domain separation.
 *
 * Asking the user for a separate E2EE passphrase would be transparently
 * correct but poor UX; deriving both from one password is safe *provided* the
 * two derivations are domain-separated and the KEK branch never crosses the
 * network. That is what the distinct `info` strings buy.
 */
export async function deriveAccountSecrets(
  password: string,
  kdfSalt: Uint8Array,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<AccountSecrets> {
  const master = await stretch(password, kdfSalt, params);
  try {
    const root = await importHkdfRoot(master);
    const authProof = await deriveBits(root, kdfSalt, 'rtc/v1/auth', 256);
    const kek = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(kdfSalt), info: new TextEncoder().encode('rtc/v1/e2ee-kek') },
      root,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    return { authProof, kek };
  } finally {
    zero(master);
  }
}

export const newKdfSalt = (): Uint8Array => randomBytes(32);

/** Crockford base32: no I, L, O or U, so it cannot be misread aloud. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * A 256-bit recovery code, shown exactly once at registration.
 *
 * This is the only escape hatch from the defining property of E2EE: a
 * server-side password reset cannot recover message history, because the
 * server never held the key. Without this code, a forgotten password destroys
 * the history permanently — the reset UI has to say so in plain language
 * rather than discovering it later.
 */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(32);
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += CROCKFORD[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += CROCKFORD[(acc << (5 - bits)) & 31];
  zero(bytes);
  return out.match(/.{1,4}/g)!.join('-');
}

/** Accept the code however the user retyped it: spaces, dashes, lower case, O-for-0. */
export function normalizeRecoveryCode(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/U/g, 'V');
}

function decodeCrockford(code: string): Uint8Array {
  const s = normalizeRecoveryCode(code);
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of s) {
    const v = CROCKFORD.indexOf(ch);
    if (v < 0) throw new Error('invalid recovery code character');
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

/**
 * KEK for the recovery wrap — HKDF only, no Argon2id, and that is correct.
 *
 * Memory hardness protects LOW-entropy secrets from brute force. A uniformly
 * random 256-bit code has nothing to brute force, so a slow KDF here would
 * add a second of latency and zero security. Running Argon2id on it anyway
 * would be cargo cult, not defence in depth.
 */
export async function deriveRecoveryKek(recoveryCode: string, salt: Uint8Array): Promise<CryptoKey> {
  const raw = decodeCrockford(recoveryCode);
  try {
    const root = await importHkdfRoot(raw);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(salt), info: new TextEncoder().encode('rtc/v1/recovery-kek') },
      root,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    zero(raw);
  }
}
