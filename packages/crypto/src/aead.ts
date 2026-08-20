import { DecryptError, randomBytes, toArrayBuffer, zero } from './bytes.js';

export const IV_BYTES = 12;
export const TAG_BITS = 128;
export const SALT_BYTES = 32;

/** Import raw key material as an HKDF root. HKDF keys are always non-extractable. */
export async function importHkdfRoot(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toArrayBuffer(raw), 'HKDF', false, ['deriveKey', 'deriveBits']);
}

/**
 * Derive a single-use AES-256-GCM key.
 *
 * Non-extractable: callers can encrypt and decrypt with it but never read it
 * back out, so an XSS that reaches this key gets the ability to use it while
 * the page lives, not a secret it can exfiltrate.
 */
export async function deriveMessageKey(
  root: CryptoKey,
  salt: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(salt), info: new TextEncoder().encode(info) },
    root,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function deriveBits(
  root: CryptoKey,
  salt: Uint8Array,
  info: string,
  bits: number,
): Promise<Uint8Array> {
  const out = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: toArrayBuffer(salt), info: new TextEncoder().encode(info) },
    root,
    bits,
  );
  return new Uint8Array(out);
}

/** AES-256-GCM encrypt with a fresh random IV. Returns the IV alongside the ciphertext. */
export async function seal(
  key: CryptoKey,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<{ iv: Uint8Array; ct: Uint8Array }> {
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad), tagLength: TAG_BITS },
    key,
    toArrayBuffer(plaintext),
  );
  return { iv, ct: new Uint8Array(ct) };
}

/** AES-256-GCM encrypt with a caller-supplied IV, for the file chunk counter. */
export async function sealWithIv(
  key: CryptoKey,
  iv: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad), tagLength: TAG_BITS },
    key,
    toArrayBuffer(plaintext),
  );
  return new Uint8Array(ct);
}

/**
 * AES-256-GCM decrypt.
 *
 * Every failure — wrong key, tampered ciphertext, altered AAD — surfaces as
 * the same opaque DecryptError. Distinguishing them across a trust boundary
 * would hand an attacker an oracle.
 */
export async function open(
  key: CryptoKey,
  aad: Uint8Array,
  iv: Uint8Array,
  ct: Uint8Array,
): Promise<Uint8Array> {
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad), tagLength: TAG_BITS },
      key,
      toArrayBuffer(ct),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptError();
  }
}

/**
 * ECDSA P-256 / SHA-256 signature over the raw bytes.
 *
 * No pre-hashing: ECDSA-SHA256 hashes its input internally, so hashing first
 * would just be a second, pointless digest. Envelopes are small enough that
 * passing the concatenation directly costs nothing.
 */
export async function signBytes(signPriv: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, signPriv, toArrayBuffer(data));
  return new Uint8Array(sig); // raw r||s, 64 bytes on P-256
}

export async function verifyBytes(
  signPub: CryptoKey,
  sig: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  return crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    signPub,
    toArrayBuffer(sig),
    toArrayBuffer(data),
  );
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(data)));
}

/**
 * Static-static or static-ephemeral ECDH, imported straight into an HKDF root.
 *
 * The raw shared secret is zeroed as soon as it is imported. It still existed
 * in a JS buffer for a moment — unavoidable, since WebCrypto has no
 * ECDH->HKDF path that skips `deriveBits` — but it does not linger.
 */
export async function ecdhRoot(privateKey: CryptoKey, publicKey: CryptoKey): Promise<CryptoKey> {
  const shared = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256),
  );
  try {
    return await importHkdfRoot(shared);
  } finally {
    zero(shared);
  }
}
