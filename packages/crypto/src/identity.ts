import { packAad, unpackParts, identityWrapAad } from './aad.js';
import { open, seal, signBytes, verifyBytes } from './aead.js';
import { b64uDecode, b64uEncode, toArrayBuffer, utf8, zero } from './bytes.js';
import type { KdfParams, PublicKeyRecord, WrappedIdentity } from '@rtc/shared';

const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

/** The two private keys a signed-in user holds. Non-extractable in normal use. */
export interface IdentityPrivate {
  /** ECDH P-256: derives shared secrets and unwraps epoch keys. */
  agreePriv: CryptoKey;
  /** ECDSA P-256: authenticates this user as the author of each message. */
  signPriv: CryptoKey;
}

export interface IdentityPublic {
  agreePub: CryptoKey;
  signPub: CryptoKey;
}

/** Canonical serialisation of KDF params, so the AAD binding is stable. */
export const kdfParamsString = (p: KdfParams): string =>
  `${p.kdf}|m=${p.memoryKiB ?? 0}|t=${p.iterations}|p=${p.parallelism ?? 1}`;

/**
 * Generate a fresh identity.
 *
 * Deliberately EXTRACTABLE: the private keys must be exported once so they can
 * be wrapped and uploaded, which is what makes the account survive a reinstall
 * or reach a second device. `sealIdentity` re-imports them non-extractable
 * immediately afterwards and drops these handles.
 */
export async function generateIdentity(): Promise<{
  agree: CryptoKeyPair;
  sign: CryptoKeyPair;
}> {
  const [agree, sign] = await Promise.all([
    crypto.subtle.generateKey(ECDH_P256, true, ['deriveKey', 'deriveBits']),
    crypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']),
  ]);
  return { agree: agree as CryptoKeyPair, sign: sign as CryptoKeyPair };
}

export async function exportPublicKeys(kp: {
  agree: CryptoKeyPair;
  sign: CryptoKeyPair;
}): Promise<{ spkiEcdh: string; spkiEcdsa: string }> {
  const [ecdh, ecdsa] = await Promise.all([
    crypto.subtle.exportKey('spki', kp.agree.publicKey),
    crypto.subtle.exportKey('spki', kp.sign.publicKey),
  ]);
  return { spkiEcdh: b64uEncode(new Uint8Array(ecdh)), spkiEcdsa: b64uEncode(new Uint8Array(ecdsa)) };
}

export async function importPublicKeys(rec: {
  spkiEcdh: string;
  spkiEcdsa: string;
}): Promise<IdentityPublic> {
  const [agreePub, signPub] = await Promise.all([
    crypto.subtle.importKey('spki', toArrayBuffer(b64uDecode(rec.spkiEcdh)), ECDH_P256, true, []),
    crypto.subtle.importKey('spki', toArrayBuffer(b64uDecode(rec.spkiEcdsa)), ECDSA_P256, true, ['verify']),
  ]);
  return { agreePub, signPub };
}

/**
 * Wrap both private keys under a KEK.
 *
 * AES-256-GCM with AAD, not AES-KW. AES-KW has no nonce and no associated
 * data, so a malicious server could swap one user's wrapped blob for
 * another's or roll a user back to a retired key version and neither would be
 * detectable. Binding userId + keyVersion + kdfParams closes both.
 */
export async function sealIdentity(
  kp: { agree: CryptoKeyPair; sign: CryptoKeyPair },
  kek: CryptoKey,
  meta: { userId: string; keyVersion: number; kdfSalt: Uint8Array; kdfParams: KdfParams; purpose: 'password' | 'recovery' },
): Promise<WrappedIdentity> {
  const [agreeRaw, signRaw] = await Promise.all([
    crypto.subtle.exportKey('pkcs8', kp.agree.privateKey),
    crypto.subtle.exportKey('pkcs8', kp.sign.privateKey),
  ]);
  const bundle = packAad(new Uint8Array(agreeRaw), new Uint8Array(signRaw));
  try {
    const aad = identityWrapAad({
      userId: meta.userId,
      keyVersion: meta.keyVersion,
      kdfParams: kdfParamsString(meta.kdfParams),
      purpose: meta.purpose,
    });
    const { iv, ct } = await seal(kek, aad, bundle);
    return {
      keyVersion: meta.keyVersion,
      iv: b64uEncode(iv),
      wrapped: b64uEncode(ct),
      kdfSalt: b64uEncode(meta.kdfSalt),
      kdfParams: meta.kdfParams,
    };
  } finally {
    zero(bundle);
  }
}

/**
 * Unwrap an identity and re-import it NON-EXTRACTABLE.
 *
 * This is the step that limits XSS damage: once the key lives in IndexedDB as
 * a non-extractable CryptoKey, injected script can use it while the page is
 * alive but cannot steal it for offline or future decryption. The raw PKCS#8
 * exists only inside this function and is zeroed on the way out.
 */
export async function openIdentity(
  wrap: WrappedIdentity,
  kek: CryptoKey,
  meta: { userId: string; purpose: 'password' | 'recovery' },
): Promise<IdentityPrivate> {
  const aad = identityWrapAad({
    userId: meta.userId,
    keyVersion: wrap.keyVersion,
    kdfParams: kdfParamsString(wrap.kdfParams),
    purpose: meta.purpose,
  });
  const bundle = await open(kek, aad, b64uDecode(wrap.iv), b64uDecode(wrap.wrapped));
  try {
    const parts = unpackParts(bundle);
    const agreeRaw = parts[0];
    const signRaw = parts[1];
    if (!agreeRaw || !signRaw || parts.length !== 2) {
      throw new Error('malformed identity bundle');
    }
    const [agreePriv, signPriv] = await Promise.all([
      crypto.subtle.importKey('pkcs8', toArrayBuffer(agreeRaw), ECDH_P256, false, ['deriveKey', 'deriveBits']),
      crypto.subtle.importKey('pkcs8', toArrayBuffer(signRaw), ECDSA_P256, false, ['sign']),
    ]);
    return { agreePriv, signPriv };
  } finally {
    zero(bundle);
  }
}

/** Bytes a key-log entry commits to. Both signatures cover exactly this. */
const keyRecordPayload = (userId: string, r: Pick<PublicKeyRecord, 'keyVersion' | 'spkiEcdh' | 'spkiEcdsa'>) =>
  packAad('rtc/v1/key-record', userId, String(r.keyVersion), r.spkiEcdh, r.spkiEcdsa);

/**
 * Sign a key-log entry.
 *
 * `prevSign` chains this version to the previous one. That chain is what makes
 * a server-injected key detectable: the server can append a record, but it
 * cannot produce a signature from a key it does not hold, so the chain breaks.
 */
export async function signKeyRecord(
  userId: string,
  rec: Pick<PublicKeyRecord, 'keyVersion' | 'spkiEcdh' | 'spkiEcdsa' | 'createdAt'>,
  signPriv: CryptoKey,
  prevSignPriv?: CryptoKey,
): Promise<PublicKeyRecord> {
  const payload = keyRecordPayload(userId, rec);
  const selfSig = await signBytes(signPriv, payload);
  const prevSig = prevSignPriv ? await signBytes(prevSignPriv, payload) : undefined;
  return {
    keyVersion: rec.keyVersion,
    spkiEcdh: rec.spkiEcdh,
    spkiEcdsa: rec.spkiEcdsa,
    createdAt: rec.createdAt,
    selfSig: b64uEncode(selfSig),
    ...(prevSig ? { prevSig: b64uEncode(prevSig) } : {}),
  };
}

/**
 * Verify a user's whole key log.
 *
 * Checks that versions increase by exactly one, that each record is
 * self-signed, and that each rotation is counter-signed by the key it
 * replaces.
 *
 * What this does NOT give you: protection against a server that was
 * malicious from the very first contact. A perfectly-chained log of keys the
 * server generated itself verifies fine. Only out-of-band comparison of the
 * safety number in ./fingerprint.ts closes that, and only if a human does it.
 * This is TOFU plus tamper-evidence, not key transparency.
 */
export async function verifyKeyLog(userId: string, log: readonly PublicKeyRecord[]): Promise<boolean> {
  if (log.length === 0) return false;
  let prevSignPub: CryptoKey | undefined;
  for (let i = 0; i < log.length; i++) {
    const rec = log[i]!;
    if (rec.keyVersion !== i + 1) return false;
    const { signPub } = await importPublicKeys(rec);
    const payload = keyRecordPayload(userId, rec);
    if (!(await verifyBytes(signPub, b64uDecode(rec.selfSig), payload))) return false;
    if (i > 0) {
      if (!rec.prevSig || !prevSignPub) return false;
      if (!(await verifyBytes(prevSignPub, b64uDecode(rec.prevSig), payload))) return false;
    } else if (rec.prevSig) {
      return false; // v1 has nothing to chain to
    }
    prevSignPub = signPub;
  }
  return true;
}

/** Stable per-peer pin: what TOFU compares on every subsequent fetch. */
export async function keyFingerprint(rec: Pick<PublicKeyRecord, 'spkiEcdh' | 'spkiEcdsa'>): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    toArrayBuffer(packAad(utf8(rec.spkiEcdh), utf8(rec.spkiEcdsa))),
  );
  return b64uEncode(new Uint8Array(digest));
}
