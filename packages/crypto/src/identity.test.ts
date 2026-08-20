import { describe, expect, it } from 'vitest';
import {
  exportPublicKeys, generateIdentity, importPublicKeys, keyFingerprint,
  openIdentity, sealIdentity, signKeyRecord, verifyKeyLog,
} from './identity.js';
import {
  deriveAccountSecrets, deriveRecoveryKek, generateRecoveryCode,
  newKdfSalt, normalizeRecoveryCode,
} from './account.js';
import { signBytes, verifyBytes } from './aead.js';
import { DecryptError, b64uDecode, b64uEncode, toArrayBuffer, utf8 } from './bytes.js';
import { FAST_KDF, oid } from './testing.js';

const ALICE = oid('a11ce');
const BOB = oid('b0b');

describe('identity wrapping', () => {
  it('round-trips both private keys and yields usable non-extractable keys', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    const priv = await openIdentity(wrap, kek, { userId: ALICE, purpose: 'password' });

    // The recovered signing key must actually verify against the public key
    // that was published alongside it.
    const pub = await exportPublicKeys(kp);
    const { signPub } = await importPublicKeys(pub);
    const sig = await signBytes(priv.signPriv, utf8('hello'));
    expect(await verifyBytes(signPub, sig, utf8('hello'))).toBe(true);

    expect(priv.agreePriv.extractable).toBe(false);
    expect(priv.signPriv.extractable).toBe(false);
  });

  it('cannot be opened with a different password', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('right', salt, FAST_KDF);
    const { kek: wrongKek } = await deriveAccountSecrets('wrong', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    await expect(openIdentity(wrap, wrongKek, { userId: ALICE, purpose: 'password' }))
      .rejects.toThrow(DecryptError);
  });

  it('is bound to the account, so a swapped blob fails', async () => {
    // A malicious server handing Alice's wrapped key to Bob is the attack
    // AES-KW could not detect. The AAD binding is what closes it.
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    await expect(openIdentity(wrap, kek, { userId: BOB, purpose: 'password' }))
      .rejects.toThrow(DecryptError);
  });

  it('is bound to the key version, so a rollback fails', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 2, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    await expect(
      openIdentity({ ...wrap, keyVersion: 1 }, kek, { userId: ALICE, purpose: 'password' }),
    ).rejects.toThrow(DecryptError);
  });

  it('is bound to its purpose, so a password wrap is not a recovery wrap', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    await expect(openIdentity(wrap, kek, { userId: ALICE, purpose: 'recovery' }))
      .rejects.toThrow(DecryptError);
  });

  it('detects a tampered ciphertext', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const { kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const wrap = await sealIdentity(kp, kek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'password',
    });
    const bytes = b64uDecode(wrap.wrapped);
    bytes[5] = (bytes[5] ?? 0) ^ 0x01;
    await expect(
      openIdentity({ ...wrap, wrapped: b64uEncode(bytes) }, kek, { userId: ALICE, purpose: 'password' }),
    ).rejects.toThrow(DecryptError);
  });
});

describe('account secret derivation', () => {
  it('is deterministic for the same password and salt', async () => {
    const salt = newKdfSalt();
    const a = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const b = await deriveAccountSecrets('pw', salt, FAST_KDF);
    expect(a.authProof).toEqual(b.authProof);
  });

  it('produces different proofs for different salts', async () => {
    const a = await deriveAccountSecrets('pw', newKdfSalt(), FAST_KDF);
    const b = await deriveAccountSecrets('pw', newKdfSalt(), FAST_KDF);
    expect(a.authProof).not.toEqual(b.authProof);
  });

  it('keeps the KEK non-extractable so it can never be sent anywhere', async () => {
    const { kek } = await deriveAccountSecrets('pw', newKdfSalt(), FAST_KDF);
    expect(kek.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', kek)).rejects.toThrow();
  });

  it('domain-separates the auth proof from the KEK', async () => {
    // If these shared derivation material, sending authProof to the server
    // would leak the wrapping key. The distinct HKDF info strings are the
    // only thing making one password safe for both jobs.
    const salt = newKdfSalt();
    const { authProof, kek } = await deriveAccountSecrets('pw', salt, FAST_KDF);
    const probe = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: new Uint8Array(0) },
      kek,
      toArrayBuffer(utf8('x')),
    );
    expect(new Uint8Array(probe)).not.toEqual(authProof.subarray(0, 17));
    expect(authProof.length).toBe(32);
  });
});

describe('recovery code', () => {
  it('formats as 13 groups of 4 Crockford characters', () => {
    const code = generateRecoveryCode();
    expect(code.split('-')).toHaveLength(13);
    expect(code.replace(/-/g, '')).toMatch(/^[0-9ABCDEFGHJKMNPQRSTVWXYZ]{52}$/);
  });

  it('is unique across generations', () => {
    const codes = new Set(Array.from({ length: 50 }, generateRecoveryCode));
    expect(codes.size).toBe(50);
  });

  it('normalises the ways a human retypes it', () => {
    const code = generateRecoveryCode();
    const mangled = code.toLowerCase().replace(/-/g, ' ');
    expect(normalizeRecoveryCode(mangled)).toBe(normalizeRecoveryCode(code));
  });

  it('restores the identity when the password is gone', async () => {
    // The whole point: E2EE means a server-side reset cannot recover history,
    // so this code is the only escape hatch that exists.
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const code = generateRecoveryCode();
    const recoveryKek = await deriveRecoveryKek(code, salt);
    const wrap = await sealIdentity(kp, recoveryKek, {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'recovery',
    });

    const reKek = await deriveRecoveryKek(code.toLowerCase(), salt);
    const priv = await openIdentity(wrap, reKek, { userId: ALICE, purpose: 'recovery' });
    const pub = await exportPublicKeys(kp);
    const { signPub } = await importPublicKeys(pub);
    const sig = await signBytes(priv.signPriv, utf8('recovered'));
    expect(await verifyBytes(signPub, sig, utf8('recovered'))).toBe(true);
  });

  it('rejects a wrong recovery code', async () => {
    const kp = await generateIdentity();
    const salt = newKdfSalt();
    const wrap = await sealIdentity(kp, await deriveRecoveryKek(generateRecoveryCode(), salt), {
      userId: ALICE, keyVersion: 1, kdfSalt: salt, kdfParams: FAST_KDF, purpose: 'recovery',
    });
    const wrongKek = await deriveRecoveryKek(generateRecoveryCode(), salt);
    await expect(openIdentity(wrap, wrongKek, { userId: ALICE, purpose: 'recovery' }))
      .rejects.toThrow(DecryptError);
  });
});

describe('key log verification', () => {
  const record = async (v: number, kp: Awaited<ReturnType<typeof generateIdentity>>, prev?: CryptoKey) =>
    signKeyRecord(ALICE, { ...(await exportPublicKeys(kp)), keyVersion: v, createdAt: 1000 * v }, kp.sign.privateKey, prev);

  it('accepts a single self-signed v1 record', async () => {
    const kp = await generateIdentity();
    expect(await verifyKeyLog(ALICE, [await record(1, kp)])).toBe(true);
  });

  it('accepts a correctly chained rotation', async () => {
    const v1 = await generateIdentity();
    const v2 = await generateIdentity();
    const log = [await record(1, v1), await record(2, v2, v1.sign.privateKey)];
    expect(await verifyKeyLog(ALICE, log)).toBe(true);
  });

  it('rejects a rotation that is not counter-signed by the previous key', async () => {
    // This is the server-injected-key case: the server can append a record,
    // but it cannot sign with a key it does not hold, so the chain breaks.
    const v1 = await generateIdentity();
    const v2 = await generateIdentity();
    const injected = await record(2, v2); // self-signed only, no prevSig
    expect(await verifyKeyLog(ALICE, [await record(1, v1), injected])).toBe(false);
  });

  it('rejects a rotation counter-signed by the wrong key', async () => {
    const v1 = await generateIdentity();
    const v2 = await generateIdentity();
    const attacker = await generateIdentity();
    const log = [await record(1, v1), await record(2, v2, attacker.sign.privateKey)];
    expect(await verifyKeyLog(ALICE, log)).toBe(false);
  });

  it('rejects a v1 record that claims a predecessor', async () => {
    const v1 = await generateIdentity();
    const other = await generateIdentity();
    const bogus = await record(1, v1, other.sign.privateKey);
    expect(await verifyKeyLog(ALICE, [bogus])).toBe(false);
  });

  it('rejects gaps and reordering in the version sequence', async () => {
    const v1 = await generateIdentity();
    const v2 = await generateIdentity();
    const r1 = await record(1, v1);
    const r2 = await record(2, v2, v1.sign.privateKey);
    expect(await verifyKeyLog(ALICE, [r2, r1])).toBe(false);
    expect(await verifyKeyLog(ALICE, [r2])).toBe(false);
  });

  it('rejects a record whose signature covers a different user id', async () => {
    // Otherwise Bob's valid record could be replayed into Alice's key log.
    const kp = await generateIdentity();
    const forBob = await signKeyRecord(
      BOB, { ...(await exportPublicKeys(kp)), keyVersion: 1, createdAt: 1 }, kp.sign.privateKey,
    );
    expect(await verifyKeyLog(ALICE, [forBob])).toBe(false);
    expect(await verifyKeyLog(BOB, [forBob])).toBe(true);
  });

  it('rejects an empty log', async () => {
    expect(await verifyKeyLog(ALICE, [])).toBe(false);
  });
});

describe('key fingerprint (TOFU pin)', () => {
  it('is stable for the same keys and differs for others', async () => {
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    expect(await keyFingerprint(a)).toBe(await keyFingerprint(a));
    expect(await keyFingerprint(a)).not.toBe(await keyFingerprint(b));
  });

  it('changes if either key changes', async () => {
    const a = await exportPublicKeys(await generateIdentity());
    const b = await exportPublicKeys(await generateIdentity());
    expect(await keyFingerprint({ ...a, spkiEcdsa: b.spkiEcdsa })).not.toBe(await keyFingerprint(a));
    expect(await keyFingerprint({ ...a, spkiEcdh: b.spkiEcdh })).not.toBe(await keyFingerprint(a));
  });
});
