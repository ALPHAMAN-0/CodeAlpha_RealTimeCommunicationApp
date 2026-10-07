// Must stay the first import: config/env.ts validates process.env the moment
// it is loaded and exits the process if anything is missing.
import '../__tests__/setup.js';
import { describe, expect, it } from 'vitest';
import { blindIndex, openField, sealField } from './sealedField.js';

const EMAIL = 'alice@demo.dev';
const ALICE = 'a'.repeat(24);
const BOB = 'b'.repeat(24);

describe('sealed fields', () => {
  it('round-trips a value, with a fresh IV each time', () => {
    const blob = sealField(EMAIL, 'users', 'email', ALICE);
    expect(openField(blob, 'users', 'email', ALICE)).toBe(EMAIL);
    // What reaches the database must not contain the address...
    expect(blob.includes(Buffer.from(EMAIL))).toBe(false);
    // ...and sealing it twice must not reveal that the two rows are equal.
    expect(sealField(EMAIL, 'users', 'email', ALICE).equals(blob)).toBe(false);
  });

  it('refuses a ciphertext moved to another document, field or collection', () => {
    // The AAD binds collection | field | document id. Without it, one user's
    // sealed email could be copied onto another user's row and still decrypt.
    const blob = sealField(EMAIL, 'users', 'email', ALICE);
    expect(() => openField(blob, 'users', 'email', BOB)).toThrow();
    expect(() => openField(blob, 'users', 'phone', ALICE)).toThrow();
    expect(() => openField(blob, 'admins', 'email', ALICE)).toThrow();
  });

  it('refuses a tampered, truncated or unknown-version blob', () => {
    const blob = sealField(EMAIL, 'users', 'email', ALICE);
    // One flipped bit in the IV, the ciphertext and the tag, in turn.
    for (const index of [1, 13, blob.length - 1]) {
      const tampered = Buffer.from(blob);
      tampered[index] = tampered[index]! ^ 0x01;
      expect(() => openField(tampered, 'users', 'email', ALICE), `byte ${index}`).toThrow();
    }

    const wrongVersion = Buffer.from(blob);
    wrongVersion[0] = 2;
    expect(() => openField(wrongVersion, 'users', 'email', ALICE)).toThrow('unsupported sealed field version');
    expect(() => openField(blob.subarray(0, 20), 'users', 'email', ALICE)).toThrow('sealed field too short');
  });
});

describe('blind index', () => {
  it('is stable across case, whitespace and Unicode form, and separates addresses', () => {
    const canonical = blindIndex('alice@demo.dev');
    expect(canonical).toHaveLength(32);
    expect(blindIndex('  Alice@Demo.DEV ').equals(canonical)).toBe(true);
    // Full-width "ａ" folds to "a" under NFKC, so a compatibility-form spelling
    // of an address maps to the same index instead of a second account.
    expect(blindIndex('ａlice@demo.dev').equals(canonical)).toBe(true);

    expect(blindIndex('bob@demo.dev').equals(canonical)).toBe(false);
    // An HMAC, not an encoding: the index reveals equality and nothing else.
    expect(canonical.includes(Buffer.from('alice'))).toBe(false);
  });
});
