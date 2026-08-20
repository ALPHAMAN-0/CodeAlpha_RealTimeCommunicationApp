import { describe, expect, it } from 'vitest';
import { b64uDecode, b64uEncode, concat, equalBytes, utf8, fromUtf8, CryptoFormatError } from './bytes.js';
import { packAad, unpackParts } from './aad.js';

describe('base64url', () => {
  it('round-trips every length from 0 to 96 bytes', () => {
    for (let n = 0; n <= 96; n++) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (i * 37 + n) & 0xff;
      expect(b64uDecode(b64uEncode(bytes)), `length ${n}`).toEqual(bytes);
    }
  });

  it('agrees with Node Buffer base64url', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(b64uEncode(bytes)).toBe(Buffer.from(bytes).toString('base64url'));
  });

  it('emits no padding and never uses + or /', () => {
    // Standard base64 would produce '+' and '/' for these byte patterns.
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 0xf8, 0x00, 0x3e, 0x3f]);
    const enc = b64uEncode(bytes);
    expect(enc).not.toMatch(/[+/=]/);
  });

  it('rejects invalid characters', () => {
    expect(() => b64uDecode('a b')).toThrow(CryptoFormatError);
    expect(() => b64uDecode('ab+c')).toThrow(CryptoFormatError);
    expect(() => b64uDecode('ab/c')).toThrow(CryptoFormatError);
    expect(() => b64uDecode('ab=c')).toThrow(CryptoFormatError);
  });

  it('rejects impossible lengths', () => {
    // No byte count encodes to a length of 1 mod 4, so such input is
    // malformed by construction and must not be silently truncated.
    for (const bad of ['A', 'AAAAA', 'AAAAAAAAA']) {
      expect(() => b64uDecode(bad), bad).toThrow(CryptoFormatError);
    }
    for (const good of ['', 'AA', 'AAA', 'AAAA', 'AAAAAA']) {
      expect(() => b64uDecode(good), good).not.toThrow();
    }
  });
});

describe('utf8', () => {
  it('round-trips multibyte text', () => {
    const s = 'héllo — 世界 🔐';
    expect(fromUtf8(utf8(s))).toBe(s);
  });
});

describe('equalBytes', () => {
  it('compares content, not identity, and rejects length mismatch', () => {
    expect(equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(equalBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
  });
});

describe('packAad', () => {
  it('is unambiguous where plain concatenation is not', () => {
    // This is the whole reason for length prefixes. Without them, ("ab","c")
    // and ("a","bc") produce identical AAD, so a server could shift a
    // boundary — moving a message between conversations, say — and the AEAD
    // would still authenticate.
    expect(packAad('ab', 'c')).not.toEqual(packAad('a', 'bc'));
    expect(packAad('a', '', 'b')).not.toEqual(packAad('a', 'b'));
  });

  it('is deterministic for identical input', () => {
    expect(packAad('x', utf8('y'), 'z')).toEqual(packAad('x', utf8('y'), 'z'));
  });

  it('round-trips through unpackParts', () => {
    const parts = unpackParts(packAad('alpha', utf8('beta'), '', 'δ'));
    expect(parts).toHaveLength(4);
    expect(fromUtf8(parts[0]!)).toBe('alpha');
    expect(fromUtf8(parts[1]!)).toBe('beta');
    expect(parts[2]!.length).toBe(0);
    expect(fromUtf8(parts[3]!)).toBe('δ');
  });

  it('rejects a truncated blob rather than guessing', () => {
    const packed = packAad('hello', 'world');
    expect(() => unpackParts(packed.subarray(0, packed.length - 3))).toThrow();
  });
});

describe('concat', () => {
  it('respects subarray views rather than the backing buffer', () => {
    const backing = new Uint8Array([9, 9, 1, 2, 9, 9]);
    const view = backing.subarray(2, 4);
    expect(concat(view, new Uint8Array([3]))).toEqual(new Uint8Array([1, 2, 3]));
  });
});
