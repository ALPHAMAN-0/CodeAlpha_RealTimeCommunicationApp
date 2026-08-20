/**
 * Byte plumbing shared by every crypto operation.
 *
 * Hand-rolled base64url rather than Buffer or btoa so the same code runs
 * unchanged in a browser, in Node, and in a Worker. Envelopes are small; the
 * only bulk data (file chunks) travels as raw bytes over multipart and never
 * passes through here.
 */

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const DECODE_TABLE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

/** Unpadded base64url. No '=' is ever emitted, and none is accepted. */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]! + B64URL[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]!;
  } else if (rem === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64URL[(n >>> 18) & 63]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]!;
  }
  return out;
}

export function b64uDecode(s: string): Uint8Array {
  const len = s.length;
  const rem = len % 4;
  if (rem === 1) throw new CryptoFormatError('invalid base64url length');
  const outLen = ((len - rem) / 4) * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const code = s.charCodeAt(i);
    const v = code < 128 ? DECODE_TABLE[code]! : -1;
    if (v < 0) throw new CryptoFormatError('invalid base64url character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
  }
  return out;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export const utf8 = (s: string): Uint8Array => encoder.encode(s);
export const fromUtf8 = (b: Uint8Array): string => decoder.decode(b);

export function concat(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const randomBytes = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

/**
 * Overwrite key material once it is no longer needed.
 *
 * Not a guarantee — a JS engine may have copied the buffer during GC or JIT —
 * but it shortens the window in which raw secrets sit in reachable memory,
 * and it costs nothing.
 */
export const zero = (b: Uint8Array): void => {
  b.fill(0);
};

/** Constant-time comparison, for fingerprints and MAC-shaped values. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/**
 * `Uint8Array` views can be windows into a larger buffer. WebCrypto accepts a
 * BufferSource, but passing a subarray's underlying buffer by mistake is a
 * classic silent-corruption bug, so normalise explicitly.
 */
export function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  return b.byteOffset === 0 && b.byteLength === b.buffer.byteLength
    ? (b.buffer as ArrayBuffer)
    : (b.slice().buffer as ArrayBuffer);
}

export class CryptoFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CryptoFormatError';
  }
}

/**
 * Thrown for every decryption failure, with no detail about which check
 * failed.
 *
 * WebCrypto itself gives an opaque OperationError; preserving that opacity is
 * deliberate. Reporting *why* a decrypt failed across a trust boundary is the
 * shape of a padding-oracle bug.
 */
export class DecryptError extends Error {
  constructor(message = 'AUTH_FAILED') {
    super(message);
    this.name = 'DecryptError';
  }
}
