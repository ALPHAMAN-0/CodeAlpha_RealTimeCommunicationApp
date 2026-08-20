import { describe, expect, it } from 'vitest';
import {
  CHUNK_BYTES, chunkCountFor, decryptChunk, decryptFileBytes, encryptChunk,
  encryptFileBytes, encryptedSize, fileChunkIv, importFileKey,
} from './file.js';
import { DecryptError, b64uEncode } from './bytes.js';

const FILE_ID = 'ffffffff-2222-4333-8444-555555555555';
const TAG = 16;

const pattern = (n: number) => {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
  return b;
};

describe('chunk IV construction', () => {
  it('never repeats across chunk indices', () => {
    const prefix = new Uint8Array([1, 2, 3, 4]);
    const seen = new Set<string>();
    for (let i = 0; i < 2000; i++) seen.add(b64uEncode(fileChunkIv(prefix, i)));
    expect(seen.size).toBe(2000);
  });

  it('keeps the per-file prefix and encodes the counter big-endian', () => {
    const iv = fileChunkIv(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]), 1);
    expect(Array.from(iv.subarray(0, 4))).toEqual([0xaa, 0xbb, 0xcc, 0xdd]);
    expect(Array.from(iv.subarray(4))).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
  });

  it('produces 12 bytes, the only correct GCM nonce size', () => {
    expect(fileChunkIv(new Uint8Array(4), 0)).toHaveLength(12);
  });
});

describe('whole-file round trip', () => {
  // Boundary sizes are where off-by-one chunking bugs live.
  const sizes = [0, 1, 15, 1024, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, CHUNK_BYTES * 2 + 123];

  for (const size of sizes) {
    it(`round-trips ${size} bytes`, async () => {
      const plain = pattern(size);
      const enc = await encryptFileBytes(plain, FILE_ID);
      expect(enc.meta.chunkCount).toBe(chunkCountFor(size));
      expect(enc.cipher.length).toBe(encryptedSize(size, enc.meta.chunkCount));
      const out = await decryptFileBytes(enc.cipher, enc.keyBytes, enc.meta);
      expect(out).toEqual(plain);
    });
  }

  it('produces ciphertext that does not contain the plaintext', async () => {
    const plain = new TextEncoder().encode('TOP SECRET PAYROLL DATA'.repeat(50));
    const enc = await encryptFileBytes(plain, FILE_ID);
    expect(Buffer.from(enc.cipher).includes(Buffer.from('PAYROLL'))).toBe(false);
  });

  it('reports the plaintext digest, not the ciphertext digest', async () => {
    const plain = pattern(5000);
    const enc = await encryptFileBytes(plain, FILE_ID);
    const expected = b64uEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', plain)));
    expect(enc.sha256).toBe(expected);
  });
});

describe('integrity of the assembled file', () => {
  const build = async (size = CHUNK_BYTES * 3 + 99) => {
    const plain = pattern(size);
    return { plain, enc: await encryptFileBytes(plain, FILE_ID) };
  };

  it('rejects a truncated stream', async () => {
    // The length check catches this before any AEAD work — and even if it did
    // not, the total-count binding in each chunk's AAD would.
    const { enc } = await build();
    await expect(
      decryptFileBytes(enc.cipher.subarray(0, enc.cipher.length - CHUNK_BYTES), enc.keyBytes, enc.meta),
    ).rejects.toThrow(/does not match declared/);
  });

  it('rejects a stream with an extra trailing byte', async () => {
    const { enc } = await build(1000);
    const longer = new Uint8Array(enc.cipher.length + 1);
    longer.set(enc.cipher);
    await expect(decryptFileBytes(longer, enc.keyBytes, enc.meta)).rejects.toThrow(/does not match declared/);
  });

  it('rejects two swapped chunks', async () => {
    // THE chunked-GCM footgun: each chunk authenticates perfectly on its own,
    // so without positional AAD the reassembled file would be
    // attacker-reordered and every tag would still verify.
    const { enc } = await build(CHUNK_BYTES * 2);
    const size = CHUNK_BYTES + TAG;
    const swapped = new Uint8Array(enc.cipher);
    const first = enc.cipher.slice(0, size);
    swapped.set(enc.cipher.slice(size, size * 2), 0);
    swapped.set(first, size);
    await expect(decryptFileBytes(swapped, enc.keyBytes, enc.meta)).rejects.toThrow(DecryptError);
  });

  it('rejects a flipped bit anywhere in the stream', async () => {
    const { enc } = await build(3000);
    for (const idx of [0, 100, enc.cipher.length - 1]) {
      const tampered = new Uint8Array(enc.cipher);
      tampered[idx]! ^= 0x01;
      await expect(decryptFileBytes(tampered, enc.keyBytes, enc.meta)).rejects.toThrow(DecryptError);
    }
  });

  it('rejects a wrong key', async () => {
    const { enc } = await build(2000);
    const wrong = new Uint8Array(32).fill(3);
    await expect(decryptFileBytes(enc.cipher, wrong, enc.meta)).rejects.toThrow(DecryptError);
  });

  it('rejects metadata claiming a different fileId', async () => {
    // Otherwise a server could serve one conversation's attachment as another's.
    const { enc } = await build(2000);
    await expect(
      decryptFileBytes(enc.cipher, enc.keyBytes, { ...enc.meta, fileId: '00000000-2222-4333-8444-555555555555' }),
    ).rejects.toThrow(DecryptError);
  });

  it('rejects metadata claiming a different chunk total', async () => {
    const { enc } = await build(CHUNK_BYTES * 2);
    await expect(
      decryptFileBytes(enc.cipher, enc.keyBytes, { ...enc.meta, chunkCount: enc.meta.chunkCount + 1 }),
    ).rejects.toThrow();
  });
});

describe('single-chunk API', () => {
  it('round-trips one chunk at its declared position', async () => {
    const key = await importFileKey(new Uint8Array(32).fill(5));
    const meta = { fileId: FILE_ID, chunkCount: 4, plainSize: 4000, ivPrefix: b64uEncode(new Uint8Array([1, 2, 3, 4])) };
    const plain = pattern(1000);
    const ct = await encryptChunk(key, meta, 2, plain);
    expect(await decryptChunk(key, meta, 2, ct)).toEqual(plain);
  });

  it('refuses to decrypt a chunk at the wrong index', async () => {
    const key = await importFileKey(new Uint8Array(32).fill(5));
    const meta = { fileId: FILE_ID, chunkCount: 4, plainSize: 4000, ivPrefix: b64uEncode(new Uint8Array([1, 2, 3, 4])) };
    const ct = await encryptChunk(key, meta, 2, pattern(1000));
    await expect(decryptChunk(key, meta, 3, ct)).rejects.toThrow(DecryptError);
  });
});
