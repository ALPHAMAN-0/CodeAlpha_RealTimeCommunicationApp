import { fileChunkAad } from './aad.js';
import { TAG_BITS, open, sealWithIv, sha256 } from './aead.js';
import { b64uDecode, b64uEncode, randomBytes, toArrayBuffer } from './bytes.js';

export const CHUNK_BYTES = 256 * 1024;
const TAG_BYTES = TAG_BITS / 8;
const IV_PREFIX_BYTES = 4;

export interface FileCipherMeta {
  fileId: string;
  chunkCount: number;
  plainSize: number;
  /** 4 random bytes; the 8-byte chunk counter completes the 12-byte IV. */
  ivPrefix: string;
}

/**
 * Deterministic IV: 4 random per-file bytes ‖ 8-byte big-endian chunk index.
 *
 * A counter rather than a random IV per chunk, because a 25 MB file is ~100
 * chunks under one key and a counter makes repetition impossible by
 * construction instead of improbable.
 */
export function fileChunkIv(ivPrefix: Uint8Array, index: number): Uint8Array {
  const iv = new Uint8Array(12);
  iv.set(ivPrefix.subarray(0, IV_PREFIX_BYTES), 0);
  new DataView(iv.buffer).setBigUint64(IV_PREFIX_BYTES, BigInt(index), false);
  return iv;
}

export const generateFileKeyBytes = (): Uint8Array => randomBytes(32);

/**
 * The per-file key travels as raw bytes inside the sealed message payload, so
 * it has to exist as a Uint8Array. It is imported non-extractable for use.
 */
export const importFileKey = (raw: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', toArrayBuffer(raw), { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);

export const encryptedSize = (plainSize: number, chunkCount: number): number =>
  plainSize + chunkCount * TAG_BYTES;

export const chunkCountFor = (plainSize: number): number =>
  Math.max(1, Math.ceil(plainSize / CHUNK_BYTES));

export async function encryptChunk(
  key: CryptoKey,
  meta: FileCipherMeta,
  index: number,
  plain: Uint8Array,
): Promise<Uint8Array> {
  const aad = fileChunkAad({
    fileId: meta.fileId,
    chunk: index,
    total: meta.chunkCount,
    plainSize: meta.plainSize,
  });
  return sealWithIv(key, fileChunkIv(b64uDecode(meta.ivPrefix), index), aad, plain);
}

export async function decryptChunk(
  key: CryptoKey,
  meta: FileCipherMeta,
  index: number,
  cipher: Uint8Array,
): Promise<Uint8Array> {
  const aad = fileChunkAad({
    fileId: meta.fileId,
    chunk: index,
    total: meta.chunkCount,
    plainSize: meta.plainSize,
  });
  return open(key, aad, fileChunkIv(b64uDecode(meta.ivPrefix), index), cipher);
}

export interface EncryptedFile {
  /** Raw key bytes, to be sealed inside the accompanying chat message. */
  keyBytes: Uint8Array;
  cipher: Uint8Array;
  meta: FileCipherMeta;
  /** SHA-256 of the PLAINTEXT, for a post-decrypt integrity display. */
  sha256: string;
}

/**
 * Encrypt a whole file in chunks.
 *
 * WebCrypto has no streaming AES-GCM, so chunking is forced — and chunking is
 * where the subtle bug lives. Every chunk's AAD binds its index, the total
 * count and the plaintext size, so truncating the stream or swapping two
 * chunks fails authentication. Chunked GCM without that positional binding
 * verifies each piece happily while the reassembled file is
 * attacker-controlled.
 */
export async function encryptFileBytes(plain: Uint8Array, fileId: string): Promise<EncryptedFile> {
  const keyBytes = generateFileKeyBytes();
  const key = await importFileKey(keyBytes);
  const ivPrefixBytes = randomBytes(IV_PREFIX_BYTES);
  const meta: FileCipherMeta = {
    fileId,
    chunkCount: chunkCountFor(plain.length),
    plainSize: plain.length,
    ivPrefix: b64uEncode(ivPrefixBytes),
  };

  const cipher = new Uint8Array(encryptedSize(plain.length, meta.chunkCount));
  let offset = 0;
  for (let i = 0; i < meta.chunkCount; i++) {
    const slice = plain.subarray(i * CHUNK_BYTES, Math.min((i + 1) * CHUNK_BYTES, plain.length));
    const out = await encryptChunk(key, meta, i, slice);
    cipher.set(out, offset);
    offset += out.length;
  }

  return { keyBytes, cipher, meta, sha256: b64uEncode(await sha256(plain)) };
}

/**
 * Decrypt a whole file, rejecting a stream whose length disagrees with the
 * metadata before spending any time on AEAD.
 */
export async function decryptFileBytes(
  cipher: Uint8Array,
  keyBytes: Uint8Array,
  meta: FileCipherMeta,
): Promise<Uint8Array> {
  const expected = encryptedSize(meta.plainSize, meta.chunkCount);
  if (cipher.length !== expected) {
    throw new Error(`ciphertext length ${cipher.length} does not match declared ${expected}`);
  }
  const key = await importFileKey(keyBytes);
  const plain = new Uint8Array(meta.plainSize);

  let inOffset = 0;
  let outOffset = 0;
  for (let i = 0; i < meta.chunkCount; i++) {
    const plainLen = Math.min(CHUNK_BYTES, meta.plainSize - outOffset);
    const cipherLen = plainLen + TAG_BYTES;
    const part = await decryptChunk(key, meta, i, cipher.subarray(inOffset, inOffset + cipherLen));
    plain.set(part, outOffset);
    inOffset += cipherLen;
    outOffset += part.length;
  }
  return plain;
}
