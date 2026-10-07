import { describe, expect, it } from 'vitest';
import { LIMITS } from '../constants.js';
import { filePayloadSchema, parseFilePayload } from './payload.js';

const b64 = (n: number) => Buffer.alloc(n, 7).toString('base64url');

/** What an honest client seals alongside an attachment. */
const payload = () => ({
  attachmentId: 'a'.repeat(24),
  fileId: '11111111-2222-4333-8444-555555555555',
  filename: 'q3-report.pdf',
  mime: 'application/pdf',
  plainSize: 300_000,
  chunkCount: 2,
  ivPrefix: b64(4),
  sha256: b64(32),
  fileKey: b64(32),
});

const rejects = (override: Record<string, unknown>) =>
  filePayloadSchema.safeParse({ ...payload(), ...override }).success === false;

describe('file payload (peer-supplied, validated on receipt)', () => {
  it('accepts what an honest client sends, with or without the optional fields', () => {
    expect(parseFilePayload(JSON.stringify(payload()))).toEqual(payload());
    expect(filePayloadSchema.safeParse({ ...payload(), caption: 'see page 4' }).success).toBe(true);

    const { fileId: _fileId, ...legacy } = payload();
    expect(filePayloadSchema.safeParse(legacy).success).toBe(true);
  });

  it('rejects fields that would be rendered or executed as something other than text', () => {
    // An object where a string is expected throws inside React's render and
    // unmounts the conversation for every member who opens it.
    expect(rejects({ filename: {} })).toBe(true);
    expect(rejects({ filename: ['a', {}] })).toBe(true);
    expect(rejects({ filename: '' })).toBe(true);
    expect(rejects({ caption: { toString: 'x' } })).toBe(true);
    expect(rejects({ mime: 42 })).toBe(true);
  });

  it('bounds the sizes the decryptor allocates from', () => {
    expect(rejects({ plainSize: LIMITS.UPLOAD_BYTES_MAX + 1 })).toBe(true);
    expect(rejects({ plainSize: -1 })).toBe(true);
    expect(rejects({ plainSize: 1.5 })).toBe(true);
    expect(rejects({ plainSize: '300000' })).toBe(true);
    expect(rejects({ chunkCount: 0 })).toBe(true);
    expect(rejects({ chunkCount: 1_000_000 })).toBe(true);
  });

  it('pins key, digest and IV-prefix lengths exactly', () => {
    expect(rejects({ fileKey: b64(16) })).toBe(true);
    expect(rejects({ fileKey: `${b64(32)}=` })).toBe(true);
    expect(rejects({ sha256: b64(20) })).toBe(true);
    expect(rejects({ ivPrefix: b64(12) })).toBe(true);
    expect(rejects({ attachmentId: '../../etc/passwd' })).toBe(true);
  });

  it('requires every field the receiver needs and ignores ones it does not know', () => {
    for (const key of ['attachmentId', 'filename', 'mime', 'plainSize', 'chunkCount', 'ivPrefix', 'sha256', 'fileKey']) {
      const { [key]: _omitted, ...rest } = payload() as Record<string, unknown>;
      expect(filePayloadSchema.safeParse(rest).success, key).toBe(false);
    }
    // Stripped, not rejected: a newer client's extra field must not make the
    // attachment unreadable here.
    const parsed = parseFilePayload(JSON.stringify({ ...payload(), thumbnail: 'future-field' }));
    expect(parsed).toEqual(payload());
  });

  it('throws on plaintext that is not a payload at all', () => {
    expect(() => parseFilePayload('not json')).toThrow();
    expect(() => parseFilePayload('null')).toThrow();
    expect(() => parseFilePayload('"just a string"')).toThrow();
    expect(() => parseFilePayload('[]')).toThrow();
  });
});
