import { describe, expect, it } from 'vitest';
import { socketSchemas, VALIDATED_EVENTS } from './socket.js';
import { cipherEnvelopeSchema } from './crypto.js';
import { b64urlExact, safeKey } from './common.js';
import { loginBodySchema, registerBodySchema } from './http.js';

const b64 = (n: number) => Buffer.alloc(n, 7).toString('base64url');

const envelope = () => ({
  alg: 'RTC/v1' as const,
  salt: b64(32),
  iv: b64(12),
  ct: b64(64),
  sig: b64(64),
  senderKeyVersion: 1,
});

const oid = 'a'.repeat(24);
const uuid = '11111111-2222-4333-8444-555555555555';

describe('wire schemas', () => {
  it('accepts a well-formed envelope', () => {
    expect(cipherEnvelopeSchema.safeParse(envelope()).success).toBe(true);
  });

  it('rejects unknown keys instead of stripping them', () => {
    // strictObject, not object: silent stripping hides contract drift between
    // client and server, and drift is where authorization bugs live.
    const res = cipherEnvelopeSchema.safeParse({ ...envelope(), extra: 'nope' });
    expect(res.success).toBe(false);
  });

  it('enforces exact IV and salt lengths', () => {
    expect(cipherEnvelopeSchema.safeParse({ ...envelope(), iv: b64(11) }).success).toBe(false);
    expect(cipherEnvelopeSchema.safeParse({ ...envelope(), salt: b64(31) }).success).toBe(false);
    expect(b64urlExact(12).safeParse(b64(12)).success).toBe(true);
    expect(b64urlExact(12).safeParse(b64(13)).success).toBe(false);
  });

  it('rejects non-base64url binary fields', () => {
    expect(cipherEnvelopeSchema.safeParse({ ...envelope(), ct: 'has spaces!' }).success).toBe(false);
    // Standard base64 uses + and /, which are not valid base64url.
    expect(cipherEnvelopeSchema.safeParse({ ...envelope(), ct: 'ab+/cd' }).success).toBe(false);
  });

  it('bounds ciphertext length', () => {
    const huge = 'A'.repeat(1_000_000);
    expect(cipherEnvelopeSchema.safeParse({ ...envelope(), ct: huge }).success).toBe(false);
  });
});

describe('message:send', () => {
  const base = {
    conversationId: oid,
    clientMsgId: uuid,
    envelope: envelope(),
    sentAt: Date.now(),
  };

  it('accepts a text message', () => {
    const r = socketSchemas['message:send'].safeParse({ ...base, kind: 'text' });
    expect(r.success).toBe(true);
  });

  it('requires an attachmentId for kind "file"', () => {
    expect(socketSchemas['message:send'].safeParse({ ...base, kind: 'file' }).success).toBe(false);
    expect(
      socketSchemas['message:send'].safeParse({ ...base, kind: 'file', attachmentId: oid }).success,
    ).toBe(true);
  });

  it('forbids an attachmentId on kind "text"', () => {
    expect(
      socketSchemas['message:send'].safeParse({ ...base, kind: 'text', attachmentId: oid }).success,
    ).toBe(false);
  });

  it('rejects a non-UUID clientMsgId', () => {
    // The idempotency key is load-bearing; a malformed one would defeat dedupe.
    expect(
      socketSchemas['message:send'].safeParse({ ...base, kind: 'text', clientMsgId: 'abc' }).success,
    ).toBe(false);
  });
});

describe('wb:op field/kind agreement', () => {
  it('requires envelope + strokeId + chunk for a stroke', () => {
    expect(socketSchemas['wb:op'].safeParse({ conversationId: oid, kind: 'stroke' }).success).toBe(false);
    expect(
      socketSchemas['wb:op'].safeParse({
        conversationId: oid, kind: 'stroke', strokeId: uuid, chunk: 0, done: false, envelope: envelope(),
      }).success,
    ).toBe(true);
  });

  it('requires a strokeId for undo/redo so the server can authorize it', () => {
    expect(socketSchemas['wb:op'].safeParse({ conversationId: oid, kind: 'undo' }).success).toBe(false);
    expect(
      socketSchemas['wb:op'].safeParse({ conversationId: oid, kind: 'undo', strokeId: uuid }).success,
    ).toBe(true);
  });

  it('accepts a bare clear and rejects a decorated one', () => {
    expect(socketSchemas['wb:op'].safeParse({ conversationId: oid, kind: 'clear' }).success).toBe(true);
    expect(
      socketSchemas['wb:op'].safeParse({ conversationId: oid, kind: 'clear', strokeId: uuid }).success,
    ).toBe(false);
  });
});

describe('signalling payload caps', () => {
  it('rejects an oversized SDP rather than relaying it', () => {
    const ok = { conversationId: oid, to: 'socket-abc123', description: { type: 'offer', sdp: 'v=0' } };
    expect(socketSchemas['rtc:describe'].safeParse(ok).success).toBe(true);
    expect(
      socketSchemas['rtc:describe'].safeParse({
        ...ok, description: { type: 'offer', sdp: 'x'.repeat(64_001) },
      }).success,
    ).toBe(false);
  });

  it('rejects an unknown description type', () => {
    expect(
      socketSchemas['rtc:describe'].safeParse({
        conversationId: oid, to: 'socket-abc123', description: { type: 'garbage' },
      }).success,
    ).toBe(false);
  });
});

describe('injection-shaped input', () => {
  it('cannot express a Mongo operator through a typed string field', () => {
    // This is the actual NoSQL-injection defense: a z.string() field can
    // never carry {$ne: null} into a query position.
    expect(loginBodySchema.safeParse({ email: { $ne: null }, authProof: b64(32) }).success).toBe(false);
    expect(socketSchemas['room:join'].safeParse({ conversationId: { $ne: null } }).success).toBe(false);
  });

  it('rejects keys that could reach an operator position', () => {
    expect(safeKey().safeParse('$where').success).toBe(false);
    expect(safeKey().safeParse('a.b').success).toBe(false);
    expect(safeKey().safeParse('normal_key').success).toBe(true);
  });
});

describe('email normalisation', () => {
  it('trims and lowercases so the blind index is stable', () => {
    const r = loginBodySchema.safeParse({ email: '  Alice@Demo.DEV ', authProof: b64(32) });
    expect(r.success).toBe(true);
    if (r.success) expect(r.data.email).toBe('alice@demo.dev');
  });

  it('rejects a malformed address', () => {
    expect(loginBodySchema.safeParse({ email: 'not-an-email', authProof: b64(32) }).success).toBe(false);
  });
});

describe('registration requires both key wraps', () => {
  const wrap = (v: number) => ({
    keyVersion: v, iv: b64(12), wrapped: b64(128), kdfSalt: b64(32),
    kdfParams: { kdf: 'argon2id' as const, memoryKiB: 65_536, iterations: 3, parallelism: 1 },
  });
  const identity = {
    publicKeys: {
      keyVersion: 1, spkiEcdh: b64(91), spkiEcdsa: b64(91),
      createdAt: Date.now(), selfSig: b64(64),
    },
    passwordWrap: wrap(1),
    recoveryWrap: wrap(1),
  };

  const validBody = (over: Record<string, unknown> = {}) => ({
    userId: oid, email: 'a@b.dev', displayName: 'Alice',
    authProof: b64(32), kdfSalt: b64(32),
    kdfParams: { kdf: 'argon2id', memoryKiB: 65_536, iterations: 3, parallelism: 1 },
    identity,
    ...over,
  });

  it('accepts a complete registration', () => {
    expect(registerBodySchema.safeParse(validBody()).success).toBe(true);
  });

  it('requires the client-generated account id', () => {
    // The identity key record is signed over this id before the account
    // exists, so registration cannot proceed without it.
    const { userId: _omitted, ...withoutId } = validBody();
    expect(registerBodySchema.safeParse(withoutId).success).toBe(false);
    expect(registerBodySchema.safeParse(validBody({ userId: 'not-an-objectid' })).success).toBe(false);
    expect(registerBodySchema.safeParse(validBody({ userId: 'A'.repeat(24) })).success).toBe(false);
  });

  it('rejects registration missing the recovery wrap', () => {
    // Without it, a forgotten password destroys history with no escape hatch.
    const { recoveryWrap: _omitted, ...partial } = identity;
    expect(registerBodySchema.safeParse(validBody({ identity: partial })).success).toBe(false);
  });

  it('rejects an unknown top-level field', () => {
    expect(registerBodySchema.safeParse(validBody({ isAdmin: true })).success).toBe(false);
  });
});

describe('event registry', () => {
  it('has a schema for every registered event name', () => {
    expect(VALIDATED_EVENTS.length).toBeGreaterThan(0);
    for (const name of VALIDATED_EVENTS) {
      expect(socketSchemas[name], `missing schema for ${name}`).toBeDefined();
    }
  });

  it('exposes no duplicate event names', () => {
    expect(new Set(VALIDATED_EVENTS).size).toBe(VALIDATED_EVENTS.length);
  });
});
