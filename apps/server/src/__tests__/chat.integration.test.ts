import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { fromUtf8, openDm, sealDm, utf8, type DmContext } from '@rtc/crypto';
import type { CipherEnvelope, ConversationDTO, MessageDTO } from '@rtc/shared';
import { startTestServer, type TestServer } from './helpers/testServer.js';
import { connectClient, settle, type TestClient } from './helpers/testClient.js';
import { api, createUser, rootBetween, signPubOf, type TestUser } from './helpers/testUser.js';

let server: TestServer;
let alice: TestUser;
let bob: TestUser;
let carol: TestUser;
let ac: TestClient;
let bc: TestClient;
let dm: ConversationDTO;

beforeAll(async () => {
  server = await startTestServer();
}, 120_000);

afterAll(async () => {
  await server?.close();
});

beforeEach(async () => {
  ac?.close();
  bc?.close();
  await server.reset();
  [alice, bob, carol] = await Promise.all([
    createUser(server.url, 'Alice'),
    createUser(server.url, 'Bob'),
    createUser(server.url, 'Carol'),
  ]);
  const created = await api(server.url, '/api/conversations', {
    method: 'POST',
    token: alice.accessToken,
    body: { type: 'dm', memberIds: [alice.userId, bob.userId] },
  });
  expect(created.status).toBe(201);
  dm = created.body.conversation;

  ac = await connectClient(server.url, alice);
  bc = await connectClient(server.url, bob);
  await ac.send('room:join', { conversationId: dm.id });
  await bc.send('room:join', { conversationId: dm.id });
});

/** Seal a DM message exactly as the real client would. */
async function seal(
  from: TestUser,
  to: TestUser,
  text: string,
  clientMsgId: string,
  sentAt = Date.now(),
): Promise<{ envelope: CipherEnvelope; ctx: DmContext }> {
  const ctx: DmContext = {
    clientMsgId,
    conversationId: dm.id,
    senderId: from.userId,
    recipientId: to.userId,
    senderKeyVersion: from.keyVersion,
    sentAt,
    contentType: 'text/plain',
  };
  const root = await rootBetween(from, to);
  return { envelope: await sealDm(root, from.priv.signPriv, ctx, utf8(text)), ctx };
}

async function openAs(reader: TestUser, writer: TestUser, ctx: DmContext, envelope: CipherEnvelope) {
  const root = await rootBetween(reader, writer);
  return fromUtf8(await openDm(root, await signPubOf(writer), ctx, envelope));
}

/**
 * CRITICAL TEST 1 — idempotent send.
 *
 * If this passes, duplicate-message bugs are structurally impossible: the
 * unique index on (conversationId, clientMsgId) means a retry cannot create a
 * second row no matter how it races.
 */
describe('idempotent send', () => {
  it('collapses a sequential retry to one row and one broadcast', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'hello exactly once', clientMsgId);
    const payload = { conversationId: dm.id, clientMsgId, kind: 'text' as const, envelope, sentAt: ctx.sentAt };

    const first = await ac.send<{ messageId: string; seq: number; deduped: boolean }>('message:send', payload);
    const second = await ac.send<{ messageId: string; seq: number; deduped: boolean }>('message:send', payload);

    expect(first.deduped).toBe(false);
    expect(second.deduped).toBe(true);
    // The retry must report the ORIGINAL id and seq, or the client would
    // reconcile its optimistic row against a message that does not exist.
    expect(second.messageId).toBe(first.messageId);
    expect(second.seq).toBe(first.seq);

    await bc.waitFor<{ message: MessageDTO }>('message:new', (p) => p.message.id === first.messageId);
    await settle();
    // A replay must not re-broadcast.
    expect(bc.received('message:new')).toHaveLength(1);
  });

  it('collapses CONCURRENT retries of the same clientMsgId', async () => {
    // The sequential case is caught by the fast-path lookup; only the
    // concurrent case exercises the duplicate-key race the index protects.
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'concurrent', clientMsgId);
    const payload = { conversationId: dm.id, clientMsgId, kind: 'text' as const, envelope, sentAt: ctx.sentAt };

    const acks = await Promise.all(
      Array.from({ length: 5 }, () => ac.send<{ messageId: string; seq: number }>('message:send', payload)),
    );
    const ids = new Set(acks.map((a) => a.messageId));
    expect(ids.size).toBe(1);
    expect(new Set(acks.map((a) => a.seq)).size).toBe(1);

    const history = await ac.send<{ messages: MessageDTO[] }>('message:history', { conversationId: dm.id });
    expect(history.messages.filter((m) => m.clientMsgId === clientMsgId)).toHaveLength(1);
  });

  it('preserves per-sender order for rapid concurrent sends', async () => {
    // Without the per-(socket, conversation) serial queue these interleave
    // inside seq allocation and the sender's own messages render out of order.
    const payloads = await Promise.all(
      Array.from({ length: 8 }, async (_, i) => {
        const clientMsgId = randomUUID();
        const { envelope, ctx } = await seal(alice, bob, `msg-${i}`, clientMsgId);
        return { conversationId: dm.id, clientMsgId, kind: 'text' as const, envelope, sentAt: ctx.sentAt, i };
      }),
    );
    const acks: Array<{ i: number; seq: number }> = [];
    await Promise.all(
      payloads.map(async ({ i, ...p }) => {
        const ack = await ac.send<{ seq: number }>('message:send', p);
        acks.push({ i, seq: ack.seq });
      }),
    );
    const bySeq = [...acks].sort((a, b) => a.seq - b.seq).map((a) => a.i);
    expect(bySeq).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });
});

/**
 * CRITICAL TEST 2 — two-client round trip.
 *
 * The whole product in one test: send, receive, decrypt, receipt, unread.
 */
describe('two-client round trip', () => {
  it('delivers, decrypts, and settles the read receipt', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'see you at 6', clientMsgId);
    const ack = await ac.send<{ messageId: string; seq: number }>('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });

    const delivered = await bc.waitFor<{ message: MessageDTO }>('message:new');
    expect(delivered.message.seq).toBe(ack.seq);
    expect(delivered.message.senderId).toBe(alice.userId);

    // Bob reconstructs the AAD from server-visible columns and decrypts.
    const text = await openAs(bob, alice, {
      clientMsgId: delivered.message.clientMsgId,
      conversationId: delivered.message.conversationId,
      senderId: delivered.message.senderId,
      recipientId: bob.userId,
      senderKeyVersion: delivered.message.envelope!.senderKeyVersion,
      sentAt: delivered.message.sentAt,
      contentType: 'text/plain',
    }, delivered.message.envelope!);
    expect(text).toBe('see you at 6');

    const read = await bc.send<{ unread: number }>('receipt:read', {
      conversationId: dm.id, seq: ack.seq,
    });
    expect(read.unread).toBe(0);

    const receipt = await ac.waitFor<{ userId: string; readSeq: number }>(
      'receipt:updated', (p) => p.userId === bob.userId && p.readSeq >= ack.seq,
    );
    expect(receipt.readSeq).toBe(ack.seq);
  });

  it('stores only ciphertext — the server never sees the plaintext', async () => {
    // The single most convincing property of the whole system, asserted rather
    // than claimed.
    const clientMsgId = randomUUID();
    const secret = 'PLAINTEXT-CANARY-a7f3';
    const { envelope, ctx } = await seal(alice, bob, secret, clientMsgId);
    await ac.send('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });

    const mongoose = (await import('mongoose')).default;
    const raw = await mongoose.connection.db!.collection('messages').findOne({ clientMsgId });
    expect(raw).not.toBeNull();
    expect(JSON.stringify(raw)).not.toContain(secret);
    expect(raw!.envelope).toBeTruthy();
  });

  it('reports unread arithmetic without a counter to drift', async () => {
    for (let i = 0; i < 3; i++) {
      const clientMsgId = randomUUID();
      const { envelope, ctx } = await seal(alice, bob, `m${i}`, clientMsgId);
      await ac.send('message:send', { conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt });
    }
    const state = await bc.send<{ unread: number; latestSeq: number }>('room:join', { conversationId: dm.id });
    expect(state.unread).toBe(3);
    expect(state.latestSeq).toBe(3);
  });

  it('relays typing to the peer but not back to the sender', async () => {
    await ac.send('typing:start', { conversationId: dm.id });
    const t = await bc.waitFor<{ userId: string; isTyping: boolean }>('typing:update');
    expect(t).toMatchObject({ userId: alice.userId, isTyping: true });
    await settle();
    expect(ac.received('typing:update')).toHaveLength(0);
  });

  it('tombstones a delete without collapsing the timeline', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'oops', clientMsgId);
    const ack = await ac.send<{ messageId: string; seq: number }>('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    await ac.send('message:delete', { conversationId: dm.id, messageId: ack.messageId });
    await bc.waitFor('message:deleted', (p: any) => p.messageId === ack.messageId);

    const history = await bc.send<{ messages: MessageDTO[] }>('message:history', { conversationId: dm.id });
    const row = history.messages.find((m) => m.id === ack.messageId)!;
    // The row and its seq survive; only the ciphertext is gone. Removing it
    // would punch a hole in every client's ordering and unread arithmetic.
    expect(row.seq).toBe(ack.seq);
    expect(row.envelope).toBeUndefined();
    expect(row.deletedAt).toBeTruthy();
  });

  it('refuses to delete someone else’s message', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'mine', clientMsgId);
    const ack = await ac.send<{ messageId: string }>('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    const nope = await bc.tryS('message:delete', { conversationId: dm.id, messageId: ack.messageId });
    expect(nope.ok).toBe(false);
    if (!nope.ok) expect(nope.error.code).toBe('FORBIDDEN');
  });
});

/**
 * CRITICAL TEST 3 — reconnect backfill.
 *
 * The part reviewers assume is broken until it is proven.
 */
describe('reconnect backfill', () => {
  it('returns exactly the missed messages, ascending, with no duplicates', async () => {
    const sent: number[] = [];
    bc.close();
    await settle();

    for (let i = 0; i < 5; i++) {
      const clientMsgId = randomUUID();
      const { envelope, ctx } = await seal(alice, bob, `while-away-${i}`, clientMsgId);
      const ack = await ac.send<{ seq: number }>('message:send', {
        conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
      });
      sent.push(ack.seq);
    }

    bc = await connectClient(server.url, bob);
    const sync = await bc.send<{
      conversations: Array<{ messages: MessageDTO[]; hasMore: boolean; latestSeq: number }>;
    }>('sync:since', { cursors: [{ conversationId: dm.id, lastSeq: 0 }] });

    expect(sync.conversations).toHaveLength(1);
    const got = sync.conversations[0]!;
    expect(got.messages.map((m) => m.seq)).toEqual(sent);
    expect(got.hasMore).toBe(false);
    expect(new Set(got.messages.map((m) => m.id)).size).toBe(5);
    // Ascending, so the client can append while inserting by seq.
    expect(got.messages.map((m) => m.seq)).toEqual([...got.messages.map((m) => m.seq)].sort((a, b) => a - b));
  });

  it('returns nothing when the cursor is already current', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'caught up', clientMsgId);
    const ack = await ac.send<{ seq: number }>('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    const sync = await bc.send<{ conversations: Array<{ messages: MessageDTO[] }> }>('sync:since', {
      cursors: [{ conversationId: dm.id, lastSeq: ack.seq }],
    });
    expect(sync.conversations[0]!.messages).toHaveLength(0);
  });

  it('flushes offline sends exactly once and in order on reconnect', async () => {
    // The inverse direction: Bob composed while disconnected, so his client
    // retries the identical payloads (same clientMsgIds) after reconnecting.
    const queued = await Promise.all(
      Array.from({ length: 3 }, async (_, i) => {
        const clientMsgId = randomUUID();
        const { envelope, ctx } = await seal(bob, alice, `queued-${i}`, clientMsgId);
        return { conversationId: dm.id, clientMsgId, kind: 'text' as const, envelope, sentAt: ctx.sentAt };
      }),
    );

    bc.close();
    await settle();
    bc = await connectClient(server.url, bob);
    await bc.send('room:join', { conversationId: dm.id });

    const seqs: number[] = [];
    for (const p of queued) {
      const ack = await bc.send<{ seq: number; deduped: boolean }>('message:send', p);
      expect(ack.deduped).toBe(false);
      seqs.push(ack.seq);
    }
    // Retrying the whole batch — the outbox flushing twice — must be a no-op.
    for (const p of queued) {
      const ack = await bc.send<{ deduped: boolean }>('message:send', p);
      expect(ack.deduped).toBe(true);
    }

    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    const history = await ac.send<{ messages: MessageDTO[] }>('message:history', { conversationId: dm.id });
    expect(history.messages).toHaveLength(3);
  });

  it('skips conversations the caller is not a member of, without leaking their existence', async () => {
    const other = await api(server.url, '/api/conversations', {
      method: 'POST', token: alice.accessToken,
      body: { type: 'dm', memberIds: [alice.userId, carol.userId] },
    });
    const sync = await bc.send<{ conversations: Array<{ conversationId: string }> }>('sync:since', {
      cursors: [
        { conversationId: dm.id, lastSeq: 0 },
        { conversationId: other.body.conversation.id, lastSeq: 0 },
      ],
    });
    expect(sync.conversations.map((c) => c.conversationId)).toEqual([dm.id]);
  });
});

describe('socket authorization', () => {
  it('refuses a handshake with no token', async () => {
    const { io: ioClient } = await import('socket.io-client');
    const socket = ioClient(server.url, { transports: ['websocket'], reconnection: false, forceNew: true });
    const err = await new Promise<Error>((resolve) => socket.once('connect_error', resolve));
    expect(err.message).toBe('AUTH_FAILED');
    socket.disconnect();
  });

  it('refuses a handshake with a tampered token', async () => {
    const { io: ioClient } = await import('socket.io-client');
    const socket = ioClient(server.url, {
      transports: ['websocket'], reconnection: false, forceNew: true,
      auth: { token: `${alice.accessToken.slice(0, -3)}xyz` },
    });
    const err = await new Promise<Error>((resolve) => socket.once('connect_error', resolve));
    expect(err.message).toBe('AUTH_FAILED');
    socket.disconnect();
  });

  it('refuses room:join for a non-member', async () => {
    const cc = await connectClient(server.url, carol);
    const ack = await cc.tryS('room:join', { conversationId: dm.id });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('NOT_A_MEMBER');
    cc.close();
  });

  it('refuses message:send from a member who never joined', async () => {
    // The DB says Bob may; the socket set says this connection did not. Both
    // checks are required, and this asserts the second one is real.
    const fresh = await connectClient(server.url, bob);
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(bob, alice, 'not joined', clientMsgId);
    const ack = await fresh.tryS('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('NOT_JOINED');
    fresh.close();
  });

  it('rejects an unknown field instead of silently stripping it', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'strict', clientMsgId);
    const ack = await ac.tryS('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
      senderId: carol.userId, // a client must never be able to assert identity
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('VALIDATION');
  });

  it('rejects a message whose sentAt is wildly out of range', async () => {
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'time traveller', clientMsgId, Date.now() + 86_400_000);
    const ack = await ac.tryS('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('VALIDATION');
  });

  it('never lets a client assert its own identity', async () => {
    // senderId is stamped from the verified token, so a message sent by Alice
    // is attributed to Alice no matter what she claims.
    const clientMsgId = randomUUID();
    const { envelope, ctx } = await seal(alice, bob, 'who am i', clientMsgId);
    const ack = await ac.send<{ messageId: string }>('message:send', {
      conversationId: dm.id, clientMsgId, kind: 'text', envelope, sentAt: ctx.sentAt,
    });
    const history = await bc.send<{ messages: MessageDTO[] }>('message:history', { conversationId: dm.id });
    expect(history.messages.find((m) => m.id === ack.messageId)!.senderId).toBe(alice.userId);
  });
});

describe('presence refcounting', () => {
  it('keeps a user online while any tab remains', async () => {
    const second = await connectClient(server.url, bob);
    await second.send('room:join', { conversationId: dm.id });
    second.close();
    await settle(400);

    // Closing one of two tabs must NOT mark the user offline.
    const presence = await ac.send<{ presence: Array<{ userId: string; status: string }> }>(
      'presence:query', { userIds: [bob.userId] },
    );
    expect(presence.presence[0]).toMatchObject({ userId: bob.userId, status: 'online' });
  });
});
