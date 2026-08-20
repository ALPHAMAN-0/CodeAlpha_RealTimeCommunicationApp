import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { VALIDATED_EVENTS } from '@rtc/shared';
import {
  b64uEncode, decryptFileBytes, encryptFileBytes, sealGroup, utf8,
  createEpoch, epochRootFromSecret, importPublicKeys,
} from '@rtc/crypto';
import type { ConversationDTO, WhiteboardOpRecord } from '@rtc/shared';
import { startTestServer, type TestServer } from './helpers/testServer.js';
import { connectClient, settle, type TestClient } from './helpers/testClient.js';
import { api, createUser, type TestUser } from './helpers/testUser.js';

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
    method: 'POST', token: alice.accessToken,
    body: { type: 'dm', memberIds: [alice.userId, bob.userId] },
  });
  dm = created.body.conversation;
  ac = await connectClient(server.url, alice);
  bc = await connectClient(server.url, bob);
  await ac.send('room:join', { conversationId: dm.id });
  await bc.send('room:join', { conversationId: dm.id });
});

/**
 * The invariant test.
 *
 * Every event declared in the shared contract must actually be registered
 * through `defineHandler`. This is the test that keeps the "nothing ships
 * unvalidated" rule true six months from now, when someone adds an event and
 * forgets to wire it — at which point the wire type compiles fine, the client
 * sends happily, and the server silently drops it.
 */
describe('handler registry invariant', () => {
  it('registers a handler for every declared event', () => {
    const sockets = [...server.io.sockets.sockets.values()];
    expect(sockets.length).toBeGreaterThan(0);
    const registered = new Set(sockets[0]!.eventNames().map(String));
    const missing = VALIDATED_EVENTS.filter((e) => !registered.has(e));
    expect(missing, `events declared but not registered: ${missing.join(', ')}`).toEqual([]);
  });

  it('ignores an event nobody registered rather than crashing', async () => {
    // Unknown events must be inert, not a way to reach an error path.
    const ack = await Promise.race([
      ac.tryS('definitely:not:an:event' as never, {}),
      settle(400).then(() => 'no-ack' as const),
    ]);
    expect(ack).toBe('no-ack');
    expect(ac.socket.connected).toBe(true);
  });
});

describe('WebRTC signalling authorization', () => {
  it('relays an offer to the addressed peer only', async () => {
    const a = await ac.send<{ selfSocketId: string; peers: unknown[] }>('call:join', {
      conversationId: dm.id, media: { audio: true, video: true, screen: false },
    });
    const b = await bc.send<{ selfSocketId: string; peers: Array<{ socketId: string }> }>('call:join', {
      conversationId: dm.id, media: { audio: true, video: false, screen: false },
    });
    expect(a.peers).toHaveLength(0);
    expect(b.peers.map((p) => p.socketId)).toEqual([a.selfSocketId]);

    await ac.send('rtc:describe', {
      conversationId: dm.id, to: b.selfSocketId,
      description: { type: 'offer', sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB' },
    });
    const got = await bc.waitFor<{ from: string; fromUserId: string }>('rtc:describe');
    // `from` is stamped server-side, so a peer cannot impersonate another.
    expect(got.from).toBe(a.selfSocketId);
    expect(got.fromUserId).toBe(alice.userId);
  });

  it('refuses signalling to a peer that is not in the call', async () => {
    await ac.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    const bobSocketId = bc.socket.id!;
    // Bob is in the ROOM but never joined the CALL.
    const ack = await ac.tryS('rtc:describe', {
      conversationId: dm.id, to: bobSocketId, description: { type: 'offer', sdp: 'v=0' },
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('BAD_TARGET');
  });

  it('refuses signalling from someone not in the call', async () => {
    await bc.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    const ack = await ac.tryS('rtc:describe', {
      conversationId: dm.id, to: bc.socket.id!, description: { type: 'offer', sdp: 'v=0' },
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('NOT_JOINED');
  });

  it('refuses self-addressed signalling', async () => {
    const a = await ac.send<{ selfSocketId: string }>('call:join', {
      conversationId: dm.id, media: { audio: true, video: true, screen: false },
    });
    const ack = await ac.tryS('rtc:describe', {
      conversationId: dm.id, to: a.selfSocketId, description: { type: 'offer', sdp: 'v=0' },
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('BAD_TARGET');
  });

  it('enforces the mesh participant cap', async () => {
    // The cap is a hard limit: at n participants each client uploads n-1
    // encodes of its own camera, so an unbounded room is a self-inflicted DoS.
    const group = await api(server.url, '/api/conversations', {
      method: 'POST', token: alice.accessToken,
      body: { type: 'group', memberIds: [alice.userId, bob.userId, carol.userId] },
    });
    const gid = group.body.conversation.id;
    const clients: TestClient[] = [];
    const users = [alice, bob, carol];
    // MAX_CALL_PARTICIPANTS is 4 in test env; open extra tabs to exceed it.
    for (let i = 0; i < 5; i++) {
      const c = await connectClient(server.url, users[i % users.length]!);
      await c.send('room:join', { conversationId: gid });
      clients.push(c);
    }
    const acks = [];
    for (const c of clients) {
      acks.push(await c.tryS('call:join', { conversationId: gid, media: { audio: true, video: true, screen: false } }));
    }
    const ok = acks.filter((a) => a.ok).length;
    const full = acks.filter((a) => !a.ok && a.error.code === 'ROOM_FULL').length;
    expect(ok).toBe(4);
    expect(full).toBe(1);
    clients.forEach((c) => c.close());
  });

  it('tells peers when a socket disappears', async () => {
    await ac.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    await bc.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    const bobSocketId = bc.socket.id!;
    bc.close();
    // Without this, the remaining peer keeps a frozen tile and waits forever
    // on a negotiation that will never complete.
    const left = await ac.waitFor<{ socketId: string; reason: string }>('call:peer-left');
    expect(left.socketId).toBe(bobSocketId);
    expect(left.reason).toBe('disconnected');
  });

  it('broadcasts mute state, which peers cannot otherwise observe', async () => {
    await ac.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    await bc.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    await ac.send('rtc:media-state', { conversationId: dm.id, state: { audio: false, video: true, screen: false } });
    const state = await bc.waitFor<{ userId: string; state: { audio: boolean } }>('rtc:media-state');
    expect(state.userId).toBe(alice.userId);
    expect(state.state.audio).toBe(false);
  });

  it('caps SDP size rather than relaying it', async () => {
    await ac.send('call:join', { conversationId: dm.id, media: { audio: true, video: true, screen: false } });
    const b = await bc.send<{ selfSocketId: string }>('call:join', {
      conversationId: dm.id, media: { audio: true, video: true, screen: false },
    });
    const ack = await ac.tryS('rtc:describe', {
      conversationId: dm.id, to: b.selfSocketId,
      description: { type: 'offer', sdp: 'x'.repeat(64_001) },
    });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('VALIDATION');
  });
});

describe('whiteboard', () => {
  const stroke = (chunk: number, strokeId: string) => ({
    conversationId: dm.id,
    kind: 'stroke' as const,
    strokeId,
    chunk,
    done: chunk === 1,
    envelope: {
      alg: 'RTC/v1' as const,
      salt: b64uEncode(new Uint8Array(32).fill(1)),
      iv: b64uEncode(new Uint8Array(12).fill(2)),
      ct: b64uEncode(new Uint8Array(48).fill(chunk)),
      sig: b64uEncode(new Uint8Array(64).fill(4)),
      senderKeyVersion: 1,
    },
  });

  it('assigns a total order and relays to peers', async () => {
    const id = randomUUID();
    const a = await ac.send<{ seq: number }>('wb:op', stroke(0, id));
    const b = await ac.send<{ seq: number }>('wb:op', stroke(1, id));
    expect(b.seq).toBeGreaterThan(a.seq);
    const got = await bc.waitFor<{ record: WhiteboardOpRecord }>('wb:op', (p) => p.record.seq === a.seq);
    expect(got.record.kind).toBe('stroke');
    expect(got.record.strokeId).toBe(id);
    // Geometry stays encrypted; the server only learns that a stroke happened.
    expect(got.record.envelope).toBeTruthy();
  });

  it('replays the whole board for a late joiner', async () => {
    const ids = [randomUUID(), randomUUID()];
    for (const id of ids) {
      await ac.send('wb:op', stroke(0, id));
      await ac.send('wb:op', stroke(1, id));
    }
    const cc = await connectClient(server.url, bob);
    const sync = await cc.send<{ ops: WhiteboardOpRecord[]; latestSeq: number; truncated: boolean }>(
      'wb:sync', { conversationId: dm.id, sinceSeq: 0 },
    );
    expect(sync.ops).toHaveLength(4);
    expect(sync.ops.map((o) => o.seq)).toEqual([1, 2, 3, 4]);
    expect(sync.truncated).toBe(false);
    cc.close();
  });

  it('allows a delta sync after a reload', async () => {
    const id = randomUUID();
    await ac.send('wb:op', stroke(0, id));
    const second = await ac.send<{ seq: number }>('wb:op', stroke(1, id));
    const delta = await bc.send<{ ops: WhiteboardOpRecord[] }>('wb:sync', {
      conversationId: dm.id, sinceSeq: second.seq - 1,
    });
    expect(delta.ops.map((o) => o.seq)).toEqual([second.seq]);
  });

  it('permits undo only by the stroke’s author', async () => {
    // Global undo means Bob presses Ctrl+Z and erases Alice's work.
    const id = randomUUID();
    await ac.send('wb:op', stroke(0, id));
    const denied = await bc.tryS('wb:op', { conversationId: dm.id, kind: 'undo', strokeId: id });
    expect(denied.ok).toBe(false);
    if (!denied.ok) expect(denied.error.code).toBe('FORBIDDEN');
    const allowed = await ac.tryS('wb:op', { conversationId: dm.id, kind: 'undo', strokeId: id });
    expect(allowed.ok).toBe(true);
  });

  it('rejects undo of a stroke that does not exist', async () => {
    const ack = await ac.tryS('wb:op', { conversationId: dm.id, kind: 'undo', strokeId: randomUUID() });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('NOT_FOUND');
  });

  it('clears the board, attributed, and stops replaying old strokes', async () => {
    const id = randomUUID();
    await ac.send('wb:op', stroke(0, id));
    await ac.send('wb:op', stroke(1, id));
    await ac.send('wb:op', { conversationId: dm.id, kind: 'clear' });

    const reset = await bc.waitFor<{ byUserId: string; clearedAtSeq: number }>('wb:reset');
    expect(reset.byUserId).toBe(alice.userId);

    // A late joiner must NOT see the cleared strokes resurrected.
    const cc = await connectClient(server.url, bob);
    const sync = await cc.send<{ ops: WhiteboardOpRecord[] }>('wb:sync', { conversationId: dm.id, sinceSeq: 0 });
    expect(sync.ops.filter((o) => o.kind === 'stroke')).toHaveLength(0);
    cc.close();
  });

  it('refuses whiteboard ops from a non-member', async () => {
    const cc = await connectClient(server.url, carol);
    const ack = await cc.tryS('wb:op', stroke(0, randomUUID()));
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('NOT_A_MEMBER');
    cc.close();
  });
});

describe('encrypted attachments', () => {
  it('round-trips an encrypted file through upload and download', async () => {
    const plaintext = new Uint8Array(300_000);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = (i * 7) & 0xff;
    const fileId = randomUUID();
    const enc = await encryptFileBytes(plaintext, fileId);

    const form = new FormData();
    form.append('file', new Blob([enc.cipher as unknown as BlobPart]), 'blob');
    const up = await fetch(`${server.url}/api/files/${dm.id}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${alice.accessToken}`, origin: 'http://localhost:5173' },
      body: form,
    });
    expect(up.status).toBe(201);
    const { attachmentId } = (await up.json()) as { attachmentId: string };

    const down = await fetch(`${server.url}/api/files/${attachmentId}`, {
      headers: { authorization: `Bearer ${bob.accessToken}` },
    });
    expect(down.status).toBe(200);
    // Served opaquely: any origin that serves attacker-controlled bytes with a
    // sniffable type is a stored-XSS primitive on itself.
    expect(down.headers.get('content-type')).toBe('application/octet-stream');
    expect(down.headers.get('x-content-type-options')).toBe('nosniff');
    expect(down.headers.get('content-disposition')).toContain('attachment');

    const cipher = new Uint8Array(await down.arrayBuffer());
    const decrypted = await decryptFileBytes(cipher, enc.keyBytes, enc.meta);
    expect(decrypted).toEqual(plaintext);
  });

  it('refuses download to a non-member of the conversation', async () => {
    const enc = await encryptFileBytes(utf8('secret payload'), randomUUID());
    const form = new FormData();
    form.append('file', new Blob([enc.cipher as unknown as BlobPart]), 'blob');
    const up = await fetch(`${server.url}/api/files/${dm.id}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${alice.accessToken}` },
      body: form,
    });
    const { attachmentId } = (await up.json()) as { attachmentId: string };

    // Authorization is CURRENT MEMBERSHIP, not ownership and not "knows the id".
    const denied = await fetch(`${server.url}/api/files/${attachmentId}`, {
      headers: { authorization: `Bearer ${carol.accessToken}` },
    });
    expect(denied.status).toBe(403);
  });

  it('refuses upload to a conversation the caller is not in', async () => {
    const enc = await encryptFileBytes(utf8('nope'), randomUUID());
    const form = new FormData();
    form.append('file', new Blob([enc.cipher as unknown as BlobPart]), 'blob');
    const res = await fetch(`${server.url}/api/files/${dm.id}`, {
      method: 'POST',
      headers: { authorization: `Bearer ${carol.accessToken}` },
      body: form,
    });
    expect(res.status).toBe(403);
  });

  it('requires authentication to download', async () => {
    const res = await fetch(`${server.url}/api/files/${'a'.repeat(24)}`);
    expect(res.status).toBe(401);
  });
});

describe('group epochs over the wire', () => {
  it('blocks sending until an epoch is published, then allows it', async () => {
    const created = await api(server.url, '/api/conversations', {
      method: 'POST', token: alice.accessToken,
      body: { type: 'group', memberIds: [alice.userId, bob.userId] },
    });
    const gid = created.body.conversation.id;
    expect(created.body.conversation.rekeyPending).toBe(true);

    await ac.send('room:join', { conversationId: gid });
    await bc.send('room:join', { conversationId: gid });

    // Fail CLOSED: no current key means no sending, rather than falling back
    // to a stale key or storing something nobody can read.
    const tooEarly = await ac.tryS('message:send', {
      conversationId: gid, clientMsgId: randomUUID(), kind: 'text',
      sentAt: Date.now(),
      envelope: {
        alg: 'RTC/v1', salt: b64uEncode(new Uint8Array(32)), iv: b64uEncode(new Uint8Array(12)),
        ct: b64uEncode(new Uint8Array(32)), sig: b64uEncode(new Uint8Array(64)),
        senderKeyVersion: 1, epoch: 1,
      },
    });
    expect(tooEarly.ok).toBe(false);
    if (!tooEarly.ok) expect(tooEarly.error.code).toBe('REKEY_PENDING');

    // Alice mints epoch 1 and wraps it for every member.
    const keys = await api(server.url, `/api/conversations/${gid}/keys`, { token: alice.accessToken });
    const members = await Promise.all(
      (keys.body.members as Array<{ userId: string; current: { spkiEcdh: string; spkiEcdsa: string }; keyVersion: number }>)
        .map(async (m) => ({
          userId: m.userId,
          agreePub: (await importPublicKeys(m.current)).agreePub,
          keyVersion: m.keyVersion,
        })),
    );
    const { record, secret } = await createEpoch({
      conversationId: gid, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: Date.now(),
    });
    await ac.send('epoch:publish', { conversationId: gid, epoch: record });
    await bc.waitFor('epoch:new', (p: any) => p.epoch.epoch === 1);

    const root = await epochRootFromSecret(secret);
    const clientMsgId = randomUUID();
    const sentAt = Date.now();
    const envelope = await sealGroup(root, alice.priv.signPriv, {
      clientMsgId, conversationId: gid, senderId: alice.userId, epoch: 1,
      senderKeyVersion: 1, sentAt, contentType: 'text/plain',
    }, utf8('group hello'));

    const ack = await ac.send<{ seq: number }>('message:send', {
      conversationId: gid, clientMsgId, kind: 'text', envelope, sentAt,
    });
    expect(ack.seq).toBe(1);
  });

  it('rejects an epoch that omits a member', async () => {
    // Otherwise a malicious member could silently lock someone out of a room
    // they belong to — a partition attack the cryptography alone allows.
    const created = await api(server.url, '/api/conversations', {
      method: 'POST', token: alice.accessToken,
      body: { type: 'group', memberIds: [alice.userId, bob.userId, carol.userId] },
    });
    const gid = created.body.conversation.id;
    await ac.send('room:join', { conversationId: gid });

    const keys = await api(server.url, `/api/conversations/${gid}/keys`, { token: alice.accessToken });
    const all = keys.body.members as Array<{ userId: string; current: { spkiEcdh: string; spkiEcdsa: string }; keyVersion: number }>;
    const partial = await Promise.all(
      all.filter((m) => m.userId !== carol.userId).map(async (m) => ({
        userId: m.userId,
        agreePub: (await importPublicKeys(m.current)).agreePub,
        keyVersion: m.keyVersion,
      })),
    );
    const { record } = await createEpoch({
      conversationId: gid, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members: partial, reason: 'created', now: Date.now(),
    });
    const ack = await ac.tryS('epoch:publish', { conversationId: gid, epoch: record });
    expect(ack.ok).toBe(false);
    if (!ack.ok) expect(ack.error.code).toBe('VALIDATION');
  });
});
