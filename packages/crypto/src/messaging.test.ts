import { beforeAll, describe, expect, it } from 'vitest';
import type { CipherEnvelope } from '@rtc/shared';
import { dmRoot, openDm, sealDm, type DmContext } from './dm.js';
import {
  acceptEpoch, createEpoch, epochRootFromSecret, openGroup, sealGroup,
  type EpochMember, type GroupContext,
} from './group.js';
import { importPublicKeys } from './identity.js';
import { deriveMessageKey, open } from './aead.js';
import { groupMessageAad } from './aad.js';
import { DecryptError, b64uDecode, b64uEncode, fromUtf8, toArrayBuffer, utf8 } from './bytes.js';
import { makeUser, oid, type TestUser } from './testing.js';

const CONV = oid('c0nv');
const MSG = '11111111-2222-4333-8444-555555555555';

let alice: TestUser;
let bob: TestUser;
let carol: TestUser;

beforeAll(async () => {
  [alice, bob, carol] = await Promise.all([
    makeUser(oid('a11ce')), makeUser(oid('b0b')), makeUser(oid('ca401')),
  ]);
});

const dmCtx = (): DmContext => ({
  clientMsgId: MSG,
  conversationId: CONV,
  senderId: alice.userId,
  recipientId: bob.userId,
  senderKeyVersion: 1,
  sentAt: 1_700_000_000_000,
  contentType: 'text/plain',
});

const roots = async () => ({
  aliceRoot: await dmRoot(alice.priv.agreePriv, (await importPublicKeys(bob.pub)).agreePub),
  bobRoot: await dmRoot(bob.priv.agreePriv, (await importPublicKeys(alice.pub)).agreePub),
});

describe('1:1 messages', () => {
  it('round-trips between the two participants', async () => {
    const { aliceRoot, bobRoot } = await roots();
    const env = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('hello bob'));
    const { signPub } = await importPublicKeys(alice.pub);
    const out = await openDm(bobRoot, signPub, dmCtx(), env);
    expect(fromUtf8(out)).toBe('hello bob');
  });

  it('derives the same root from either side (ECDH symmetry)', async () => {
    const { aliceRoot, bobRoot } = await roots();
    const salt = new Uint8Array(32).fill(9);
    const [k1, k2] = await Promise.all([
      deriveMessageKey(aliceRoot, salt, 'probe'),
      deriveMessageKey(bobRoot, salt, 'probe'),
    ]);
    const ct = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: new Uint8Array(0) }, k1, toArrayBuffer(utf8('x')),
    );
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(12), additionalData: new Uint8Array(0) }, k2, ct,
    );
    expect(fromUtf8(new Uint8Array(pt))).toBe('x');
  });

  it('uses a fresh salt and IV per message, so identical plaintext differs', async () => {
    // A fresh derived key per message is what makes (key, IV) reuse
    // structurally impossible rather than merely improbable.
    const { aliceRoot } = await roots();
    const a = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('same'));
    const b = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('same'));
    expect(a.ct).not.toBe(b.ct);
    expect(a.iv).not.toBe(b.iv);
    expect(a.salt).not.toBe(b.salt);
  });

  it('rejects a message signed by someone else', async () => {
    const { aliceRoot, bobRoot } = await roots();
    // Carol seals using a root she should not have, and signs as herself.
    const env = await sealDm(aliceRoot, carol.priv.signPriv, dmCtx(), utf8('spoofed'));
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    await expect(openDm(bobRoot, alicePub, dmCtx(), env)).rejects.toThrow(DecryptError);
  });

  it('rejects a tampered ciphertext', async () => {
    const { aliceRoot, bobRoot } = await roots();
    const env = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('hello'));
    const ct = b64uDecode(env.ct);
    ct[0] = (ct[0] ?? 0) ^ 0x01;
    const { signPub } = await importPublicKeys(alice.pub);
    await expect(openDm(bobRoot, signPub, dmCtx(), { ...env, ct: b64uEncode(ct) }))
      .rejects.toThrow(DecryptError);
  });
});

/**
 * One test per AAD-bound field.
 *
 * This is what proves the security property rather than merely proving that
 * AES was called: if the server rewrites any of these columns, the recipient's
 * reconstructed AAD stops matching and decryption fails loudly.
 */
describe('AAD binding — server metadata tampering is detectable', () => {
  const mutations: Array<[string, (c: DmContext) => DmContext]> = [
    ['clientMsgId', (c) => ({ ...c, clientMsgId: '99999999-2222-4333-8444-555555555555' })],
    ['conversationId', (c) => ({ ...c, conversationId: oid('0ther') })],
    ['senderId', (c) => ({ ...c, senderId: oid('ca401') })],
    ['recipientId', (c) => ({ ...c, recipientId: oid('ca401') })],
    ['senderKeyVersion', (c) => ({ ...c, senderKeyVersion: 2 })],
    ['sentAt', (c) => ({ ...c, sentAt: c.sentAt + 1 })],
    ['contentType', (c) => ({ ...c, contentType: 'application/rtc-file-v1' })],
  ];

  for (const [field, mutate] of mutations) {
    it(`fails when the server alters ${field}`, async () => {
      const { aliceRoot, bobRoot } = await roots();
      const env = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('secret'));
      const { signPub } = await importPublicKeys(alice.pub);
      await expect(openDm(bobRoot, signPub, mutate(dmCtx()), env)).rejects.toThrow(DecryptError);
    });
  }

  it('succeeds when nothing was altered (control)', async () => {
    const { aliceRoot, bobRoot } = await roots();
    const env = await sealDm(aliceRoot, alice.priv.signPriv, dmCtx(), utf8('secret'));
    const { signPub } = await importPublicKeys(alice.pub);
    await expect(openDm(bobRoot, signPub, dmCtx(), env)).resolves.toBeDefined();
  });
});

// ── groups ──────────────────────────────────────────────────────────────────

const memberOf = async (u: TestUser): Promise<EpochMember> => ({
  userId: u.userId,
  agreePub: (await importPublicKeys(u.pub)).agreePub,
  keyVersion: u.keyVersion,
});

const groupCtx = (over: Partial<GroupContext> = {}): GroupContext => ({
  clientMsgId: MSG,
  conversationId: CONV,
  senderId: alice.userId,
  epoch: 1,
  senderKeyVersion: 1,
  sentAt: 1_700_000_000_000,
  contentType: 'text/plain',
  ...over,
});

describe('group epochs', () => {
  it('lets every wrapped member derive the same room key', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob), memberOf(carol)]);
    const { record, secret } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const aliceRoot = await epochRootFromSecret(secret);
    const { signPub: creatorPub } = await importPublicKeys(alice.pub);

    const env = await sealGroup(aliceRoot, alice.priv.signPriv, groupCtx(), utf8('team hello'));

    for (const u of [bob, carol]) {
      const root = await acceptEpoch({
        conversationId: CONV, record, myUserId: u.userId,
        myAgreePriv: u.priv.agreePriv, creatorSignPub: creatorPub,
      });
      expect(fromUtf8(await openGroup(root, creatorPub, groupCtx(), env))).toBe('team hello');
    }
  });

  it('rejects an epoch whose signature does not match the creator', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const { record } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: carol.priv.signPriv, // signed by the wrong key
      members, reason: 'created', now: 1,
    });
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    await expect(acceptEpoch({
      conversationId: CONV, record, myUserId: bob.userId,
      myAgreePriv: bob.priv.agreePriv, creatorSignPub: alicePub,
    })).rejects.toThrow(DecryptError);
  });

  it('rejects an epoch whose wraps were tampered with', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const { record } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    const bad = { ...record, wraps: record.wraps.map((w) => ({ ...w, iv: b64uEncode(new Uint8Array(12)) })) };
    await expect(acceptEpoch({
      conversationId: CONV, record: bad, myUserId: bob.userId,
      myAgreePriv: bob.priv.agreePriv, creatorSignPub: alicePub,
    })).rejects.toThrow(DecryptError);
  });

  it('gives a non-member no wrap to open', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const { record } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    await expect(acceptEpoch({
      conversationId: CONV, record, myUserId: carol.userId,
      myAgreePriv: carol.priv.agreePriv, creatorSignPub: alicePub,
    })).rejects.toThrow(/NO_EPOCH_WRAP_FOR_USER/);
  });
});

describe('rekey isolation', () => {
  it('cuts off a removed member and hides history from a joiner', async () => {
    const { signPub: alicePub } = await importPublicKeys(alice.pub);

    // Epoch 1: alice + bob.
    const e1 = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId, mySignPriv: alice.priv.signPriv,
      members: await Promise.all([memberOf(alice), memberOf(bob)]), reason: 'created', now: 1,
    });
    // Epoch 2: bob removed, carol added.
    const e2 = await createEpoch({
      conversationId: CONV, epoch: 2, myUserId: alice.userId, mySignPriv: alice.priv.signPriv,
      members: await Promise.all([memberOf(alice), memberOf(carol)]), reason: 'member_removed', now: 2,
    });

    const root1 = await epochRootFromSecret(e1.secret);
    const root2 = await epochRootFromSecret(e2.secret);

    const inE1 = await sealGroup(root1, alice.priv.signPriv, groupCtx({ epoch: 1 }), utf8('before'));
    const inE2 = await sealGroup(root2, alice.priv.signPriv, groupCtx({ epoch: 2 }), utf8('after'));

    // The removed member has no wrap in epoch 2, so cannot read anything new.
    await expect(acceptEpoch({
      conversationId: CONV, record: e2.record, myUserId: bob.userId,
      myAgreePriv: bob.priv.agreePriv, creatorSignPub: alicePub,
    })).rejects.toThrow(/NO_EPOCH_WRAP_FOR_USER/);

    // The joiner has no wrap in epoch 1, so cannot read history.
    await expect(acceptEpoch({
      conversationId: CONV, record: e1.record, myUserId: carol.userId,
      myAgreePriv: carol.priv.agreePriv, creatorSignPub: alicePub,
    })).rejects.toThrow(/NO_EPOCH_WRAP_FOR_USER/);

    // Carol reads epoch 2 fine.
    const carolRoot = await acceptEpoch({
      conversationId: CONV, record: e2.record, myUserId: carol.userId,
      myAgreePriv: carol.priv.agreePriv, creatorSignPub: alicePub,
    });
    expect(fromUtf8(await openGroup(carolRoot, alicePub, groupCtx({ epoch: 2 }), inE2))).toBe('after');

    // And an epoch-1 key cannot open an epoch-2 message.
    await expect(openGroup(root1, alicePub, groupCtx({ epoch: 2 }), inE2)).rejects.toThrow(DecryptError);
    await expect(openGroup(root2, alicePub, groupCtx({ epoch: 1 }), inE1)).rejects.toThrow(DecryptError);
  });

  it('generates an independent secret per epoch', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const a = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const b = await createEpoch({
      conversationId: CONV, epoch: 2, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'member_added', now: 2,
    });
    expect(a.secret).not.toEqual(b.secret);
    expect(a.record.ephSpki).not.toBe(b.record.ephSpki);
  });
});

/**
 * The single most important group-crypto test.
 *
 * Every member holds the epoch key, so AEAD alone cannot say WHO wrote a
 * message. Without a per-sender signature, any member could forge as any
 * other — and this test would pass while the app was silently broken.
 */
describe('group sender authentication', () => {
  it('stops one member forging a message as another', async () => {
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const { record, secret } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    const bobRoot = await acceptEpoch({
      conversationId: CONV, record, myUserId: bob.userId,
      myAgreePriv: bob.priv.agreePriv, creatorSignPub: alicePub,
    });

    // Bob seals a message CLAIMING to be from Alice, signing with his own key.
    const forgedCtx = groupCtx({ senderId: alice.userId });
    const forged = await sealGroup(bobRoot, bob.priv.signPriv, forgedCtx, utf8('transfer the money'));

    // Alice's client verifies against Alice's published key and rejects it.
    const aliceRoot = await epochRootFromSecret(secret);
    await expect(openGroup(aliceRoot, alicePub, forgedCtx, forged)).rejects.toThrow(DecryptError);
  });

  it('demonstrates that AEAD alone would have accepted the forgery', async () => {
    // Kept deliberately: it documents exactly what the signature is buying.
    // If someone ever "simplifies" the envelope by dropping `sig`, this test
    // shows the resulting hole rather than leaving it to a code review.
    const members = await Promise.all([memberOf(alice), memberOf(bob)]);
    const { record } = await createEpoch({
      conversationId: CONV, epoch: 1, myUserId: alice.userId,
      mySignPriv: alice.priv.signPriv, members, reason: 'created', now: 1,
    });
    const { signPub: alicePub } = await importPublicKeys(alice.pub);
    const bobRoot = await acceptEpoch({
      conversationId: CONV, record, myUserId: bob.userId,
      myAgreePriv: bob.priv.agreePriv, creatorSignPub: alicePub,
    });

    const forgedCtx = groupCtx({ senderId: alice.userId });
    const forged: CipherEnvelope = await sealGroup(bobRoot, bob.priv.signPriv, forgedCtx, utf8('forged'));

    // Bypassing the signature check, the GCM tag verifies happily.
    const key = await deriveMessageKey(
      bobRoot, b64uDecode(forged.salt),
      `rtc/v1/group-msg|${CONV}|1|${MSG}`,
    );
    const plain = await open(key, groupMessageAad(forgedCtx), b64uDecode(forged.iv), b64uDecode(forged.ct));
    expect(fromUtf8(plain)).toBe('forged');
  });
});
