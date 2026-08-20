/**
 * Seed a demo dataset.
 *
 * This script deliberately acts as a CLIENT: it generates real identity keys,
 * derives real KEKs, and seals every message with the same @rtc/crypto code
 * the browser uses. Inserting plaintext rows directly would be far quicker and
 * would produce a database the real app cannot read — which is exactly the
 * kind of demo data that hides bugs instead of exposing them.
 *
 *   pnpm seed              # idempotent: safe to run repeatedly
 *   pnpm seed --reset      # wipe first
 *   pnpm seed --if-empty   # no-op if any user exists (used by `pnpm dev`)
 */
import { Types } from 'mongoose';
import {
  b64uEncode, createEpoch, deriveAccountSecrets, deriveRecoveryKek,
  dmRoot, epochRootFromSecret, exportPublicKeys, generateIdentity, generateRecoveryCode,
  importPublicKeys, newKdfSalt, openIdentity, sealDm, sealGroup, sealIdentity,
  signKeyRecord, utf8, type IdentityPrivate,
} from '@rtc/crypto';
import type { CipherEnvelope, KdfParams, StrokePayload } from '@rtc/shared';
import { whiteboardAad, deriveMessageKey, seal, signBytes, concat, randomBytes, SALT_BYTES } from '@rtc/crypto';
import { env } from '../config/env.js';
import { connectDb, disconnectDb } from '../db/connect.js';
import { ensureIndexes } from '../db/ensureIndexes.js';
import {
  Attachment, Conversation, Epoch, Message, Participant, RefreshToken, User, WhiteboardOp,
} from '../db/models/index.js';
import { blindIndex, sealField } from '../crypto/sealedField.js';
import { hashProof } from '../crypto/passwords.js';

/**
 * Weak KDF params for demo accounts only.
 *
 * Seeding three accounts at the production 64 MiB / t=3 costs several seconds
 * each and would make `pnpm dev` feel broken. Real registrations always use
 * DEFAULT_KDF_PARAMS; these accounts advertise their own params, so the client
 * derives correctly either way.
 */
const SEED_KDF: KdfParams = { kdf: 'argon2id', memoryKiB: 8192, iterations: 1, parallelism: 1 };

interface SeedUser {
  id: Types.ObjectId;
  email: string;
  displayName: string;
  avatarColor: string;
  priv: IdentityPrivate;
  pub: { spkiEcdh: string; spkiEcdsa: string };
  keyVersion: number;
}

const AVATARS = ['#2563eb', '#059669', '#c026d3'];

async function createUser(name: string, index: number): Promise<SeedUser> {
  const id = new Types.ObjectId();
  const email = `${name.toLowerCase()}@demo.dev`;
  const userId = id.toHexString();

  const kdfSalt = newKdfSalt();
  const { authProof, kek } = await deriveAccountSecrets(env.SEED_PASSWORD, kdfSalt, SEED_KDF);
  const kp = await generateIdentity();
  const pub = await exportPublicKeys(kp);
  const publicKeys = await signKeyRecord(
    userId, { ...pub, keyVersion: 1, createdAt: Date.now() }, kp.sign.privateKey,
  );
  const recoverySalt = newKdfSalt();
  const passwordWrap = await sealIdentity(kp, kek, {
    userId, keyVersion: 1, kdfSalt, kdfParams: SEED_KDF, purpose: 'password',
  });
  const recoveryWrap = await sealIdentity(
    kp, await deriveRecoveryKek(generateRecoveryCode(), recoverySalt),
    { userId, keyVersion: 1, kdfSalt: recoverySalt, kdfParams: SEED_KDF, purpose: 'recovery' },
  );

  await User.create({
    _id: id,
    emailSealed: sealField(email, 'users', 'email', userId),
    emailIndex: blindIndex(email),
    displayName: name,
    avatarColor: AVATARS[index % AVATARS.length]!,
    proofHash: await hashProof(b64uEncode(authProof)),
    kdfSalt: b64uEncode(kdfSalt),
    kdfParams: SEED_KDF,
    keyLog: [publicKeys],
    keyVersion: 1,
    passwordWrap,
    recoveryWrap,
    presence: { status: 'offline', lastSeenAt: new Date() },
  });

  const priv = await openIdentity(passwordWrap, kek, { userId, purpose: 'password' });
  return { id, email, displayName: name, avatarColor: AVATARS[index % AVATARS.length]!, priv, pub, keyVersion: 1 };
}

const DM_SCRIPT: Array<[0 | 1, string]> = [
  [0, 'Morning! Did the encrypted file sharing land?'],
  [1, 'It did. Attachments are chunked and sealed client-side before upload.'],
  [0, 'So the server literally cannot read them?'],
  [1, 'Correct. It stores ciphertext and serves it back as octet-stream. It never sees the filename either.'],
  [0, 'Nice. What happens if someone truncates the upload?'],
  [1, 'Every chunk binds its index and the total count into the AAD, so a short stream fails to authenticate.'],
  [0, 'And if I lose my password?'],
  [1, 'Then your history is gone unless you kept the recovery code. That is what E2EE actually means.'],
  [0, 'Harsh but honest. Better than pretending otherwise.'],
  [1, 'The reset screen says it in plain language rather than burying it.'],
  [0, 'How is the call quality with three people?'],
  [1, 'Mesh, so each of us uploads two streams. It steps down to 640x360 automatically at three or more.'],
  [0, 'Makes sense. Beyond that you would need an SFU.'],
  [1, 'Exactly — that is written down in docs/WEBRTC.md rather than implied to scale forever.'],
  [0, 'Try the whiteboard? I want to sketch the key rotation flow.'],
  [1, 'Go ahead. Strokes are encrypted too, so the server only knows that someone drew.'],
  [0, 'Even the undo?'],
  [1, 'The op kind and stroke id are visible — the server needs them to authorize undo and prune on clear. Geometry is not.'],
  [0, 'Good line to draw. Ship it.'],
  [1, 'Reconnect handling is in too: kill the server mid-send and nothing duplicates.'],
];

const GROUP_SCRIPT: Array<[number, string]> = [
  [0, 'Adding you both here so we can test group keys.'],
  [1, 'Nice — so every membership change rotates the room key?'],
  [0, 'Yes. Removed members cannot read the next message, and joiners cannot read the last one.'],
  [2, 'Just joined. I genuinely cannot see the history above, can I?'],
  [0, 'You cannot, and that is the intended behaviour rather than a bug.'],
  [1, 'What stops me forging a message as Alice, since we share the room key?'],
  [0, 'A per-sender ECDSA signature. The AEAD tag alone would only prove "someone in this room".'],
  [2, 'That is the part most homegrown group crypto gets wrong.'],
  [1, 'There is a test for exactly that failure mode.'],
  [0, 'Sending is blocked while a rotation is pending too — fail closed, never fall back to the old key.'],
];

const WB_SKETCH: StrokePayload[] = [
  { tool: 'pen', color: '#4dd8e6', width: 8, points: [700, 700, 900, 700, 1100, 700, 1300, 700, 1500, 700] },
  { tool: 'pen', color: '#4dd8e6', width: 8, points: [1500, 700, 1500, 900, 1500, 1100] },
  { tool: 'pen', color: '#4dd8e6', width: 8, points: [1500, 1100, 1300, 1100, 1100, 1100, 900, 1100, 700, 1100] },
  { tool: 'pen', color: '#4dd8e6', width: 8, points: [700, 1100, 700, 900, 700, 700] },
  { tool: 'pen', color: '#a78bfa', width: 6, points: [1700, 700, 2000, 900, 1700, 1100] },
  { tool: 'pen', color: '#a78bfa', width: 6, points: [2100, 700, 2100, 1100, 2400, 1100] },
  { tool: 'highlighter', color: '#fbbf24', width: 20, points: [650, 1250, 2450, 1250] },
  { tool: 'pen', color: '#34d399', width: 6, points: [2600, 700, 2900, 700, 2900, 1100, 2600, 1100, 2600, 700] },
  { tool: 'pen', color: '#34d399', width: 6, points: [2750, 700, 2750, 1100] },
  { tool: 'pen', color: '#f87171', width: 6, points: [3100, 800, 3300, 1000] },
  { tool: 'pen', color: '#f87171', width: 6, points: [3300, 800, 3100, 1000] },
];

async function main(): Promise<void> {
  const reset = process.argv.includes('--reset');
  const ifEmpty = process.argv.includes('--if-empty');

  await connectDb();
  await ensureIndexes();

  if (reset) {
    await Promise.all([
      User.deleteMany({}), RefreshToken.deleteMany({}), Conversation.deleteMany({}),
      Participant.deleteMany({}), Message.deleteMany({}), Attachment.deleteMany({}),
      WhiteboardOp.deleteMany({}), Epoch.deleteMany({}),
    ]);
    process.stdout.write('Wiped existing data.\n');
  }

  const existing = await User.countDocuments({});
  if (existing > 0) {
    process.stdout.write(
      ifEmpty
        ? 'Database already has users — skipping seed.\n'
        : 'Database already has users. Use --reset to reseed.\n',
    );
    await disconnectDb();
    return;
  }

  process.stdout.write('Generating demo identities (real keys, real crypto)…\n');
  const [alice, bob, carol] = await Promise.all([
    createUser('Alice', 0), createUser('Bob', 1), createUser('Carol', 2),
  ]);
  const users = [alice, bob, carol];

  // ── DM: Alice <-> Bob ────────────────────────────────────────────────────
  const dmId = new Types.ObjectId();
  const dmKey = [alice.id.toHexString(), bob.id.toHexString()].sort().join(':');
  await Conversation.create({
    _id: dmId, type: 'dm', dmKey,
    memberIds: [alice.id, bob.id], createdBy: alice.id,
    messageSeq: 0, whiteboardSeq: 0, epoch: 0, rekeyPending: false,
    whiteboard: { clearedAtSeq: 0, opCount: 0, truncated: false },
  });
  await Participant.insertMany([alice, bob].map((u, i) => ({
    conversationId: dmId, userId: u.id, role: i === 0 ? 'owner' : 'member',
    lastReadSeq: 0, lastDeliveredSeq: 0, joinedAt: new Date(),
  })));

  const aliceRoot = await dmRoot(alice.priv.agreePriv, (await importPublicKeys(bob.pub)).agreePub);
  let seq = 0;
  // Backdated so scroll-back pagination is visibly exercised rather than
  // everything landing in one minute.
  let clock = Date.now() - DM_SCRIPT.length * 7 * 60_000;
  let lastDm: { id: Types.ObjectId; seq: number; senderId: Types.ObjectId; at: Date } | undefined;

  for (const [who, text] of DM_SCRIPT) {
    const sender = who === 0 ? alice : bob;
    const recipient = who === 0 ? bob : alice;
    const clientMsgId = crypto.randomUUID();
    seq += 1;
    clock += 7 * 60_000;

    const envelope: CipherEnvelope = await sealDm(aliceRoot, sender.priv.signPriv, {
      clientMsgId,
      conversationId: dmId.toHexString(),
      senderId: sender.id.toHexString(),
      recipientId: recipient.id.toHexString(),
      senderKeyVersion: 1,
      sentAt: clock,
      contentType: 'text/plain',
    }, utf8(text));

    const created = await Message.create({
      conversationId: dmId, seq, senderId: sender.id, clientMsgId,
      kind: 'text', envelope, sentAt: clock, createdAt: new Date(clock),
    });
    lastDm = { id: created._id, seq, senderId: sender.id, at: new Date(clock) };
  }

  await Conversation.updateOne({ _id: dmId }, {
    $set: {
      messageSeq: seq,
      ...(lastDm ? {
        lastMessage: {
          messageId: lastDm.id, seq: lastDm.seq, senderId: lastDm.senderId,
          kind: 'text', createdAt: lastDm.at,
        },
      } : {}),
    },
  });

  /**
   * Leave Bob a few unread.
   *
   * A zero-everywhere seed makes the unread badge look broken rather than
   * absent, so the read watermarks stop short of the newest message.
   */
  await Participant.updateOne({ conversationId: dmId, userId: alice.id }, { $set: { lastReadSeq: seq, lastDeliveredSeq: seq } });
  await Participant.updateOne({ conversationId: dmId, userId: bob.id }, { $set: { lastReadSeq: Math.max(0, seq - 3), lastDeliveredSeq: seq } });

  // ── Group: all three, with a real epoch ──────────────────────────────────
  const groupId = new Types.ObjectId();
  await Conversation.create({
    _id: groupId, type: 'group',
    memberIds: users.map((u) => u.id), createdBy: alice.id,
    messageSeq: 0, whiteboardSeq: 0, epoch: 0, rekeyPending: true, rekeyReason: 'created',
    whiteboard: { clearedAtSeq: 0, opCount: 0, truncated: false },
  });
  await Participant.insertMany(users.map((u, i) => ({
    conversationId: groupId, userId: u.id, role: i === 0 ? 'owner' : 'member',
    lastReadSeq: 0, lastDeliveredSeq: 0, joinedAt: new Date(),
  })));

  const members = await Promise.all(users.map(async (u) => ({
    userId: u.id.toHexString(),
    agreePub: (await importPublicKeys(u.pub)).agreePub,
    keyVersion: 1,
  })));
  const { record: epochRecord, secret } = await createEpoch({
    conversationId: groupId.toHexString(), epoch: 1, myUserId: alice.id.toHexString(),
    mySignPriv: alice.priv.signPriv, members, reason: 'created', now: Date.now(),
  });
  await Epoch.create({
    conversationId: groupId, epoch: 1, ephSpki: epochRecord.ephSpki,
    createdBy: alice.id, sig: epochRecord.sig, reason: 'created',
    wraps: epochRecord.wraps.map((w) => ({
      userId: new Types.ObjectId(String(w.userId)),
      keyVersion: w.keyVersion, iv: w.iv, wrapped: w.wrapped,
    })),
  });
  await Conversation.updateOne({ _id: groupId }, {
    $set: { epoch: 1, rekeyPending: false }, $unset: { rekeyReason: 1 },
  });

  const groupRoot = await epochRootFromSecret(secret);
  let gseq = 0;
  let gclock = Date.now() - GROUP_SCRIPT.length * 11 * 60_000;
  let lastGroup: { id: Types.ObjectId; seq: number; senderId: Types.ObjectId; at: Date } | undefined;

  for (const [who, text] of GROUP_SCRIPT) {
    const sender = users[who]!;
    const clientMsgId = crypto.randomUUID();
    gseq += 1;
    gclock += 11 * 60_000;
    const envelope = await sealGroup(groupRoot, sender.priv.signPriv, {
      clientMsgId,
      conversationId: groupId.toHexString(),
      senderId: sender.id.toHexString(),
      epoch: 1, senderKeyVersion: 1, sentAt: gclock, contentType: 'text/plain',
    }, utf8(text));
    const created = await Message.create({
      conversationId: groupId, seq: gseq, senderId: sender.id, clientMsgId,
      kind: 'text', envelope, sentAt: gclock, createdAt: new Date(gclock),
    });
    lastGroup = { id: created._id, seq: gseq, senderId: sender.id, at: new Date(gclock) };
  }

  await Conversation.updateOne({ _id: groupId }, {
    $set: {
      messageSeq: gseq,
      ...(lastGroup ? {
        lastMessage: {
          messageId: lastGroup.id, seq: lastGroup.seq, senderId: lastGroup.senderId,
          kind: 'text', createdAt: lastGroup.at,
        },
      } : {}),
    },
  });
  await Participant.updateOne({ conversationId: groupId, userId: alice.id }, { $set: { lastReadSeq: gseq, lastDeliveredSeq: gseq } });
  await Participant.updateOne({ conversationId: groupId, userId: bob.id }, { $set: { lastReadSeq: gseq - 2, lastDeliveredSeq: gseq } });

  /**
   * A non-empty whiteboard on first open.
   *
   * Encrypted with the same envelope the client uses, so the demo board proves
   * the whole path rather than just that a canvas renders.
   */
  let wseq = 0;
  for (const [index, sketch] of WB_SKETCH.entries()) {
    const strokeId = crypto.randomUUID();
    const author = users[index % 2]!;
    wseq += 1;
    const aad = whiteboardAad({
      conversationId: dmId.toHexString(), strokeId, chunk: 0,
      authorId: author.id.toHexString(), epoch: 0, senderKeyVersion: 1,
    });
    const salt = randomBytes(SALT_BYTES);
    const key = await deriveMessageKey(
      aliceRoot, salt, `rtc/v1/wb-op|${dmId.toHexString()}|${strokeId}|0`,
    );
    const { iv, ct } = await seal(key, aad, utf8(JSON.stringify(sketch)));
    const sig = await signBytes(author.priv.signPriv, concat(aad, iv, ct));
    await WhiteboardOp.create({
      conversationId: dmId, seq: wseq, authorId: author.id, kind: 'stroke',
      strokeId, chunk: 0, done: true,
      envelope: {
        alg: 'RTC/v1', salt: b64uEncode(salt), iv: b64uEncode(iv),
        ct: b64uEncode(ct), sig: b64uEncode(sig), senderKeyVersion: 1,
      },
    });
  }
  await Conversation.updateOne({ _id: dmId }, {
    $set: { whiteboardSeq: wseq, 'whiteboard.opCount': wseq },
  });

  process.stdout.write(
    `\nSeeded successfully.\n\n` +
    `  Accounts (password: ${env.SEED_PASSWORD})\n` +
    users.map((u) => `    ${u.email.padEnd(18)} ${u.displayName}`).join('\n') +
    `\n\n  Conversations\n` +
    `    Alice <-> Bob        ${DM_SCRIPT.length} messages, ${wseq} whiteboard strokes\n` +
    `    Alice, Bob, Carol    ${GROUP_SCRIPT.length} messages, group epoch 1\n\n` +
    `  Every message above is real ciphertext. Verify it yourself:\n` +
    `    docker compose exec mongo mongosh rtc --eval 'db.messages.findOne()'\n\n`,
  );

  await disconnectDb();
}

main().catch(async (err) => {
  process.stderr.write(`Seed failed: ${String(err instanceof Error ? err.stack : err)}\n`);
  await disconnectDb().catch(() => undefined);
  process.exit(1);
});
