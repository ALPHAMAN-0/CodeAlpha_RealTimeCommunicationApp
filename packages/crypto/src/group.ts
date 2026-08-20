import type { CipherEnvelope, ContentType, EpochRecord, EpochWrap, RekeyReason } from '@rtc/shared';
import { epochWrapAad, groupMessageAad, packAad } from './aad.js';
import {
  SALT_BYTES, deriveMessageKey, ecdhRoot, importHkdfRoot, open, seal, sha256,
  signBytes, verifyBytes,
} from './aead.js';
import {
  DecryptError, b64uDecode, b64uEncode, concat, randomBytes, toArrayBuffer, utf8, zero,
} from './bytes.js';
import { importPublicKeys } from './identity.js';

const ECDH_P256 = { name: 'ECDH', namedCurve: 'P-256' } as const;
const EPOCH_SECRET_BYTES = 32;

export interface EpochMember {
  userId: string;
  /** The member's ECDH public key, already verified against their key log. */
  agreePub: CryptoKey;
  keyVersion: number;
}

/**
 * Deterministic HKDF salt for an epoch's per-member wrap keys.
 *
 * Both sides can compute it, it is unique per (conversation, epoch), and it
 * avoids the zero-salt case that some WebCrypto implementations are fussy
 * about.
 */
const wrapSalt = (conversationId: string, epoch: number) =>
  sha256(utf8(`rtc/v1/epoch-kek|${conversationId}|${epoch}`));

const wrapInfo = (conversationId: string, epoch: number, memberId: string) =>
  `rtc/v1/epoch-kek|${conversationId}|${epoch}|${memberId}`;

/**
 * Mint a new epoch: one random room secret, wrapped once per member.
 *
 * The sender key is EPHEMERAL rather than the creator's identity key
 * (static-ephemeral ECDH). That costs one keygen and buys forward secrecy of
 * the wrap against later compromise of the creator's identity key.
 *
 * Being precise about what it does not buy: it does NOT protect against
 * compromise of a RECIPIENT's identity key, since that key is static and can
 * re-derive the same wrap KEK. The asymmetry is inherent to wrapping to
 * long-term keys and is documented rather than glossed over.
 */
export async function createEpoch(args: {
  conversationId: string;
  epoch: number;
  myUserId: string;
  mySignPriv: CryptoKey;
  members: readonly EpochMember[];
  reason: RekeyReason;
  now: number;
}): Promise<{ record: EpochRecord; secret: Uint8Array }> {
  const secret = randomBytes(EPOCH_SECRET_BYTES);
  const eph = (await crypto.subtle.generateKey(ECDH_P256, false, ['deriveKey', 'deriveBits'])) as CryptoKeyPair;
  const ephSpkiBytes = new Uint8Array(await crypto.subtle.exportKey('spki', eph.publicKey));
  const ephSpki = b64uEncode(ephSpkiBytes);
  const salt = await wrapSalt(args.conversationId, args.epoch);

  const wraps: EpochWrap[] = [];
  for (const m of args.members) {
    const root = await ecdhRoot(eph.privateKey, m.agreePub);
    const kek = await deriveMessageKey(root, salt, wrapInfo(args.conversationId, args.epoch, m.userId));
    const aad = epochWrapAad({
      conversationId: args.conversationId,
      epoch: args.epoch,
      senderId: args.myUserId,
      recipientId: m.userId,
      recipientKeyVersion: m.keyVersion,
    });
    const { iv, ct } = await seal(kek, aad, secret);
    wraps.push({
      userId: m.userId as EpochWrap['userId'],
      keyVersion: m.keyVersion,
      iv: b64uEncode(iv),
      wrapped: b64uEncode(ct),
    });
  }

  const sig = await signBytes(
    args.mySignPriv,
    epochSignPayload(args.conversationId, args.epoch, ephSpki, wraps),
  );

  return {
    record: {
      epoch: args.epoch,
      ephSpki,
      createdBy: args.myUserId as EpochRecord['createdBy'],
      createdAt: args.now,
      sig: b64uEncode(sig),
      wraps,
      reason: args.reason,
    },
    secret,
  };
}

/** Exactly the bytes an epoch's signature commits to. */
function epochSignPayload(
  conversationId: string,
  epoch: number,
  ephSpki: string,
  wraps: readonly EpochWrap[],
): Uint8Array {
  const parts: (string | Uint8Array)[] = ['rtc/v1/epoch', conversationId, String(epoch), ephSpki];
  for (const w of wraps) {
    parts.push(w.userId, String(w.keyVersion), w.iv, w.wrapped);
  }
  return packAad(...parts);
}

/**
 * Unwrap this member's copy of an epoch key.
 *
 * The creator's signature is verified before anything is decrypted: the
 * server relays epochs but cannot forge one, and this check is what enforces
 * that. An unsigned or wrongly-signed epoch is rejected outright rather than
 * being trusted because it arrived over an authenticated socket.
 */
export async function acceptEpoch(args: {
  conversationId: string;
  record: EpochRecord;
  myUserId: string;
  myAgreePriv: CryptoKey;
  /** The epoch creator's signing key, from their verified key log. */
  creatorSignPub: CryptoKey;
}): Promise<CryptoKey> {
  const { record } = args;
  const okSig = await verifyBytes(
    args.creatorSignPub,
    b64uDecode(record.sig),
    epochSignPayload(args.conversationId, record.epoch, record.ephSpki, record.wraps),
  );
  if (!okSig) throw new DecryptError('BAD_EPOCH_SIGNATURE');

  const mine = record.wraps.find((w) => w.userId === args.myUserId);
  if (!mine) throw new DecryptError('NO_EPOCH_WRAP_FOR_USER');

  const ephPub = await crypto.subtle.importKey(
    'spki',
    toArrayBuffer(b64uDecode(record.ephSpki)),
    ECDH_P256,
    false,
    [],
  );
  const root = await ecdhRoot(args.myAgreePriv, ephPub);
  const salt = await wrapSalt(args.conversationId, record.epoch);
  const kek = await deriveMessageKey(root, salt, wrapInfo(args.conversationId, record.epoch, args.myUserId));
  const aad = epochWrapAad({
    conversationId: args.conversationId,
    epoch: record.epoch,
    senderId: record.createdBy,
    recipientId: args.myUserId,
    recipientKeyVersion: mine.keyVersion,
  });
  const secret = await open(kek, aad, b64uDecode(mine.iv), b64uDecode(mine.wrapped));
  try {
    return await importHkdfRoot(secret);
  } finally {
    zero(secret);
  }
}

/** Turn a freshly created epoch secret into the same HKDF root recipients get. */
export async function epochRootFromSecret(secret: Uint8Array): Promise<CryptoKey> {
  return importHkdfRoot(secret);
}

export interface GroupContext {
  clientMsgId: string;
  conversationId: string;
  senderId: string;
  epoch: number;
  senderKeyVersion: number;
  sentAt: number;
  contentType: ContentType;
}

const groupInfo = (ctx: GroupContext) =>
  `rtc/v1/group-msg|${ctx.conversationId}|${ctx.epoch}|${ctx.clientMsgId}`;

/**
 * Seal a group message under the current epoch.
 *
 * The ECDSA signature is not optional decoration. Every member holds the
 * epoch key, so the GCM tag proves only "someone in this room wrote this".
 * Without a per-sender signature any member could forge a message attributed
 * to any other — the single most common flaw in homegrown group E2EE.
 */
export async function sealGroup(
  epochRoot: CryptoKey,
  signPriv: CryptoKey,
  ctx: GroupContext,
  plaintext: Uint8Array,
): Promise<CipherEnvelope> {
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveMessageKey(epochRoot, salt, groupInfo(ctx));
  const aad = groupMessageAad(ctx);
  const { iv, ct } = await seal(key, aad, plaintext);
  const sig = await signBytes(signPriv, concat(aad, iv, ct));
  return {
    alg: 'RTC/v1',
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    ct: b64uEncode(ct),
    sig: b64uEncode(sig),
    senderKeyVersion: ctx.senderKeyVersion,
    epoch: ctx.epoch,
  };
}

export async function openGroup(
  epochRoot: CryptoKey,
  senderSignPub: CryptoKey,
  ctx: GroupContext,
  env: CipherEnvelope,
): Promise<Uint8Array> {
  const iv = b64uDecode(env.iv);
  const ct = b64uDecode(env.ct);
  const aad = groupMessageAad(ctx);
  if (!(await verifyBytes(senderSignPub, b64uDecode(env.sig), concat(aad, iv, ct)))) {
    throw new DecryptError('BAD_SIGNATURE');
  }
  const key = await deriveMessageKey(epochRoot, b64uDecode(env.salt), groupInfo(ctx));
  return open(key, aad, iv, ct);
}

/** Helper for callers holding a raw SPKI pair rather than imported keys. */
export const memberFromKeys = async (
  userId: string,
  rec: { spkiEcdh: string; spkiEcdsa: string; keyVersion: number },
): Promise<EpochMember> => {
  const { agreePub } = await importPublicKeys(rec);
  return { userId, agreePub, keyVersion: rec.keyVersion };
};
