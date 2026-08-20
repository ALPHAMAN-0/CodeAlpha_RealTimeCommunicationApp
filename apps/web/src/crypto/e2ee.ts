import {
  acceptEpoch, dmRoot, epochRootFromSecret, importPublicKeys, keyFingerprint,
  openDm, openGroup, sealDm, sealGroup, verifyKeyLog,
  type DmContext, type GroupContext, type IdentityPrivate,
} from '@rtc/crypto';
import type {
  CipherEnvelope, ContentType, EpochRecord, MessageDTO, PublicKeyBundle,
} from '@rtc/shared';
import { request } from '../lib/api.js';
import { checkTrust, type TrustVerdict } from './keystore.js';

/**
 * The client-side encryption layer.
 *
 * Everything here is cache management around the primitives in @rtc/crypto.
 * The caches are in-memory only and per-tab: derived keys are non-extractable
 * CryptoKey handles, so there is nothing to persist even if we wanted to.
 */

export interface PeerKeys {
  userId: string;
  agreePub: CryptoKey;
  signPub: CryptoKey;
  keyVersion: number;
  fingerprint: string;
  trust: TrustVerdict;
  raw: { spkiEcdh: string; spkiEcdsa: string };
}

const peerCache = new Map<string, PeerKeys>();
const dmRootCache = new Map<string, CryptoKey>();
const epochRootCache = new Map<string, CryptoKey>();

export class KeyTrustError extends Error {
  constructor(readonly peerId: string, readonly fingerprint: string) {
    super('This contact’s security code changed');
    this.name = 'KeyTrustError';
  }
}

/**
 * Fetch and verify a peer's identity keys.
 *
 * Two independent checks, and both matter:
 *
 *  1. The signed, append-only key log must verify — versions increasing by
 *     one, each self-signed, each rotation counter-signed by the key it
 *     replaces. This makes later tampering evident.
 *  2. TOFU pinning. A verified chain does NOT rule out a server that lied from
 *     first contact, so a changed fingerprint blocks sending until a human
 *     compares safety numbers out of band. That is the only defence against
 *     first-contact substitution, and it is why the UI surfaces it loudly.
 */
export async function peerKeys(userId: string, opts?: { force?: boolean }): Promise<PeerKeys> {
  if (!opts?.force) {
    const hit = peerCache.get(userId);
    if (hit) return hit;
  }

  const bundle = await request<PublicKeyBundle>(`/api/keys/${userId}`);
  if (!(await verifyKeyLog(userId, bundle.log))) {
    throw new Error(`Identity key log for ${userId} failed verification`);
  }
  const fingerprint = await keyFingerprint(bundle.current);
  const trust = await checkTrust(userId, fingerprint);
  const { agreePub, signPub } = await importPublicKeys(bundle.current);

  const keys: PeerKeys = {
    userId,
    agreePub: agreePub as CryptoKey,
    signPub: signPub as CryptoKey,
    keyVersion: bundle.current.keyVersion,
    fingerprint,
    trust,
    raw: { spkiEcdh: bundle.current.spkiEcdh, spkiEcdsa: bundle.current.spkiEcdsa },
  };
  peerCache.set(userId, keys);
  return keys;
}

/** Drop caches for a peer after an accepted key change. */
export function forgetPeer(userId: string): void {
  peerCache.delete(userId);
  for (const key of [...dmRootCache.keys()]) {
    if (key.includes(userId)) dmRootCache.delete(key);
  }
}

async function rootForDm(priv: IdentityPrivate, peerId: string): Promise<CryptoKey> {
  const cached = dmRootCache.get(peerId);
  if (cached) return cached;
  const peer = await peerKeys(peerId);
  if (peer.trust === 'CHANGED') throw new KeyTrustError(peerId, peer.fingerprint);
  const root = (await dmRoot(priv.agreePriv, peer.agreePub as never)) as CryptoKey;
  dmRootCache.set(peerId, root);
  return root;
}

const epochKey = (conversationId: string, epoch: number) => `${conversationId}:${epoch}`;

/** Unwrap and cache a group epoch key. */
export async function ingestEpoch(
  priv: IdentityPrivate,
  myUserId: string,
  conversationId: string,
  record: EpochRecord,
): Promise<void> {
  const creator = await peerKeys(String(record.createdBy));
  const root = await acceptEpoch({
    conversationId,
    record,
    myUserId,
    myAgreePriv: priv.agreePriv,
    creatorSignPub: creator.signPub as never,
  });
  epochRootCache.set(epochKey(conversationId, record.epoch), root as CryptoKey);
}

/** Cache the epoch key we just minted ourselves, without a round trip. */
export async function ingestOwnEpoch(
  conversationId: string,
  epoch: number,
  secret: Uint8Array,
): Promise<void> {
  epochRootCache.set(epochKey(conversationId, epoch), (await epochRootFromSecret(secret)) as CryptoKey);
}

export const hasEpoch = (conversationId: string, epoch: number): boolean =>
  epochRootCache.has(epochKey(conversationId, epoch));

/**
 * The cached root for an epoch, or undefined if it has not been ingested.
 *
 * Callers that can fetch (see whiteboard/epochBridge) use this to decide
 * whether a round trip is needed; callers that cannot simply fail, which is
 * the correct behaviour — there is no fallback key.
 */
export const epochRoot = (conversationId: string, epoch: number): CryptoKey | undefined =>
  epochRootCache.get(epochKey(conversationId, epoch));

async function rootForEpoch(conversationId: string, epoch: number): Promise<CryptoKey> {
  const cached = epochRootCache.get(epochKey(conversationId, epoch));
  if (cached) return cached;
  // Fetching an older epoch is normal after a reload, when only the current
  // key is in memory but history spans several.
  throw new Error(`Missing key for epoch ${epoch}`);
}

export interface SealArgs {
  priv: IdentityPrivate;
  myUserId: string;
  myKeyVersion: number;
  conversationId: string;
  clientMsgId: string;
  sentAt: number;
  contentType: ContentType;
  plaintext: Uint8Array;
}

export async function sealForDm(args: SealArgs & { peerId: string }): Promise<CipherEnvelope> {
  const ctx: DmContext = {
    clientMsgId: args.clientMsgId,
    conversationId: args.conversationId,
    senderId: args.myUserId,
    recipientId: args.peerId,
    senderKeyVersion: args.myKeyVersion,
    sentAt: args.sentAt,
    contentType: args.contentType,
  };
  const root = await rootForDm(args.priv, args.peerId);
  return sealDm(root as never, args.priv.signPriv, ctx, args.plaintext);
}

export async function sealForGroup(args: SealArgs & { epoch: number }): Promise<CipherEnvelope> {
  const ctx: GroupContext = {
    clientMsgId: args.clientMsgId,
    conversationId: args.conversationId,
    senderId: args.myUserId,
    epoch: args.epoch,
    senderKeyVersion: args.myKeyVersion,
    sentAt: args.sentAt,
    contentType: args.contentType,
  };
  const root = await rootForEpoch(args.conversationId, args.epoch);
  return sealGroup(root as never, args.priv.signPriv, ctx, args.plaintext);
}

export interface OpenArgs {
  priv: IdentityPrivate;
  myUserId: string;
  message: MessageDTO;
  /** DM only: the other participant. */
  peerId?: string;
  contentType?: ContentType;
}

/**
 * Decrypt one message.
 *
 * The AAD is rebuilt from the server-visible columns on the message. If the
 * server altered any of them — sender, conversation, timestamp — the
 * reconstruction no longer matches and this throws, which is precisely the
 * point of binding them.
 */
export async function openMessage(args: OpenArgs): Promise<Uint8Array> {
  const { message } = args;
  if (!message.envelope) throw new Error('Message has no ciphertext');
  const contentType: ContentType =
    args.contentType ?? (message.kind === 'file' ? 'application/rtc-file-v1' : 'text/plain');

  const sender = await peerKeys(String(message.senderId));

  if (message.envelope.epoch !== undefined) {
    const root = await rootForEpoch(String(message.conversationId), message.envelope.epoch);
    return openGroup(root as never, sender.signPub as never, {
      clientMsgId: String(message.clientMsgId),
      conversationId: String(message.conversationId),
      senderId: String(message.senderId),
      epoch: message.envelope.epoch,
      senderKeyVersion: message.envelope.senderKeyVersion,
      sentAt: message.sentAt,
      contentType,
    }, message.envelope);
  }

  // In a DM the AAD's recipient is "the other party", which differs depending
  // on which side is reading.
  const peerId = args.peerId ?? String(message.senderId);
  const recipientId = String(message.senderId) === args.myUserId ? peerId : args.myUserId;
  const root = await rootForDm(args.priv, peerId);
  return openDm(root as never, sender.signPub as never, {
    clientMsgId: String(message.clientMsgId),
    conversationId: String(message.conversationId),
    senderId: String(message.senderId),
    recipientId,
    senderKeyVersion: message.envelope.senderKeyVersion,
    sentAt: message.sentAt,
    contentType,
  }, message.envelope);
}

export function clearCryptoCaches(): void {
  peerCache.clear();
  dmRootCache.clear();
  epochRootCache.clear();
}
