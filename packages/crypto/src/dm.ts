import type { CipherEnvelope, ContentType } from '@rtc/shared';
import { dmMessageAad } from './aad.js';
import { SALT_BYTES, deriveMessageKey, ecdhRoot, open, seal, signBytes, verifyBytes } from './aead.js';
import { DecryptError, b64uDecode, b64uEncode, concat, randomBytes } from './bytes.js';

/**
 * Long-term root for a 1:1 conversation: static-static ECDH, cached per peer.
 *
 * Both sides compute the same root from their own private key and the peer's
 * public key, so no key agreement message is needed.
 */
export const dmRoot = (myAgreePriv: CryptoKey, theirAgreePub: CryptoKey): Promise<CryptoKey> =>
  ecdhRoot(myAgreePriv, theirAgreePub);

export interface DmContext {
  clientMsgId: string;
  conversationId: string;
  senderId: string;
  recipientId: string;
  senderKeyVersion: number;
  sentAt: number;
  contentType: ContentType;
}

const infoFor = (ctx: DmContext) =>
  `rtc/v1/dm-msg|${ctx.conversationId}|${ctx.clientMsgId}`;

/**
 * Seal a 1:1 message.
 *
 * A FRESH key is derived per message from a fresh random salt. That is what
 * makes (key, IV) reuse structurally impossible rather than merely unlikely:
 * with a long-lived key and random IVs you are relying on the 96-bit birthday
 * bound holding and on no retry path ever reusing a nonce. Here an IV
 * collision across two messages is harmless, because the keys differ.
 */
export async function sealDm(
  root: CryptoKey,
  signPriv: CryptoKey,
  ctx: DmContext,
  plaintext: Uint8Array,
): Promise<CipherEnvelope> {
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveMessageKey(root, salt, infoFor(ctx));
  const aad = dmMessageAad(ctx);
  const { iv, ct } = await seal(key, aad, plaintext);
  const sig = await signBytes(signPriv, concat(aad, iv, ct));
  return {
    alg: 'RTC/v1',
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    ct: b64uEncode(ct),
    sig: b64uEncode(sig),
    senderKeyVersion: ctx.senderKeyVersion,
  };
}

/**
 * Open a 1:1 message, verifying the sender's signature FIRST.
 *
 * Order matters: verify before decrypt so a forged message is rejected on
 * cheap public-key math rather than after the AEAD has already run.
 */
export async function openDm(
  root: CryptoKey,
  senderSignPub: CryptoKey,
  ctx: DmContext,
  env: CipherEnvelope,
): Promise<Uint8Array> {
  const iv = b64uDecode(env.iv);
  const ct = b64uDecode(env.ct);
  const aad = dmMessageAad(ctx);
  if (!(await verifyBytes(senderSignPub, b64uDecode(env.sig), concat(aad, iv, ct)))) {
    throw new DecryptError('BAD_SIGNATURE');
  }
  const key = await deriveMessageKey(root, b64uDecode(env.salt), infoFor(ctx));
  return open(key, aad, iv, ct);
}
