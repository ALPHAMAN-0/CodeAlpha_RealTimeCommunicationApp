import { fromUtf8, utf8, whiteboardAad, seal, open, signBytes, verifyBytes, deriveMessageKey, b64uDecode, b64uEncode, concat, randomBytes, SALT_BYTES } from '@rtc/crypto';
import type { CipherEnvelope, StrokePayload, WhiteboardOpRecord } from '@rtc/shared';
import { peerKeys } from '../crypto/e2ee.js';
import { useConversations } from '../stores/conversations.store.js';
import { useSession } from '../stores/session.store.js';
import { dmPeerId } from '../realtime/chat.js';
import { dmRoot } from '@rtc/crypto';

/**
 * Whiteboard strokes reuse the message envelope, keyed the same way as the
 * conversation they belong to.
 *
 * Note what stays visible to the server: the op KIND, the stroke id and the
 * chunk index. It needs those to authorize an undo, to prune on clear, and to
 * serve a late joiner — none of which is possible on opaque bytes. Geometry,
 * colour and width are encrypted, so the server learns that someone drew,
 * never what.
 */
const rootFor = async (conversationId: string): Promise<{ root: CryptoKey; epoch: number }> => {
  const { user, priv } = useSession.getState();
  if (!user || !priv) throw new Error('not signed in');
  const view = useConversations.getState().byId[conversationId];
  if (!view) throw new Error('unknown conversation');

  if (view.conversation.type === 'group') {
    const { epochRootFor } = await import('./epochBridge.js');
    return { root: await epochRootFor(conversationId, view.conversation.epoch), epoch: view.conversation.epoch };
  }
  const peerId = dmPeerId(view.conversation, user.id);
  if (!peerId) throw new Error('conversation has no peer');
  const peer = await peerKeys(peerId);
  return { root: (await dmRoot(priv.agreePriv, peer.agreePub as never)) as CryptoKey, epoch: 0 };
};

export async function sealWhiteboardOp(
  conversationId: string,
  strokeId: string,
  chunk: number,
  payload: StrokePayload,
): Promise<CipherEnvelope> {
  const { user, priv } = useSession.getState();
  if (!user || !priv) throw new Error('not signed in');
  const { root, epoch } = await rootFor(conversationId);

  const aad = whiteboardAad({
    conversationId, strokeId, chunk, authorId: user.id, epoch, senderKeyVersion: user.keyVersion,
  });
  const salt = randomBytes(SALT_BYTES);
  const key = await deriveMessageKey(root as never, salt, `rtc/v1/wb-op|${conversationId}|${strokeId}|${chunk}`);
  const { iv, ct } = await seal(key, aad, utf8(JSON.stringify(payload)));
  const sig = await signBytes(priv.signPriv, concat(aad, iv, ct));
  return {
    alg: 'RTC/v1',
    salt: b64uEncode(salt),
    iv: b64uEncode(iv),
    ct: b64uEncode(ct),
    sig: b64uEncode(sig),
    senderKeyVersion: user.keyVersion,
    ...(epoch > 0 ? { epoch } : {}),
  };
}

export async function openWhiteboardOp(
  conversationId: string,
  record: WhiteboardOpRecord,
): Promise<StrokePayload> {
  if (!record.envelope || !record.strokeId) throw new Error('op has no ciphertext');
  const { root } = await rootFor(conversationId);
  const author = await peerKeys(String(record.authorId));

  const aad = whiteboardAad({
    conversationId,
    strokeId: String(record.strokeId),
    chunk: record.chunk ?? 0,
    authorId: String(record.authorId),
    epoch: record.envelope.epoch ?? 0,
    senderKeyVersion: record.envelope.senderKeyVersion,
  });
  const iv = b64uDecode(record.envelope.iv);
  const ct = b64uDecode(record.envelope.ct);
  // Verify authorship before decrypting: in a group every member holds the
  // room key, so the AEAD tag alone cannot say who drew this.
  if (!(await verifyBytes(author.signPub as never, b64uDecode(record.envelope.sig), concat(aad, iv, ct)))) {
    throw new Error('bad whiteboard signature');
  }
  const key = await deriveMessageKey(
    root as never, b64uDecode(record.envelope.salt),
    `rtc/v1/wb-op|${conversationId}|${String(record.strokeId)}|${record.chunk ?? 0}`,
  );
  return JSON.parse(fromUtf8(await open(key, aad, iv, ct))) as StrokePayload;
}
