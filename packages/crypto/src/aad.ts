import { concat, utf8 } from './bytes.js';

/**
 * Canonical, length-prefixed encoding for associated data.
 *
 * NEVER use JSON.stringify for AAD. Key order, number formatting and unicode
 * escaping are not stable across engines or versions, so a value that
 * encrypts on one browser could fail to authenticate on another — an
 * intermittent, unreproducible decryption failure. Length-prefixing also
 * makes the encoding unambiguous: ("ab","c") and ("a","bc") produce different
 * AAD, which plain concatenation would not.
 */
export function packAad(...parts: readonly (string | Uint8Array)[]): Uint8Array {
  const bufs = parts.map((p) => (typeof p === 'string' ? utf8(p) : p));
  const out: Uint8Array[] = [];
  for (const b of bufs) {
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, b.length, false);
    out.push(len, b);
  }
  return concat(...out);
}

/** Unpack a length-prefixed blob produced by `packAad`. */
export function unpackParts(packed: Uint8Array): Uint8Array[] {
  const view = new DataView(packed.buffer, packed.byteOffset, packed.byteLength);
  const parts: Uint8Array[] = [];
  let o = 0;
  while (o < packed.length) {
    if (o + 4 > packed.length) throw new Error('truncated length prefix');
    const len = view.getUint32(o, false);
    o += 4;
    if (o + len > packed.length) throw new Error('truncated part');
    parts.push(packed.subarray(o, o + len));
    o += len;
  }
  return parts;
}

/**
 * AAD for a 1:1 message.
 *
 * Note `clientMsgId`, not the server's `_id`: the sender seals the message
 * before the server has assigned an id, so the only message identifier that
 * exists at encryption time is the client's. It is unique per conversation by
 * database index, which is exactly the property the AAD needs.
 *
 * `sentAt` is the CLIENT's clock and is authenticated. The server's
 * `createdAt` and `seq` are assigned after signing, so they cannot appear
 * here — which is precisely why the UI must display `sentAt` and use `seq`
 * only for ordering.
 */
export const dmMessageAad = (m: {
  clientMsgId: string;
  conversationId: string;
  senderId: string;
  recipientId: string;
  senderKeyVersion: number;
  sentAt: number;
  contentType: string;
}): Uint8Array =>
  packAad(
    'rtc/v1/dm-msg',
    m.clientMsgId,
    m.conversationId,
    m.senderId,
    m.recipientId,
    String(m.senderKeyVersion),
    String(m.sentAt),
    m.contentType,
  );

/** AAD for a group message. Binds the epoch so a message cannot be replayed into another. */
export const groupMessageAad = (m: {
  clientMsgId: string;
  conversationId: string;
  senderId: string;
  epoch: number;
  senderKeyVersion: number;
  sentAt: number;
  contentType: string;
}): Uint8Array =>
  packAad(
    'rtc/v1/group-msg',
    m.clientMsgId,
    m.conversationId,
    m.senderId,
    String(m.epoch),
    String(m.senderKeyVersion),
    String(m.sentAt),
    m.contentType,
  );

/**
 * AAD for a whiteboard op, bound to its stroke and chunk index so the server
 * cannot reorder chunks or move a stroke between boards.
 */
export const whiteboardAad = (m: {
  conversationId: string;
  strokeId: string;
  chunk: number;
  authorId: string;
  epoch: number;
  senderKeyVersion: number;
}): Uint8Array =>
  packAad(
    'rtc/v1/wb-op',
    m.conversationId,
    m.strokeId,
    String(m.chunk),
    m.authorId,
    String(m.epoch),
    String(m.senderKeyVersion),
  );

/**
 * AAD for the wrapped identity blob.
 *
 * Binding userId and keyVersion is what stops a malicious server swapping
 * Alice's wrapped key for Bob's, or rolling her back to a retired version.
 * AES-KW cannot express this, which is why this design uses AES-GCM to wrap.
 */
export const identityWrapAad = (m: {
  userId: string;
  keyVersion: number;
  kdfParams: string;
  purpose: 'password' | 'recovery';
}): Uint8Array =>
  packAad('rtc/v1/identity-wrap', m.userId, String(m.keyVersion), m.kdfParams, m.purpose);

/** AAD for one member's copy of a group epoch key. */
export const epochWrapAad = (m: {
  conversationId: string;
  epoch: number;
  senderId: string;
  recipientId: string;
  recipientKeyVersion: number;
}): Uint8Array =>
  packAad(
    'rtc/v1/epoch-wrap',
    m.conversationId,
    String(m.epoch),
    m.senderId,
    m.recipientId,
    String(m.recipientKeyVersion),
  );

/**
 * AAD for one file chunk.
 *
 * `chunk`, `total` and `plainSize` are the anti-truncation binding: a
 * decryptor that learns the expected count from chunk 0 will reject a short
 * or reordered stream. Chunked GCM WITHOUT positional AAD is the classic
 * footgun — each chunk verifies fine on its own while the assembled file is
 * attacker-controlled.
 */
export const fileChunkAad = (m: {
  fileId: string;
  chunk: number;
  total: number;
  plainSize: number;
}): Uint8Array =>
  packAad(
    'rtc/v1/file-chunk',
    m.fileId,
    String(m.chunk),
    String(m.total),
    String(m.plainSize),
  );
