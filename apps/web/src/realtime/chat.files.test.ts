import { resolveObjectURL } from 'node:buffer';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConversationDTO, FilePayload, MessageDTO } from '@rtc/shared';

/**
 * The attachment path, with the network and the message envelope stubbed out.
 *
 * What is under test is the contract between the sender and the receiver of a
 * file message. Everything the receiver needs has to travel inside the sealed
 * payload — the server only ever holds ciphertext — and whatever arrives in
 * that payload was written by another member, so it is untrusted input. The
 * file encryption itself is real.
 */
const wire = vi.hoisted(() => ({
  uploaded: undefined as Uint8Array | undefined,
  sealedPlaintext: undefined as Uint8Array | undefined,
  enqueued: [] as Array<{ kind: string; attachmentId?: string }>,
  /** What the stubbed envelope "decrypts" to on the receiving side. */
  incomingPlaintext: undefined as string | undefined,
}));

const ATTACHMENT_ID = 'c'.repeat(24);

vi.mock('../lib/api.js', () => ({
  request: vi.fn(),
  uploadAttachment: vi.fn(async (_conversationId: string, cipher: Uint8Array) => {
    wire.uploaded = cipher;
    return { attachmentId: ATTACHMENT_ID, cipherSize: cipher.length };
  }),
  fetchAttachment: vi.fn(async () => wire.uploaded!),
}));

vi.mock('../lib/socket.js', () => ({
  emit: vi.fn(async () => undefined),
  SocketError: class SocketError extends Error {},
}));

vi.mock('./Outbox.js', () => ({
  outbox: () => ({
    enqueue: (entry: { kind: string; attachmentId?: string }) => wire.enqueued.push(entry),
  }),
}));

vi.mock('../crypto/e2ee.js', () => ({
  // Stand-ins for the message envelope: capture what would have been sealed,
  // and hand back whatever the test says the envelope contained.
  sealForDm: vi.fn(async (args: { plaintext: Uint8Array }) => {
    wire.sealedPlaintext = args.plaintext;
    return { alg: 'RTC/v1', salt: '', iv: '', ct: '', sig: '', senderKeyVersion: 1 };
  }),
  openMessage: vi.fn(async () => new TextEncoder().encode(wire.incomingPlaintext)),
  sealForGroup: vi.fn(),
  peerKeys: vi.fn(),
  hasEpoch: vi.fn(),
  ingestEpoch: vi.fn(),
  ingestOwnEpoch: vi.fn(),
  KeyTrustError: class KeyTrustError extends Error {},
}));

const { decryptAll, downloadAttachment, sendFile } = await import('./chat.js');
const { useConversations } = await import('../stores/conversations.store.js');
const { useMessages } = await import('../stores/messages.store.js');
const { useSession } = await import('../stores/session.store.js');

const ME = 'a'.repeat(24);
const PEER = 'b'.repeat(24);
const CONVERSATION = 'd'.repeat(24);

/** Two chunks' worth, so the per-chunk binding is exercised, not just chunk 0. */
const original = Uint8Array.from({ length: 300_000 }, (_, i) => (i * 31) & 0xff);

/** Send a file and return the payload exactly as the receiver would parse it. */
async function sendAndReadPayload(): Promise<FilePayload> {
  await sendFile(CONVERSATION, new File([original], 'q3-report.pdf', { type: 'application/pdf' }));
  return JSON.parse(new TextDecoder().decode(wire.sealedPlaintext)) as FilePayload;
}

/** Deliver a file message whose envelope opens to `plaintext`, then render it. */
async function receive(plaintext: string) {
  wire.incomingPlaintext = plaintext;
  const message = {
    id: 'e'.repeat(24), conversationId: CONVERSATION, seq: 1, senderId: PEER,
    clientMsgId: crypto.randomUUID(), kind: 'file', attachmentId: ATTACHMENT_ID,
    envelope: { alg: 'RTC/v1', salt: '', iv: '', ct: '', sig: '', senderKeyVersion: 1 },
    sentAt: Date.now(), createdAt: Date.now(),
  } as unknown as MessageDTO;
  useMessages.getState().upsert(CONVERSATION, [message]);
  await decryptAll(CONVERSATION, [message]);
  return useMessages.getState().list(CONVERSATION)[0]!;
}

beforeEach(() => {
  wire.uploaded = undefined;
  wire.sealedPlaintext = undefined;
  wire.incomingPlaintext = undefined;
  wire.enqueued = [];
  useSession.setState({
    user: { id: ME, displayName: 'Me', avatarColor: '#000000', keyVersion: 1 },
    priv: {} as never,
    status: 'signed-in',
  });
  useMessages.getState().reset();
  useConversations.getState().reset();
  useConversations.getState().upsert({
    conversation: {
      id: CONVERSATION, type: 'dm', memberIds: [ME, PEER], createdBy: ME, createdAt: 0,
      messageSeq: 0, whiteboardSeq: 0, epoch: 0, rekeyPending: false,
    } as unknown as ConversationDTO,
  });
});

describe('sending and opening an attachment', () => {
  it('lets the receiver decrypt exactly what the sender uploaded', async () => {
    const payload = await sendAndReadPayload();

    // The server saw ciphertext only, and a file message was queued for it.
    expect(wire.uploaded).toBeDefined();
    expect(Buffer.from(wire.uploaded!).includes(Buffer.from(original.subarray(0, 64)))).toBe(false);
    expect(wire.enqueued).toEqual([expect.objectContaining({ kind: 'file', attachmentId: ATTACHMENT_ID })]);

    const { url, bytes, revoke } = await downloadAttachment(payload);
    expect(bytes).toEqual(original);
    const blob = resolveObjectURL(url);
    expect(blob?.type).toBe('application/pdf');
    expect(new Uint8Array(await blob!.arrayBuffer())).toEqual(original);
    revoke();
  });

  it('carries the id the chunks were sealed under, which is not the attachment id', async () => {
    const payload = await sendAndReadPayload();
    // Minted before the upload, so the server-assigned attachment id cannot be
    // what the chunk AAD was built with. Without this id in the payload the
    // receiver has nothing to rebuild that AAD from and every chunk fails.
    expect(payload.fileId).toMatch(/^[0-9a-f-]{36}$/);
    expect(payload.fileId).not.toBe(String(payload.attachmentId));
  });

  it('refuses to decrypt under any other file id', async () => {
    const payload = await sendAndReadPayload();
    await expect(downloadAttachment({ ...payload, fileId: crypto.randomUUID() })).rejects.toThrow();
  });
});

describe('receiving a file message', () => {
  it('renders a well-formed payload', async () => {
    const payload = await sendAndReadPayload();
    const rendered = await receive(JSON.stringify(payload));
    expect(rendered.filePayload).toEqual(payload);
    expect(rendered.plaintext).toBe('');
  });

  it('shows a forged payload as unreadable instead of handing it to the renderer', async () => {
    const payload = await sendAndReadPayload();
    // Correctly sealed and signed by a member, but shaped to break the reader:
    // an object where the file name should be throws inside React's render.
    for (const forged of [
      { ...payload, filename: { length: 3 } },
      { ...payload, caption: ['x', {}] },
      { ...payload, plainSize: 2 ** 40 },
      { ...payload, fileKey: 'short' },
    ]) {
      useMessages.getState().reset();
      const rendered = await receive(JSON.stringify(forged));
      expect(rendered.filePayload).toBeUndefined();
      expect(rendered.plaintext).toBeNull();
    }
    useMessages.getState().reset();
    const garbage = await receive('<html>not json</html>');
    expect(garbage.filePayload).toBeUndefined();
    expect(garbage.plaintext).toBeNull();
  });
});
