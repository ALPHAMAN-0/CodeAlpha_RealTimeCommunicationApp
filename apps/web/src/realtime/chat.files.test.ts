import { resolveObjectURL } from 'node:buffer';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConversationDTO, FilePayload } from '@rtc/shared';

/**
 * The attachment path, with the network and the message envelope stubbed out.
 *
 * What is under test is the contract between the sender and the receiver of a
 * file message: everything the receiver needs has to travel inside the sealed
 * payload, because the server only ever holds ciphertext. The file encryption
 * itself is real.
 */
const wire = vi.hoisted(() => ({
  uploaded: undefined as Uint8Array | undefined,
  sealedPlaintext: undefined as Uint8Array | undefined,
  enqueued: [] as Array<{ kind: string; attachmentId?: string }>,
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
  // Stands in for the message envelope: capture what would have been sealed.
  sealForDm: vi.fn(async (args: { plaintext: Uint8Array }) => {
    wire.sealedPlaintext = args.plaintext;
    return { alg: 'RTC/v1', salt: '', iv: '', ct: '', sig: '', senderKeyVersion: 1 };
  }),
  openMessage: vi.fn(),
  sealForGroup: vi.fn(),
  peerKeys: vi.fn(),
  hasEpoch: vi.fn(),
  ingestEpoch: vi.fn(),
  ingestOwnEpoch: vi.fn(),
  KeyTrustError: class KeyTrustError extends Error {},
}));

const { downloadAttachment, sendFile } = await import('./chat.js');
const { useConversations } = await import('../stores/conversations.store.js');
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

beforeEach(() => {
  wire.uploaded = undefined;
  wire.sealedPlaintext = undefined;
  wire.enqueued = [];
  useSession.setState({
    user: { id: ME, displayName: 'Me', avatarColor: '#000000', keyVersion: 1 },
    priv: {} as never,
    status: 'signed-in',
  });
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
