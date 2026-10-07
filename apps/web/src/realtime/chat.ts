import {
  b64uDecode, b64uEncode, createEpoch, decryptFileBytes, encryptFileBytes,
  fromUtf8, importPublicKeys, safetyNumber, utf8,
} from '@rtc/crypto';
import type {
  ConversationDTO, EpochRecord, FilePayload, MessageDTO, ParticipantDTO,
  PresenceDTO, CallPeerDTO,
} from '@rtc/shared';
import { fetchAttachment, request, uploadAttachment } from '../lib/api.js';
import { emit } from '../lib/socket.js';
import {
  KeyTrustError, hasEpoch, ingestEpoch, ingestOwnEpoch, openMessage,
  peerKeys, sealForDm, sealForGroup,
} from '../crypto/e2ee.js';
import { useConversations } from '../stores/conversations.store.js';
import { useMessages } from '../stores/messages.store.js';
import { useSession } from '../stores/session.store.js';
import { outbox } from './Outbox.js';

const uuid = (): string => crypto.randomUUID();

const me = () => {
  const { user, priv } = useSession.getState();
  if (!user || !priv) throw new Error('not signed in');
  return { user, priv };
};

/** The other participant in a DM, from the caller's point of view. */
export function dmPeerId(conversation: ConversationDTO, myUserId: string): string | undefined {
  if (conversation.type !== 'dm') return undefined;
  return conversation.memberIds.map(String).find((id) => id !== myUserId);
}

export async function loadConversations(): Promise<void> {
  const { conversations } = await request<{
    conversations: Array<{
      conversation: ConversationDTO;
      members: Array<{ userId: string; displayName: string; avatarColor: string; keyVersion: number }>;
    }>;
  }>('/api/conversations');
  useConversations.getState().setList(conversations);
}

export interface JoinResult {
  conversation: ConversationDTO;
  participants: ParticipantDTO[];
}

export async function joinConversation(conversationId: string): Promise<JoinResult> {
  const { user, priv } = me();
  const state = await emit<{
    conversation: ConversationDTO;
    participants: ParticipantDTO[];
    presence: PresenceDTO[];
    latestSeq: number;
    yourLastReadSeq: number;
    unread: number;
    whiteboardSeq: number;
    call: { active: boolean; peers: CallPeerDTO[] };
    epoch?: EpochRecord;
  }>('room:join', { conversationId });

  useConversations.getState().upsert({
    conversation: state.conversation,
    participants: state.participants,
    unread: state.unread,
    latestSeq: state.latestSeq,
    myReadSeq: state.yourLastReadSeq,
    rekeyPending: state.conversation.rekeyPending,
  });
  useConversations.getState().setPresence(state.presence);

  // Take the group key before any decryption is attempted.
  if (state.epoch) {
    await ingestEpoch(priv, user.id, conversationId, state.epoch).catch(() => undefined);
  }

  await loadHistory(conversationId);
  return { conversation: state.conversation, participants: state.participants };
}

export async function loadHistory(conversationId: string, beforeSeq?: number): Promise<void> {
  const page = await emit<{ messages: MessageDTO[]; hasMore: boolean; oldestSeq: number | null }>(
    'message:history',
    { conversationId, ...(beforeSeq !== undefined ? { beforeSeq } : {}) },
  );
  useMessages.getState().upsert(conversationId, page.messages);
  useMessages.getState().setHistoryMeta(conversationId, page.oldestSeq, page.hasMore);
  await decryptAll(conversationId, page.messages);
}

/**
 * Decrypt a batch.
 *
 * Failures are recorded as `null` plaintext rather than thrown: one
 * undecryptable message — a missing epoch key, a rotated identity — must not
 * blank the entire conversation.
 */
export async function decryptAll(conversationId: string, messages: MessageDTO[]): Promise<void> {
  const { user, priv } = me();
  const view = useConversations.getState().byId[conversationId];
  const peerId = view ? dmPeerId(view.conversation, user.id) : undefined;

  await Promise.all(
    messages.map(async (message) => {
      if (!message.envelope || message.deletedAt) return;
      try {
        const plain = await openMessage({
          priv, myUserId: user.id, message,
          ...(peerId ? { peerId } : {}),
        });
        if (message.kind === 'file') {
          const payload = JSON.parse(fromUtf8(plain)) as FilePayload;
          useMessages.getState().setPlaintext(
            conversationId, String(message.id), payload.caption ?? '', payload,
          );
        } else {
          useMessages.getState().setPlaintext(conversationId, String(message.id), fromUtf8(plain));
        }
      } catch (err) {
        if (err instanceof KeyTrustError) {
          useConversations.getState().markUntrusted(conversationId, err.peerId);
        }
        useMessages.getState().setPlaintext(conversationId, String(message.id), null);
      }
    }),
  );
}

async function sealFor(
  conversationId: string,
  clientMsgId: string,
  sentAt: number,
  plaintext: Uint8Array,
  contentType: 'text/plain' | 'application/rtc-file-v1',
) {
  const { user, priv } = me();
  const view = useConversations.getState().byId[conversationId];
  if (!view) throw new Error('unknown conversation');

  const common = {
    priv, myUserId: user.id, myKeyVersion: user.keyVersion,
    conversationId, clientMsgId, sentAt, contentType, plaintext,
  } as const;

  if (view.conversation.type === 'group') {
    // Fail closed: without the current epoch key there is no correct key to
    // use, and falling back to an older one would be readable by someone who
    // was just removed.
    if (view.rekeyPending) throw new Error('Room keys are being rotated. Try again in a moment.');
    const epoch = view.conversation.epoch;
    if (!hasEpoch(conversationId, epoch)) throw new Error('Waiting for the room key.');
    return sealForGroup({ ...common, epoch });
  }

  const peerId = dmPeerId(view.conversation, user.id);
  if (!peerId) throw new Error('conversation has no peer');
  return sealForDm({ ...common, peerId });
}

/**
 * Install the confirmation handler.
 *
 * Called once per signed-in session. It inserts the sender's own message into
 * the timeline from the ack, using the plaintext already held locally — there
 * is nothing to decrypt for a message we just composed.
 */
export function installSendConfirmation(userId: string): () => void {
  return outbox(userId).onSent((entry, ack) => {
    const dto: MessageDTO = {
      id: ack.messageId as never,
      conversationId: entry.conversationId as never,
      seq: ack.seq,
      senderId: userId as never,
      clientMsgId: ack.clientMsgId as never,
      kind: entry.kind,
      envelope: entry.envelope,
      ...(entry.attachmentId ? { attachmentId: entry.attachmentId as never } : {}),
      sentAt: entry.sentAt,
      createdAt: ack.createdAt,
    };
    useMessages.getState().upsert(entry.conversationId, [dto]);
    useConversations.getState().setLatestSeq(entry.conversationId, ack.seq);

    if (entry.kind === 'file') {
      // The payload was sealed from a local object; re-open it so the file
      // bubble renders without a round trip.
      void openMessage({ priv: me().priv, myUserId: userId, message: dto })
        .then((plain) => {
          const payload = JSON.parse(fromUtf8(plain)) as FilePayload;
          useMessages.getState().setPlaintext(
            entry.conversationId, ack.messageId, payload.caption ?? '', payload,
          );
        })
        .catch(() => useMessages.getState().setPlaintext(entry.conversationId, ack.messageId, null));
    } else {
      useMessages.getState().setPlaintext(entry.conversationId, ack.messageId, entry.preview);
    }
  });
}

export async function sendText(conversationId: string, text: string): Promise<void> {
  const trimmed = text.trim();
  if (!trimmed) return;
  const { user } = me();
  // Minted ONCE here. Never regenerated on retry — that is what makes the
  // server's uniqueness index collapse replays instead of duplicating them.
  const clientMsgId = uuid();
  const sentAt = Date.now();
  const envelope = await sealFor(conversationId, clientMsgId, sentAt, utf8(trimmed), 'text/plain');

  outbox(user.id).enqueue({
    clientMsgId, conversationId, kind: 'text', envelope, sentAt, preview: trimmed,
  });
}

export async function sendFile(
  conversationId: string,
  file: File,
  onProgress?: (fraction: number) => void,
): Promise<void> {
  const { user } = me();
  const clientMsgId = uuid();
  const fileId = uuid();
  const sentAt = Date.now();

  const bytes = new Uint8Array(await file.arrayBuffer());
  const enc = await encryptFileBytes(bytes, fileId);

  // Upload first, then send. Decoupling means a failed send retries without
  // re-uploading the bytes, and the outbox stays small enough to persist.
  const { attachmentId } = await uploadAttachment(conversationId, enc.cipher, (fraction) => {
    onProgress?.(fraction);
    void emit('file:upload-progress', { conversationId, clientMsgId, progress: fraction })
      .catch(() => undefined);
  });

  const payload: FilePayload = {
    attachmentId: attachmentId as never,
    // The id the chunks were just sealed under. It has to travel with the
    // key: the receiver rebuilds every chunk's AAD from it, and the attachment
    // id cannot stand in, because the server assigned that after encryption.
    fileId,
    // Filename and MIME travel INSIDE the ciphertext: "Q3_layoffs.xlsx" leaks
    // plenty on its own, so the server never sees either.
    filename: file.name,
    mime: file.type || 'application/octet-stream',
    plainSize: enc.meta.plainSize,
    chunkCount: enc.meta.chunkCount,
    ivPrefix: enc.meta.ivPrefix,
    sha256: enc.sha256,
    fileKey: b64uEncode(enc.keyBytes),
  };
  const envelope = await sealFor(
    conversationId, clientMsgId, sentAt, utf8(JSON.stringify(payload)), 'application/rtc-file-v1',
  );

  outbox(user.id).enqueue({
    clientMsgId, conversationId, kind: 'file', envelope, sentAt,
    attachmentId, preview: file.name,
  });
}

/**
 * Download and decrypt an attachment into a blob: URL.
 *
 * Never a direct link: the bearer token lives only in memory so a plain
 * navigation would be unauthenticated, and routing bytes through a blob keeps
 * attacker-supplied content off the app's own origin entirely.
 */
export async function downloadAttachment(
  payload: FilePayload,
): Promise<{ url: string; bytes: Uint8Array; revoke: () => void }> {
  const cipher = await fetchAttachment(String(payload.attachmentId));
  const plain = await decryptFileBytes(cipher, b64uDecode(payload.fileKey), {
    fileId: extractFileId(payload),
    chunkCount: payload.chunkCount,
    plainSize: payload.plainSize,
    ivPrefix: payload.ivPrefix,
  });
  const blob = new Blob([plain as unknown as BlobPart], { type: payload.mime });
  const url = URL.createObjectURL(blob);
  // The decrypted bytes are returned alongside the URL so a caller that wants
  // to inspect them does not have to read the blob: URL back.
  return { url, bytes: plain, revoke: () => URL.revokeObjectURL(url) };
}

/**
 * The fileId used in the chunk AAD.
 *
 * It is generated client-side at encryption time and stored in the payload;
 * older payloads that predate the explicit field fall back to the attachment
 * id, which is what they used.
 */
const extractFileId = (payload: FilePayload): string =>
  payload.fileId ?? String(payload.attachmentId);

export async function markRead(conversationId: string, seq: number): Promise<void> {
  if (seq <= 0) return;
  const result = await emit<{ unread: number }>('receipt:read', { conversationId, seq })
    .catch(() => undefined);
  if (result) useConversations.getState().setUnread(conversationId, result.unread);
}

/**
 * Publish the next group epoch when nominated as leader.
 *
 * Every current member gets exactly one wrap; the server rejects an epoch that
 * omits anyone, which prevents a member from silently locking someone out.
 */
export async function publishNextEpoch(conversationId: string, nextEpoch: number, reason: EpochRecord['reason']): Promise<void> {
  const { user, priv } = me();
  const { members } = await request<{
    members: Array<{ userId: string; keyVersion: number; current: { spkiEcdh: string; spkiEcdsa: string } }>;
  }>(`/api/conversations/${conversationId}/keys`);

  const resolved = await Promise.all(
    members.map(async (m) => ({
      userId: m.userId,
      agreePub: (await importPublicKeys(m.current)).agreePub,
      keyVersion: m.keyVersion,
    })),
  );

  const { record, secret } = await createEpoch({
    conversationId, epoch: nextEpoch, myUserId: user.id,
    mySignPriv: priv.signPriv, members: resolved, reason, now: Date.now(),
  });

  // Cache our own key before publishing, so a message can be sent the instant
  // the server confirms.
  await ingestOwnEpoch(conversationId, nextEpoch, secret);
  await emit('epoch:publish', { conversationId, epoch: record });
  useConversations.getState().setRekeyPending(conversationId, false);
}

export async function createDm(peerUserId: string): Promise<ConversationDTO> {
  const { user } = me();
  const { conversation } = await request<{ conversation: ConversationDTO }>('/api/conversations', {
    method: 'POST',
    body: { type: 'dm', memberIds: [user.id, peerUserId] },
  });
  useConversations.getState().upsert({ conversation });
  return conversation;
}

export async function createGroup(memberIds: string[]): Promise<ConversationDTO> {
  const { user } = me();
  const { conversation } = await request<{ conversation: ConversationDTO }>('/api/conversations', {
    method: 'POST',
    body: { type: 'group', memberIds: [user.id, ...memberIds] },
  });
  useConversations.getState().upsert({ conversation });
  // A new group has no key yet; the creator mints epoch 1 immediately.
  await publishNextEpoch(String(conversation.id), 1, 'created');
  return conversation;
}

export const safetyNumberFor = async (peerId: string): Promise<string> => {
  const { user } = me();
  const [mine, theirs] = await Promise.all([peerKeys(user.id), peerKeys(peerId)]);
  return safetyNumber(mine.raw, theirs.raw);
};
