import { socket, emit, installTokenRenewal } from '../lib/socket.js';
import { useConversations } from '../stores/conversations.store.js';
import { useMessages } from '../stores/messages.store.js';
import { useSession } from '../stores/session.store.js';
import { ingestEpoch } from '../crypto/e2ee.js';
import { decryptAll, loadConversations, publishNextEpoch } from './chat.js';
import { outbox } from './Outbox.js';
import type { MessageDTO } from '@rtc/shared';

type Cleanup = () => void;

/**
 * Signalling bridge, installed by the call UI while a call is live.
 *
 * The listeners below are registered once for the whole session, but the mesh
 * only exists during a call — so signalling is routed through this indirection
 * rather than by adding and removing socket listeners, which would risk
 * dropping an offer during the window between the two.
 */
export interface MeshBridge {
  describe?: (from: string, description: RTCSessionDescriptionInit) => void;
  candidate?: (from: string, candidate: RTCIceCandidateInit) => void;
  peerJoined?: (peer: unknown) => void;
  peerLeft?: (socketId: string) => void;
  mediaState?: (socketId: string, state: unknown) => void;
}

let meshBridge: MeshBridge = {};

export const setMeshBridge = (bridge: MeshBridge): void => {
  meshBridge = bridge;
};

export const clearMeshBridge = (): void => {
  meshBridge = {};
};

/**
 * Resynchronise after every connect.
 *
 * The ORDER matters and is the whole point of this function:
 *
 *  1. Backfill first. If a send actually landed before the drop, backfill
 *     delivers it, the message store reconciles the optimistic row on
 *     clientMsgId, and the outbox entry retires without re-emitting.
 *  2. Re-join rooms, so live fan-out resumes.
 *  3. Only then flush the outbox.
 *
 * Flushing first would work — sends are idempotent — but it would emit
 * requests the backfill was about to make unnecessary.
 */
async function resync(): Promise<void> {
  const { user } = useSession.getState();
  if (!user) return;

  const cursors = useConversations.getState().syncCursors();
  if (cursors.length > 0) {
    try {
      const result = await emit<{
        serverTime: number;
        conversations: Array<{
          conversationId: string;
          messages: MessageDTO[];
          hasMore: boolean;
          latestSeq: number;
          watermarks: Array<{ userId: string; deliveredSeq: number; readSeq: number }>;
          presence: Array<{ userId: string; status: 'online' | 'offline'; lastSeenAt: number }>;
        }>;
      }>('sync:since', { cursors });

      for (const conv of result.conversations) {
        if (conv.messages.length > 0) {
          useMessages.getState().upsert(conv.conversationId, conv.messages);
          useConversations.getState().setLatestSeq(conv.conversationId, conv.latestSeq);
          void decryptAll(conv.conversationId, conv.messages);
        }
        useConversations.getState().setPresence(conv.presence as never);
      }
    } catch {
      // A failed backfill is recoverable: history is refetched lazily on scroll.
    }
  }

  // Re-join every conversation this tab had open.
  const active = useConversations.getState().activeId;
  if (active) await emit('room:join', { conversationId: active }).catch(() => undefined);

  await outbox(user.id).flush();
}

/**
 * Register every server-to-client listener exactly once.
 *
 * One place, so there is a single answer to "what happens when the server
 * says X" — and no chance of two components both reacting and double-applying.
 */
export function installBindings(): Cleanup {
  const conversations = () => useConversations.getState();
  const messages = () => useMessages.getState();

  const onConnect = () => {
    useSession.getState().setConnection('online');
    void resync();
  };
  const onDisconnect = () => useSession.getState().setConnection('connecting');

  const onMessage = ({ message }: { message: MessageDTO }) => {
    const conversationId = String(message.conversationId);
    messages().upsert(conversationId, [message]);
    conversations().setLatestSeq(conversationId, message.seq);
    void decryptAll(conversationId, [message]);

    // Only bump unread for a conversation that is not on screen.
    const { activeId } = conversations();
    const { user } = useSession.getState();
    if (conversationId !== activeId && String(message.senderId) !== user?.id) {
      const view = conversations().byId[conversationId];
      if (view) conversations().setUnread(conversationId, view.unread + 1);
    }
  };

  const onDeleted = (p: { conversationId: string; messageId: string; deletedAt: number }) =>
    messages().markDeleted(String(p.conversationId), String(p.messageId), p.deletedAt);

  const onReceipt = (p: { conversationId: string; userId: string; readSeq: number; deliveredSeq: number }) => {
    const view = conversations().byId[String(p.conversationId)];
    if (!view) return;
    conversations().setParticipants(
      String(p.conversationId),
      view.participants.map((participant) =>
        String(participant.userId) === String(p.userId)
          ? { ...participant, lastReadSeq: p.readSeq, lastDeliveredSeq: p.deliveredSeq }
          : participant,
      ),
    );
  };

  const onTyping = (p: { conversationId: string; userId: string; isTyping: boolean }) =>
    conversations().setTyping(String(p.conversationId), String(p.userId), p.isTyping);

  const onPresence = (p: { userId: string; status: 'online' | 'offline'; lastSeenAt: number }) =>
    conversations().setPresence([p as never]);

  const onEpoch = async (p: { conversationId: string; epoch: never }) => {
    const { user, priv } = useSession.getState();
    if (!user || !priv) return;
    await ingestEpoch(priv, user.id, String(p.conversationId), p.epoch).catch(() => undefined);
    conversations().setRekeyPending(String(p.conversationId), false);
    // History encrypted under the new epoch can now be opened.
    await loadConversations().catch(() => undefined);
  };

  /**
   * Membership changed, so the room needs a new key.
   *
   * Only the nominated leader publishes, to avoid every online member racing
   * to mint a competing epoch. A wasted round is harmless — the server cannot
   * forge one — but it is still wasted.
   */
  const onRekeyRequired = async (p: {
    conversationId: string; newEpoch: number; reason: never; leaderUserId: string;
  }) => {
    const { user } = useSession.getState();
    conversations().setRekeyPending(String(p.conversationId), true);
    if (!user || String(p.leaderUserId) !== user.id) return;
    await publishNextEpoch(String(p.conversationId), p.newEpoch, p.reason).catch(() => undefined);
  };

  const onDraining = () => useSession.getState().setConnection('draining');
  const onExpired = () => {
    useSession.getState().setConnection('offline');
    useSession.getState().signOut();
  };

  const onRtcDescribe = (p: { from: string; description: RTCSessionDescriptionInit }) =>
    meshBridge.describe?.(String(p.from), p.description);
  const onRtcIce = (p: { from: string; candidate: RTCIceCandidateInit }) =>
    meshBridge.candidate?.(String(p.from), p.candidate);
  const onPeerJoined = (p: { peer: unknown }) => meshBridge.peerJoined?.(p.peer);
  const onPeerLeft = (p: { socketId: string }) => meshBridge.peerLeft?.(String(p.socketId));
  const onRemoteMedia = (p: { socketId: string; state: unknown }) =>
    meshBridge.mediaState?.(String(p.socketId), p.state);

  socket.on('connect', onConnect);
  socket.on('disconnect', onDisconnect);
  socket.on('message:new', onMessage);
  socket.on('message:deleted', onDeleted as never);
  socket.on('receipt:updated', onReceipt as never);
  socket.on('typing:update', onTyping as never);
  socket.on('presence:update', onPresence as never);
  socket.on('epoch:new', onEpoch as never);
  socket.on('room:rekey-required', onRekeyRequired as never);
  socket.on('server:draining', onDraining);
  socket.on('session:expired', onExpired);
  socket.on('rtc:describe', onRtcDescribe as never);
  socket.on('rtc:ice', onRtcIce as never);
  socket.on('call:peer-joined', onPeerJoined as never);
  socket.on('call:peer-left', onPeerLeft as never);
  socket.on('rtc:media-state', onRemoteMedia as never);

  const stopRenewal = installTokenRenewal();

  return () => {
    socket.off('connect', onConnect);
    socket.off('disconnect', onDisconnect);
    socket.off('message:new', onMessage);
    socket.off('message:deleted', onDeleted as never);
    socket.off('receipt:updated', onReceipt as never);
    socket.off('typing:update', onTyping as never);
    socket.off('presence:update', onPresence as never);
    socket.off('epoch:new', onEpoch as never);
    socket.off('room:rekey-required', onRekeyRequired as never);
    socket.off('server:draining', onDraining);
    socket.off('session:expired', onExpired);
    socket.off('rtc:describe', onRtcDescribe as never);
    socket.off('rtc:ice', onRtcIce as never);
    socket.off('call:peer-joined', onPeerJoined as never);
    socket.off('call:peer-left', onPeerLeft as never);
    socket.off('rtc:media-state', onRemoteMedia as never);
    stopRenewal();
  };
}
