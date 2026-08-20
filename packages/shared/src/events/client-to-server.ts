import type { Ack } from '../result.js';
import type {
  ConversationId, UserId, SocketId, ClientMsgId, MessageId, AttachmentId, StrokeId, Seq,
} from '../ids.js';
import type {
  ConversationDTO, ParticipantDTO, MessageDTO, PresenceDTO, CallPeerDTO,
  MediaState, WhiteboardOpRecord, WhiteboardOpKind, CipherEnvelope,
  EpochRecord, SdpDescription, IceCandidatePayload,
} from '../domain/index.js';

/**
 * Every client->server event takes EXACTLY (payload, ack). No positional
 * args, no exceptions.
 *
 * That uniformity is what lets a single `defineHandler` wrapper enforce rate
 * limiting, Zod validation, room authorization, serialization and error
 * shaping for all of them. A handler that skips the wrapper becomes visibly
 * anomalous in review instead of being an invisible hole.
 */
export interface ClientToServerEvents {
  // ── session ───────────────────────────────────────────────────────────────
  /**
   * Re-authenticate in place after the access token expired mid-connection.
   * Tearing down the socket instead would take the whole WebRTC mesh with it.
   */
  'session:reauth': (
    p: { accessToken: string },
    ack: (r: Ack<{ userId: UserId; expiresAt: number }>) => void,
  ) => void;

  // ── rooms ─────────────────────────────────────────────────────────────────
  /** Idempotent: re-joining returns fresh state rather than an error. */
  'room:join': (
    p: { conversationId: ConversationId },
    ack: (r: Ack<{
      conversation: ConversationDTO;
      participants: ParticipantDTO[];
      presence: PresenceDTO[];
      latestSeq: Seq;
      yourLastReadSeq: Seq;
      unread: number;
      call: { active: boolean; peers: CallPeerDTO[] };
      whiteboardSeq: Seq;
      /** The caller's wrap of the current epoch key. Absent for DMs. */
      epoch?: EpochRecord;
    }>) => void,
  ) => void;

  'room:leave': (
    p: { conversationId: ConversationId },
    ack: (r: Ack<null>) => void,
  ) => void;

  // ── chat ──────────────────────────────────────────────────────────────────
  /**
   * Idempotent on (conversationId, clientMsgId), enforced by a unique index.
   * Safe to retry the identical payload forever — that property is the whole
   * reliability story, see docs/RELIABILITY.md.
   */
  'message:send': (
    p: {
      conversationId: ConversationId;
      clientMsgId: ClientMsgId;
      kind: 'text' | 'file';
      /** Sealed body. The server stores it verbatim and cannot read it. */
      envelope: CipherEnvelope;
      /** Client clock, bound into the envelope's AAD. */
      sentAt: number;
      attachmentId?: AttachmentId;
      replyToId?: MessageId;
    },
    ack: (r: Ack<{
      messageId: MessageId;
      /** Echoed so the client can reconcile its optimistic row. */
      clientMsgId: ClientMsgId;
      seq: Seq;
      createdAt: number;
      /** True => this was a replay and no new row was written. */
      deduped: boolean;
    }>) => void,
  ) => void;

  /** Backwards scroll. `beforeSeq` is exclusive. */
  'message:history': (
    p: { conversationId: ConversationId; beforeSeq?: Seq; limit?: number },
    ack: (r: Ack<{ messages: MessageDTO[]; hasMore: boolean; oldestSeq: Seq | null }>) => void,
  ) => void;

  'message:delete': (
    p: { conversationId: ConversationId; messageId: MessageId },
    ack: (r: Ack<{ messageId: MessageId; deletedAt: number }>) => void,
  ) => void;

  // ── reconnect backfill ────────────────────────────────────────────────────
  /**
   * Batched across every open conversation so a reconnect costs one round
   * trip instead of one per room. Runs on EVERY connect, whether or not
   * connectionStateRecovery kicked in.
   */
  'sync:since': (
    p: { cursors: Array<{ conversationId: ConversationId; lastSeq: Seq }> },
    ack: (r: Ack<{
      serverTime: number;
      conversations: Array<{
        conversationId: ConversationId;
        /** seq ascending, strictly greater than the cursor. */
        messages: MessageDTO[];
        hasMore: boolean;
        latestSeq: Seq;
        watermarks: Array<{ userId: UserId; deliveredSeq: Seq; readSeq: Seq }>;
        presence: PresenceDTO[];
      }>;
    }>) => void,
  ) => void;

  // ── receipts (watermarks, never per-message arrays) ───────────────────────
  'receipt:delivered': (
    p: { conversationId: ConversationId; seq: Seq },
    ack: (r: Ack<null>) => void,
  ) => void;

  'receipt:read': (
    p: { conversationId: ConversationId; seq: Seq },
    ack: (r: Ack<{ unread: number }>) => void,
  ) => void;

  // ── typing (fire-and-forget; the ack exists for tests) ────────────────────
  'typing:start': (p: { conversationId: ConversationId }, ack: (r: Ack<null>) => void) => void;
  'typing:stop': (p: { conversationId: ConversationId }, ack: (r: Ack<null>) => void) => void;

  // ── presence ──────────────────────────────────────────────────────────────
  'presence:query': (
    p: { userIds: UserId[] },
    ack: (r: Ack<{ presence: PresenceDTO[] }>) => void,
  ) => void;

  // ── calls / WebRTC signalling ─────────────────────────────────────────────
  'call:join': (
    p: { conversationId: ConversationId; media: MediaState },
    ack: (r: Ack<{
      peers: CallPeerDTO[];
      selfSocketId: SocketId;
      maxParticipants: number;
    }>) => void,
  ) => void;

  'call:leave': (p: { conversationId: ConversationId }, ack: (r: Ack<null>) => void) => void;

  /**
   * ONE channel carries both offers and answers.
   *
   * Splitting into rtc:offer / rtc:answer duplicates the glare-resolution
   * logic into two code paths that have to agree, and eventually don't.
   */
  'rtc:describe': (
    p: { conversationId: ConversationId; to: SocketId; description: SdpDescription },
    ack: (r: Ack<null>) => void,
  ) => void;

  'rtc:ice': (
    p: { conversationId: ConversationId; to: SocketId; candidate: IceCandidatePayload },
    ack: (r: Ack<null>) => void,
  ) => void;

  /**
   * Mute / camera-off / screen-share toggles. Tracks are never removed for
   * these — a receiver cannot observe `track.enabled = false`, so this event
   * is what drives the remote UI.
   */
  'rtc:media-state': (
    p: { conversationId: ConversationId; state: MediaState },
    ack: (r: Ack<null>) => void,
  ) => void;

  // ── whiteboard ────────────────────────────────────────────────────────────
  'wb:op': (
    p: {
      conversationId: ConversationId;
      kind: WhiteboardOpKind;
      strokeId?: StrokeId;
      chunk?: number;
      done?: boolean;
      /** Sealed geometry. Required for kind === 'stroke', absent otherwise. */
      envelope?: CipherEnvelope;
    },
    ack: (r: Ack<{ seq: Seq }>) => void,
  ) => void;

  'wb:sync': (
    p: { conversationId: ConversationId; sinceSeq: Seq },
    ack: (r: Ack<{
      ops: WhiteboardOpRecord[];
      hasMore: boolean;
      latestSeq: Seq;
      /** True => the log hit its cap and the oldest ops were dropped. */
      truncated: boolean;
    }>) => void,
  ) => void;

  'wb:cursor': (
    p: { conversationId: ConversationId; x: number; y: number },
    ack: (r: Ack<null>) => void,
  ) => void;

  // ── group key management ──────────────────────────────────────────────────
  /**
   * The nominated rekey leader publishes the next epoch: a fresh room key
   * wrapped once per member. The server relays and stores it but cannot forge
   * one (no valid wraps, no valid signature), so a bad nomination costs at
   * most a wasted epoch.
   */
  'epoch:publish': (
    p: { conversationId: ConversationId; epoch: EpochRecord },
    ack: (r: Ack<{ epoch: number }>) => void,
  ) => void;

  /** Fetch a specific epoch's wrap, e.g. when decrypting older messages. */
  'epoch:get': (
    p: { conversationId: ConversationId; epoch: number },
    ack: (r: Ack<{ epoch: EpochRecord }>) => void,
  ) => void;

  // ── files ─────────────────────────────────────────────────────────────────
  /** Cosmetic: lets peers see "Alice is sending a file… 40%" during an upload. */
  'file:upload-progress': (
    p: { conversationId: ConversationId; clientMsgId: ClientMsgId; progress: number },
    ack: (r: Ack<null>) => void,
  ) => void;
}
