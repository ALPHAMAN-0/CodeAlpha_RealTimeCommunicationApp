import type { ConversationId, UserId, SocketId, MessageId, ClientMsgId, Seq } from '../ids.js';
import type {
  MessageDTO, ParticipantDTO, PresenceDTO, CallPeerDTO, MediaState,
  WhiteboardOpRecord, EpochRecord, RekeyReason, SdpDescription, IceCandidatePayload,
} from '../domain/index.js';

export interface ServerToClientEvents {
  // ── session / transport ───────────────────────────────────────────────────
  /** Access token is about to expire. Refresh, then call `session:reauth`. */
  'auth:expiring': (p: { expiresAt: number; graceMs: number }) => void;
  'session:expired': (p: { reason: 'token-expired' | 'revoked' | 'rate-banned' }) => void;
  /** Graceful shutdown notice, so clients back off instead of stampeding. */
  'server:draining': (p: { retryAfterMs: number }) => void;
  /** Out-of-band error with no ack to attach to. */
  'error:notice': (p: { code: string; message: string }) => void;

  // ── rooms / membership ────────────────────────────────────────────────────
  'room:member-joined': (p: { conversationId: ConversationId; participant: ParticipantDTO }) => void;
  'room:member-left': (p: { conversationId: ConversationId; userId: UserId }) => void;

  // ── chat ──────────────────────────────────────────────────────────────────
  /** At-least-once fan-out. Receivers dedupe on `message.id`. */
  'message:new': (p: { message: MessageDTO }) => void;
  'message:deleted': (p: {
    conversationId: ConversationId;
    messageId: MessageId;
    seq: Seq;
    deletedAt: number;
  }) => void;

  // ── receipts ──────────────────────────────────────────────────────────────
  'receipt:updated': (p: {
    conversationId: ConversationId;
    userId: UserId;
    deliveredSeq: Seq;
    readSeq: Seq;
  }) => void;

  // ── typing / presence ─────────────────────────────────────────────────────
  'typing:update': (p: { conversationId: ConversationId; userId: UserId; isTyping: boolean }) => void;
  'presence:update': (p: PresenceDTO) => void;

  // ── calls ─────────────────────────────────────────────────────────────────
  'call:peer-joined': (p: { conversationId: ConversationId; peer: CallPeerDTO }) => void;
  'call:peer-left': (p: {
    conversationId: ConversationId;
    socketId: SocketId;
    userId: UserId;
    reason: 'left' | 'disconnected' | 'evicted';
  }) => void;

  /** Relayed verbatim to ONE addressed socket. `from` is stamped server-side. */
  'rtc:describe': (p: {
    conversationId: ConversationId;
    from: SocketId;
    fromUserId: UserId;
    description: SdpDescription;
  }) => void;

  'rtc:ice': (p: {
    conversationId: ConversationId;
    from: SocketId;
    candidate: IceCandidatePayload;
  }) => void;

  'rtc:media-state': (p: {
    conversationId: ConversationId;
    socketId: SocketId;
    userId: UserId;
    state: MediaState;
  }) => void;

  // ── whiteboard ────────────────────────────────────────────────────────────
  'wb:op': (p: { conversationId: ConversationId; record: WhiteboardOpRecord }) => void;
  'wb:reset': (p: { conversationId: ConversationId; clearedAtSeq: Seq; byUserId: UserId }) => void;
  'wb:cursor': (p: { conversationId: ConversationId; userId: UserId; x: number; y: number }) => void;

  // ── group key management ──────────────────────────────────────────────────
  /**
   * Membership changed, so the room key must be replaced. Sending is blocked
   * client-side until a new epoch lands — fail closed, never fall back to the
   * old key.
   */
  'room:rekey-required': (p: {
    conversationId: ConversationId;
    newEpoch: number;
    reason: RekeyReason;
    /** Nominated publisher: the online member with the lowest userId. */
    leaderUserId: UserId;
  }) => void;

  'epoch:new': (p: { conversationId: ConversationId; epoch: EpochRecord }) => void;

  // ── files ─────────────────────────────────────────────────────────────────
  'file:upload-progress': (p: {
    conversationId: ConversationId;
    userId: UserId;
    clientMsgId: ClientMsgId;
    progress: number;
  }) => void;
}
