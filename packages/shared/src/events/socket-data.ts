import type { ConversationId, UserId } from '../ids.js';

/** Per-socket server state. Set by the handshake middleware, never by a client. */
export interface SocketData {
  userId: UserId;
  /** Refresh-token family id. Revoking a family disconnects every socket on it. */
  sessionId: string;
  displayName: string;
  avatarColor: string;
  /** Access token expiry, epoch ms. Re-checked by every handler. */
  tokenExpiresAt: number;
  /**
   * Conversations this socket has joined AND was authorized for. Handlers
   * check this set instead of hitting Mongo on every event — but a DB
   * membership check still runs for anything security-relevant, because the
   * DB is the authority and this cache can lag a removal.
   */
  rooms: Set<ConversationId>;
  /** Conversations where this socket is an active call participant. */
  calls: Set<ConversationId>;
}

export interface InterServerEvents {
  /** Reserved for @socket.io/redis-adapter when this outgrows one instance. */
  ping: () => void;
}
