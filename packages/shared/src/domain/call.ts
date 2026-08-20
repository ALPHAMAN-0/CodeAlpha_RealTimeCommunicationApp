import type { SocketId, UserId } from '../ids.js';

export interface MediaState {
  audio: boolean;
  video: boolean;
  screen: boolean;
}

export interface CallPeerDTO {
  /**
   * Signalling is addressed per SOCKET, not per user: one user with two tabs
   * is two independent peers with two independent PeerConnections.
   */
  socketId: SocketId;
  userId: UserId;
  displayName: string;
  avatarColor: string;
  state: MediaState;
}

/**
 * Structural mirrors of the WebRTC dictionaries.
 *
 * Defined here rather than reusing lib.DOM so the server can typecheck the
 * signalling relay without pulling browser globals into its type environment.
 * They are assignable to/from the real DOM types on the client.
 */
export interface SdpDescription {
  type: 'offer' | 'answer' | 'pranswer' | 'rollback';
  sdp?: string;
}

export interface IceCandidatePayload {
  candidate: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
  usernameFragment?: string | null;
}

export interface IceServerConfig {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export interface IceConfigDTO {
  iceServers: IceServerConfig[];
  /** Seconds until the TURN credentials above expire. */
  ttlSeconds: number;
  /** True => TURN is configured, so relay-only mode can hide participant IPs. */
  relayAvailable: boolean;
}
