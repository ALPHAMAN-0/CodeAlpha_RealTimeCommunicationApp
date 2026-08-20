import {
  RtcError, asSocketId, asUserId, callKey, roomKey, socketSchemas,
  type CallPeerDTO, type ConversationId, type IceCandidatePayload,
  type MediaState, type SdpDescription, type SocketId,
} from '@rtc/shared';
import { env } from '../../config/env.js';
import { securityLog } from '../../config/logger.js';
import { defineHandler } from '../handler.js';
import { addPeer, isInCall, peersOf, removePeer, setMediaState } from '../registry/CallRegistry.js';
import type { TypedServer, TypedSocket } from '../types.js';

/**
 * Resolve and authorize a signalling target.
 *
 * This is the highest-risk authorization in the app, so every condition is
 * explicit:
 *
 *  - the target socket must exist and be authenticated
 *  - it must not be the sender (self-signalling is meaningless and would loop)
 *  - it must be in the SAME conversation's call
 *
 * The message is then emitted to that ONE resolved socket. Broadcasting to the
 * room instead would hand every participant's ICE candidates and DTLS
 * fingerprints to everyone — leaking IP addresses far beyond the pair that
 * needs them.
 */
function resolveTarget(
  io: TypedServer,
  socket: TypedSocket,
  conversationId: string,
  to: SocketId,
): TypedSocket {
  const target = io.sockets.sockets.get(String(to)) as TypedSocket | undefined;
  if (
    !target ||
    target.id === socket.id ||
    !target.data?.userId ||
    !isInCall(conversationId, target.id)
  ) {
    throw new RtcError('BAD_TARGET', 'Signalling target is not in this call');
  }
  return target;
}

/** The sender must be in the call too — membership alone is not enough. */
function assertInCall(socket: TypedSocket, conversationId: string): void {
  if (!isInCall(conversationId, socket.id)) {
    throw new RtcError('NOT_JOINED', 'Join the call before signalling');
  }
}

export function registerRtcHandlers(io: TypedServer, socket: TypedSocket): void {
  defineHandler<
    { conversationId: ConversationId; media: MediaState },
    { peers: CallPeerDTO[]; selfSocketId: SocketId; maxParticipants: number }
  >(
    io, socket, 'call:join', socketSchemas['call:join'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      // Snapshot the existing peers BEFORE adding self, so the joiner gets the
      // list it needs to open connections to and does not include itself.
      const existing = peersOf(conversationId);

      const { ok, full } = addPeer(conversationId, {
        socketId: socket.id,
        userId: socket.data.userId,
        displayName: socket.data.displayName,
        avatarColor: socket.data.avatarColor,
        state: payload.media,
      });
      if (!ok && full) throw new RtcError('ROOM_FULL', `Call is full (${env.MAX_CALL_PARTICIPANTS}/${env.MAX_CALL_PARTICIPANTS})`);

      void socket.join(callKey(conversationId));
      socket.data.calls.add(payload.conversationId);

      const self: CallPeerDTO = {
        socketId: asSocketId(socket.id),
        userId: asUserId(socket.data.userId),
        displayName: socket.data.displayName,
        avatarColor: socket.data.avatarColor,
        state: payload.media,
      };
      // Announce to the room, not just the call: the UI shows a "call in
      // progress" affordance to members who have not joined yet.
      socket.to(roomKey(conversationId)).emit('call:peer-joined', {
        conversationId: payload.conversationId,
        peer: self,
      });

      return {
        peers: existing,
        selfSocketId: asSocketId(socket.id),
        maxParticipants: env.MAX_CALL_PARTICIPANTS,
      };
    },
  );

  defineHandler<{ conversationId: ConversationId }, null>(
    io, socket, 'call:leave', socketSchemas['call:leave'], {},
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      if (removePeer(conversationId, socket.id)) {
        void socket.leave(callKey(conversationId));
        socket.data.calls.delete(payload.conversationId);
        socket.to(roomKey(conversationId)).emit('call:peer-left', {
          conversationId: payload.conversationId,
          socketId: asSocketId(socket.id),
          userId: asUserId(socket.data.userId),
          reason: 'left',
        });
      }
      return null;
    },
  );

  /**
   * Relay one SDP offer or answer.
   *
   * The SDP is size-capped by the schema and passed through UNPARSED. An SDP
   * mangler is a parser attack surface and a reliable source of subtle interop
   * breakage; the membership and target checks are what make pass-through
   * safe. A malicious *member* can put whatever it likes in SDP — that is the
   * accepted "malicious room member" risk, documented in SECURITY.md.
   */
  defineHandler<{ conversationId: ConversationId; to: SocketId; description: SdpDescription }, null>(
    io, socket, 'rtc:describe', socketSchemas['rtc:describe'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      assertInCall(socket, conversationId);
      const target = resolveTarget(io, socket, conversationId, payload.to);
      // `from` is stamped from verified socket state and is never read from
      // the payload, so a peer cannot impersonate another in a negotiation.
      target.emit('rtc:describe', {
        conversationId: payload.conversationId,
        from: asSocketId(socket.id),
        fromUserId: asUserId(socket.data.userId),
        description: payload.description,
      });
      return null;
    },
  );

  defineHandler<{ conversationId: ConversationId; to: SocketId; candidate: IceCandidatePayload }, null>(
    io, socket, 'rtc:ice', socketSchemas['rtc:ice'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      assertInCall(socket, conversationId);
      const target = resolveTarget(io, socket, conversationId, payload.to);
      target.emit('rtc:ice', {
        conversationId: payload.conversationId,
        from: asSocketId(socket.id),
        candidate: payload.candidate,
      });
      return null;
    },
  );

  /**
   * Mute, camera-off and screen-share state.
   *
   * These are signalled explicitly because a receiver CANNOT observe
   * `track.enabled = false` — the track keeps flowing, just black or silent.
   * Removing the track instead would force a renegotiation and freeze the
   * remote's last frame, which is why this event exists at all.
   */
  defineHandler<{ conversationId: ConversationId; state: MediaState }, null>(
    io, socket, 'rtc:media-state', socketSchemas['rtc:media-state'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      if (!setMediaState(conversationId, socket.id, payload.state)) {
        throw new RtcError('NOT_JOINED', 'Not in this call');
      }
      socket.to(roomKey(conversationId)).emit('rtc:media-state', {
        conversationId: payload.conversationId,
        socketId: asSocketId(socket.id),
        userId: asUserId(socket.data.userId),
        state: payload.state,
      });
      return null;
    },
  );

  socket.on('disconnect', () => {
    // Peers must be told, or they sit waiting on a negotiation that will never
    // complete and the UI keeps a frozen tile forever.
    for (const conversationId of socket.data.calls ?? []) {
      const id = String(conversationId);
      if (removePeer(id, socket.id)) {
        socket.to(roomKey(id)).emit('call:peer-left', {
          conversationId,
          socketId: asSocketId(socket.id),
          userId: asUserId(socket.data.userId),
          reason: 'disconnected',
        });
      }
    }
    securityLog.debug({ socketId: socket.id }, 'call cleanup on disconnect');
  });
}
