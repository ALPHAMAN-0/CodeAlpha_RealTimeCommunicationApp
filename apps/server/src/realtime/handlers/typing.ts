import { asUserId, roomKey, socketSchemas, THROTTLE, type ConversationId } from '@rtc/shared';
import { defineHandler } from '../handler.js';
import type { TypedServer, TypedSocket } from '../types.js';

/**
 * Typing indicators.
 *
 * Never persisted, and server-visible by necessity — the server has to route
 * the event, so it necessarily knows who emitted it and when. Encrypting the
 * mere fact of an event you must deliver would be theatre.
 *
 * The server also expires them. A client that emits `typing:start` and then
 * crashes would otherwise leave a permanent "Alice is typing…" on every other
 * screen.
 */
export function registerTypingHandlers(io: TypedServer, socket: TypedSocket): void {
  const expiry = new Map<string, NodeJS.Timeout>();

  const emit = (conversationId: string, isTyping: boolean) => {
    // Excludes this socket: you do not need to be told you are typing.
    socket.to(roomKey(conversationId)).emit('typing:update', {
      conversationId: conversationId as never,
      userId: asUserId(socket.data.userId),
      isTyping,
    });
  };

  const stop = (conversationId: string) => {
    const timer = expiry.get(conversationId);
    if (timer) {
      clearTimeout(timer);
      expiry.delete(conversationId);
      emit(conversationId, false);
    }
  };

  defineHandler<{ conversationId: ConversationId }, null>(
    io, socket, 'typing:start', socketSchemas['typing:start'],
    { requiresMembership: true, requiresJoined: true },
    ({ payload }) => {
      const conversationId = String(payload.conversationId);
      const already = expiry.has(conversationId);
      clearTimeout(expiry.get(conversationId));
      const timer = setTimeout(() => {
        expiry.delete(conversationId);
        emit(conversationId, false);
      }, THROTTLE.TYPING_EXPIRE_MS);
      timer.unref?.();
      expiry.set(conversationId, timer);
      // Re-emitting on every keystroke would be pure noise; the timer refresh
      // above is what keeps the indicator alive.
      if (!already) emit(conversationId, true);
      return null;
    },
  );

  defineHandler<{ conversationId: ConversationId }, null>(
    io, socket, 'typing:stop', socketSchemas['typing:stop'],
    { requiresMembership: true },
    ({ payload }) => {
      stop(String(payload.conversationId));
      return null;
    },
  );

  socket.on('disconnect', () => {
    for (const [conversationId, timer] of expiry) {
      clearTimeout(timer);
      // Clear the indicator for everyone else; the socket is gone, so it is
      // certainly not still typing.
      socket.to(roomKey(conversationId)).emit('typing:update', {
        conversationId: conversationId as never,
        userId: asUserId(socket.data.userId),
        isTyping: false,
      });
    }
    expiry.clear();
  });
}
