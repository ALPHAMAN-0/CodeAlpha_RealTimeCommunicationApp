import type { ZodType } from 'zod';
import { RtcError, asConversationId, type Ack, type AppError, isRetryable } from '@rtc/shared';
import { log, securityLog } from '../config/logger.js';
import { checkRate, recordDisconnect, recordViolation } from './buckets.js';
import { isMember } from './membership.js';
import { SerialQueueMap } from './SerialQueue.js';
import type { TypedServer, TypedSocket } from './types.js';

/** One queue map process-wide, keyed `${socketId}:${conversationId}`. */
const queues = new SerialQueueMap();
export const releaseQueues = (socketId: string): void => queues.deletePrefix(`${socketId}:`);

export interface HandlerCtx<P> {
  io: TypedServer;
  socket: TypedSocket;
  payload: P;
  userId: string;
}

export interface HandlerOptions {
  /** Require DB-verified membership of `payload.conversationId`. */
  requiresMembership?: boolean;
  /** Require that this socket actually joined the room, not just that it may. */
  requiresJoined?: boolean;
  /** Serialise per (socket, conversation) — for anything allocating a seq. */
  serialize?: boolean;
}

type Handler<P, R> = (ctx: HandlerCtx<P>) => Promise<R> | R;

const toAppError = (err: unknown): AppError => {
  if (err instanceof RtcError) return err.toAppError();
  return { code: 'INTERNAL', message: 'Internal error', retryable: true };
};

/**
 * The single registration path for every client->server event.
 *
 * Uniform `(payload, ack)` signatures let this one wrapper enforce, in order:
 *
 *   rate limit -> Zod parse -> token still valid -> membership -> joined
 *   -> optional serialisation -> handler -> error shaping -> ack
 *
 * The point is not convenience. It is that a handler which skips this wrapper
 * is visibly anomalous in review, rather than being an invisible hole in
 * authorization. A reflection test asserts every declared event is registered
 * through it.
 */
export function defineHandler<P, R>(
  io: TypedServer,
  socket: TypedSocket,
  event: string,
  schema: ZodType,
  options: HandlerOptions,
  handler: Handler<P, R>,
): void {
  socket.on(event as never, (async (raw: unknown, rawAck?: unknown) => {
    const ack = (typeof rawAck === 'function' ? rawAck : () => {}) as (r: Ack<unknown>) => void;

    const fail = (error: AppError) => ack({ ok: false, error });

    try {
      // 1. Rate limit BEFORE parsing, so a flood of malformed payloads costs
      //    as little as a flood of valid ones.
      const verdict = await checkRate(socket.id, event);
      if (!verdict.allowed) {
        if (recordViolation(socket.id)) {
          securityLog.warn({ userId: socket.data.userId, event }, 'socket disconnected for repeated rate violations');
          if (recordDisconnect(socket.data.userId)) {
            socket.emit('session:expired', { reason: 'rate-banned' });
          }
          socket.disconnect(true);
          return;
        }
        return fail({
          code: 'RATE_LIMITED', message: 'Slow down', retryable: true, retryAfterMs: verdict.retryAfterMs,
        });
      }

      // 2. Validate. Schemas are strict, so unknown keys are rejected rather
      //    than stripped — silent stripping hides client/server contract drift.
      const parsed = schema.safeParse(raw);
      if (!parsed.success) {
        log.warn(
          {
            event,
            userId: socket.data.userId,
            issues: parsed.error.issues
              .slice(0, 5)
              .map((i) => ({ at: i.path.join('.') || '(root)', code: i.code })),
          },
          'socket payload rejected',
        );
        // Report which fields, never the values.
        return fail({ code: 'VALIDATION', message: 'Invalid payload', retryable: false });
      }
      const payload = parsed.data as P & { conversationId?: string };

      // 3. The expiry timer is a convenience; THIS is the authority. A socket
      //    must never outlive the token that authorized it.
      if (Date.now() >= socket.data.tokenExpiresAt) {
        return fail({ code: 'TOKEN_EXPIRED', message: 'Access token expired', retryable: true });
      }

      const conversationId = payload.conversationId;

      // 4. The database is the authority on membership.
      if (options.requiresMembership) {
        if (!conversationId || !(await isMember(socket.data.userId, conversationId))) {
          securityLog.warn(
            { userId: socket.data.userId, event, conversationId },
            'membership check failed',
          );
          return fail({ code: 'NOT_A_MEMBER', message: 'Not a member of this conversation', retryable: false });
        }
      }

      // 5. The socket's room set is the authority on delivery. Both checks are
      //    needed: a removed-but-still-joined socket must fail (4), and a
      //    member who never joined must not inject into the room (5).
      if (options.requiresJoined && (!conversationId || !socket.data.rooms.has(asConversationId(conversationId)))) {
        return fail({ code: 'NOT_JOINED', message: 'Join the conversation first', retryable: false });
      }

      const ctx: HandlerCtx<P> = { io, socket, payload: payload as P, userId: socket.data.userId };
      const run = () => Promise.resolve(handler(ctx));
      const data = options.serialize && conversationId
        ? await queues.for(`${socket.id}:${conversationId}`).run(run)
        : await run();

      ack({ ok: true, data });
    } catch (err) {
      const appError = toAppError(err);
      if (appError.code === 'INTERNAL') {
        // Log the cause server-side; the client gets a code and nothing else.
        log.error({ err, event, userId: socket.data.userId }, 'socket handler error');
      }
      fail({ ...appError, retryable: isRetryable(appError.code) });
    }
  }) as never);
}
