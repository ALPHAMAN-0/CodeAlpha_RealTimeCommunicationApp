import { RateLimiterMemory } from 'rate-limiter-flexible';
import { RATE, RATE_ESCALATION, RATE_GLOBAL, WB_BYTE_BUDGET, type RateLimitedEvent } from '@rtc/shared';

/**
 * Per-socket token buckets.
 *
 * Memory-backed, which is correct for a single instance. Multi-instance would
 * swap in the Redis store; the interface does not change, so that is a
 * configuration change rather than a rewrite.
 */
const perEvent = new Map<RateLimitedEvent, RateLimiterMemory>();
for (const [event, cfg] of Object.entries(RATE)) {
  perEvent.set(
    event as RateLimitedEvent,
    new RateLimiterMemory({ points: cfg.points, duration: cfg.durationMs / 1000 }),
  );
}

/** Catch-all, applied in addition to the per-event bucket. */
const global = new RateLimiterMemory({
  points: RATE_GLOBAL.points,
  duration: RATE_GLOBAL.durationMs / 1000,
});

/**
 * A byte budget alongside the op-count budget for whiteboard traffic.
 *
 * Counting ops alone is insufficient: 200 ops of 4 bytes and 200 ops of 200 KB
 * are the same number of ops and wildly different amounts of work.
 */
const wbBytes = new RateLimiterMemory({
  points: WB_BYTE_BUDGET.bytes,
  duration: WB_BYTE_BUDGET.durationMs / 1000,
});

export interface RateVerdict {
  allowed: boolean;
  retryAfterMs: number;
}

const consume = async (limiter: RateLimiterMemory, key: string, points = 1): Promise<RateVerdict> => {
  try {
    await limiter.consume(key, points);
    return { allowed: true, retryAfterMs: 0 };
  } catch (rejection) {
    const ms = (rejection as { msBeforeNext?: number }).msBeforeNext ?? 1000;
    return { allowed: false, retryAfterMs: ms };
  }
};

export async function checkRate(socketId: string, event: string): Promise<RateVerdict> {
  const g = await consume(global, socketId);
  if (!g.allowed) return g;
  const limiter = perEvent.get(event as RateLimitedEvent);
  if (!limiter) return { allowed: true, retryAfterMs: 0 };
  return consume(limiter, `${event}:${socketId}`, 1);
}

export const checkWhiteboardBytes = (socketId: string, bytes: number): Promise<RateVerdict> =>
  consume(wbBytes, socketId, Math.max(1, bytes));

/**
 * Escalation: repeated violations disconnect the socket, and repeated
 * disconnects refuse the USER at the handshake.
 *
 * Without the second step a client in a tight reconnect loop simply pays the
 * cost of a new connection and carries on flooding.
 */
const violations = new Map<string, number[]>();
const disconnects = new Map<string, number[]>();
const bans = new Map<string, number>();

const prune = (arr: number[], windowMs: number, now: number) => arr.filter((t) => now > 0 && t > now - windowMs);

/** @returns true when this socket has earned a disconnect. */
export function recordViolation(socketId: string, now = Date.now()): boolean {
  const hits = prune(violations.get(socketId) ?? [], RATE_ESCALATION.VIOLATION_WINDOW_MS, now);
  hits.push(now);
  violations.set(socketId, hits);
  return hits.length >= RATE_ESCALATION.VIOLATIONS_BEFORE_DISCONNECT;
}

/** @returns true when this user is now banned from opening new connections. */
export function recordDisconnect(userId: string, now = Date.now()): boolean {
  const hits = prune(disconnects.get(userId) ?? [], RATE_ESCALATION.DISCONNECT_WINDOW_MS, now);
  hits.push(now);
  disconnects.set(userId, hits);
  if (hits.length >= RATE_ESCALATION.DISCONNECTS_BEFORE_BAN) {
    bans.set(userId, now + RATE_ESCALATION.BAN_MS);
    return true;
  }
  return false;
}

export function isBanned(userId: string, now = Date.now()): boolean {
  const until = bans.get(userId);
  if (until === undefined) return false;
  if (until <= now) {
    bans.delete(userId);
    return false;
  }
  return true;
}

export function forgetSocket(socketId: string): void {
  violations.delete(socketId);
}

/** Tests share module state; they need a way back to a clean slate. */
export function __resetEscalation(): void {
  violations.clear();
  disconnects.clear();
  bans.clear();
}
