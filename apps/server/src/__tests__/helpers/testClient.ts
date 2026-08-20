import { io as ioClient, type Socket } from 'socket.io-client';
import type { Ack, ClientToServerEvents, ServerToClientEvents } from '@rtc/shared';
import type { TestUser } from './testUser.js';

type ClientSocket = Socket<ServerToClientEvents, ClientToServerEvents>;

export interface TestClient {
  socket: ClientSocket;
  /** Emit and await the ack, failing loudly on `ok: false`. */
  send: <T>(event: keyof ClientToServerEvents, payload: unknown) => Promise<T>;
  /** Emit and return the raw ack, for asserting on errors. */
  tryS: (event: keyof ClientToServerEvents, payload: unknown) => Promise<Ack<unknown>>;
  /** Resolve on the next matching event, or reject on timeout. */
  waitFor: <T = any>(event: keyof ServerToClientEvents, predicate?: (p: T) => boolean, timeoutMs?: number) => Promise<T>;
  /** Every occurrence of an event seen so far — for asserting on duplicates. */
  received: <T = any>(event: keyof ServerToClientEvents) => T[];
  close: () => void;
}

const RECORDED: Array<keyof ServerToClientEvents> = [
  'message:new', 'message:deleted', 'receipt:updated', 'typing:update',
  'presence:update', 'epoch:new', 'room:rekey-required',
  'call:peer-joined', 'call:peer-left', 'rtc:describe', 'rtc:ice', 'rtc:media-state',
  'wb:op', 'wb:reset', 'wb:cursor', 'session:expired', 'auth:expiring',
  'room:member-joined', 'room:member-left', 'file:upload-progress',
];

export async function connectClient(url: string, user: TestUser): Promise<TestClient> {
  const socket: ClientSocket = ioClient(url, {
    path: '/socket.io',
    transports: ['websocket'],
    // The token travels in the handshake `auth` payload, never a cookie and
    // never the query string — same as the real client.
    auth: { token: user.accessToken },
    reconnection: false,
    forceNew: true,
  });

  const log = new Map<string, any[]>();
  for (const event of RECORDED) {
    log.set(event, []);
    socket.on(event as never, ((payload: unknown) => log.get(event)!.push(payload)) as never);
  }

  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('socket connect timeout')), 10_000);
    socket.once('connect', () => { clearTimeout(timer); resolve(); });
    socket.once('connect_error', (err) => { clearTimeout(timer); reject(err); });
  });

  /**
   * A deliberately loose emit view of the socket.
   *
   * The typed contract gives each event its own signature, which is exactly
   * what you want in application code and exactly what blocks a generic
   * test helper. Narrowing happens at the call sites instead, via the
   * explicit type argument on `send<T>`.
   */
  const loose = socket as unknown as {
    emit: (event: string, payload: unknown, ack: (r: Ack<unknown>) => void) => void;
  };

  const tryS = (event: keyof ClientToServerEvents, payload: unknown): Promise<Ack<unknown>> =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`ack timeout for ${event}`)), 10_000);
      loose.emit(event as string, payload, (ack: Ack<unknown>) => {
        clearTimeout(timer);
        resolve(ack);
      });
    });

  return {
    socket,
    tryS,
    send: async <T>(event: keyof ClientToServerEvents, payload: unknown): Promise<T> => {
      const ack = await tryS(event, payload);
      if (!ack.ok) throw new Error(`${event} failed: ${ack.error.code} ${ack.error.message}`);
      return ack.data as T;
    },
    waitFor: <T>(event: keyof ServerToClientEvents, predicate?: (p: T) => boolean, timeoutMs = 5000): Promise<T> => {
      // Check what already arrived before waiting, so a fast event that landed
      // between two awaits does not cause a spurious timeout.
      const seen = (log.get(event) ?? []) as T[];
      const hit = predicate ? seen.find(predicate) : seen[0];
      if (hit !== undefined) return Promise.resolve(hit);
      return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => {
          socket.off(event as never, handler as never);
          reject(new Error(`timeout waiting for ${event}`));
        }, timeoutMs);
        const handler = (payload: T) => {
          if (predicate && !predicate(payload)) return;
          clearTimeout(timer);
          socket.off(event as never, handler as never);
          resolve(payload);
        };
        socket.on(event as never, handler as never);
      });
    },
    received: <T>(event: keyof ServerToClientEvents): T[] => [...((log.get(event) ?? []) as T[])],
    close: () => socket.disconnect(),
  };
}

/** Let queued events drain before asserting on what did NOT arrive. */
export const settle = (ms = 250): Promise<void> => new Promise((r) => setTimeout(r, ms));
