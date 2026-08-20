import { createServer, type Server as HttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { createApp } from '../../app.js';
import { connectDb, disconnectDb } from '../../db/connect.js';
import { ensureIndexes } from '../../db/ensureIndexes.js';
import { createIo, ioStats } from '../../realtime/index.js';
import { __resetGraceCache } from '../../services/auth.service.js';
import { __clearPendingOffline } from '../../services/presence.service.js';
import { __resetEscalation } from '../../realtime/buckets.js';
import { __resetMembershipCache } from '../../realtime/membership.js';
import { __resetCalls } from '../../realtime/registry/CallRegistry.js';
import type { TypedServer } from '../../realtime/types.js';

export interface TestServer {
  url: string;
  io: TypedServer;
  http: HttpServer;
  close: () => Promise<void>;
  /** Wipe all collections and process-local caches between tests. */
  reset: () => Promise<void>;
}

/**
 * Boot a real HTTP + Socket.IO server on an ephemeral port against an
 * in-memory MongoDB.
 *
 * Deliberately the real stack, not mocks: the bugs worth catching here live in
 * the interaction between Express, Socket.IO, Mongoose indexes and the
 * handler wrapper — none of which a mock would reproduce.
 */
export async function startTestServer(): Promise<TestServer> {
  const mongo = await MongoMemoryServer.create();
  await connectDb(mongo.getUri('rtc-test'));
  await ensureIndexes();

  const http = createServer();
  const io = createIo(http);
  http.on('request', createApp(ioStats(io)));
  await new Promise<void>((resolve) => http.listen(0, '127.0.0.1', resolve));
  const { port } = http.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    io,
    http,
    reset: async () => {
      const collections = await mongoose.connection.db!.collections();
      await Promise.all(collections.map((c) => c.deleteMany({})));
      // Module-level state survives a database wipe, so it has to be cleared
      // explicitly or tests leak into each other in order-dependent ways.
      __resetGraceCache();
      __clearPendingOffline();
      __resetEscalation();
      __resetMembershipCache();
      __resetCalls();
    },
    close: async () => {
      await new Promise<void>((resolve) => io.close(() => resolve()));
      await new Promise<void>((resolve) => http.close(() => resolve()));
      await disconnectDb();
      await mongo.stop();
    },
  };
}
