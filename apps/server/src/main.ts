import { createServer } from 'node:http';
import { env } from './config/env.js';
import { log } from './config/logger.js';
import { createApp } from './app.js';
import { connectDb, disconnectDb } from './db/connect.js';
import { ensureIndexes } from './db/ensureIndexes.js';
import { initDummyHash } from './crypto/passwords.js';
import { createIo, ioStats } from './realtime/index.js';

async function main(): Promise<void> {
  await connectDb();
  await ensureIndexes();
  // Warm the hasher so the first login is not also paying JIT and wasm setup.
  await initDummyHash();

  const httpServer = createServer();
  const io = createIo(httpServer);
  const app = createApp(ioStats(io));
  httpServer.on('request', app);

  // Close slowloris-shaped holes: a connection that never finishes its headers
  // otherwise occupies a socket indefinitely.
  httpServer.requestTimeout = 30_000;
  httpServer.headersTimeout = 20_000;
  httpServer.keepAliveTimeout = 65_000;

  await new Promise<void>((resolve) => httpServer.listen(env.PORT, resolve));
  log.info({ port: env.PORT, env: env.NODE_ENV }, 'server listening');

  /**
   * Graceful shutdown.
   *
   * Telling clients we are draining first means they reconnect on their own
   * jittered backoff instead of stampeding the replacement process the
   * instant it binds.
   */
  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info({ signal }, 'shutting down');
    io.emit('server:draining', { retryAfterMs: 3000 });

    const hardKill = setTimeout(() => {
      log.error('shutdown timed out; forcing exit');
      process.exit(1);
    }, 10_000);
    hardKill.unref();

    await new Promise<void>((resolve) => io.close(() => resolve()));
    await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    await disconnectDb();
    clearTimeout(hardKill);
    log.info('shutdown complete');
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => log.error({ reason }, 'unhandled rejection'));
}

main().catch((err) => {
  log.fatal({ err }, 'failed to start');
  process.exit(1);
});
