import mongoose from 'mongoose';
import { env } from '../config/env.js';
import { log } from '../config/logger.js';

/**
 * Global Mongoose hardening, applied before any model is used.
 */
export function configureMongoose(): void {
  /**
   * `sanitizeFilter` is deliberately NOT enabled. That needs justifying,
   * because it is usually recommended.
   *
   * It works by wrapping any filter value that is an object with $-prefixed
   * keys in `$eq`. It cannot tell whose operator it is looking at, so it
   * mangles the server's own `$in`, `$gt` and `$exists` exactly as readily as
   * an injected `$ne`. Living with it means wrapping every legitimate operator
   * in `mongoose.trusted()` at dozens of call sites — and that has a worse
   * failure mode than going without: a developer who wraps a USER-SUPPLIED
   * value in `trusted()` reintroduces the vulnerability while appearing to
   * have done the safe thing, and it reviews as correct.
   *
   * The actual defence is typed parsing at every boundary. Every filter value
   * in this codebase originates from a Zod-parsed primitive, and a
   * `z.string().email()` cannot become `{$ne: null}` no matter what arrives on
   * the wire. That is enforced structurally by `validate()` for HTTP and by
   * `defineHandler` for sockets, and asserted by tests at both layers.
   *
   * Additional layers that do NOT have the same footgun:
   *  - `strict: 'throw'` — writing an undeclared path is an error.
   *  - `strictQuery: true` — querying an undeclared path is an error, rather
   *    than silently matching nothing (which is how a renamed field turns
   *    into a permanently empty result set).
   *  - `$where`, `$function`, `$accumulator` and `mapReduce` are never used;
   *    they are JavaScript-evaluation sinks, not query operators.
   */
  mongoose.set('strictQuery', true);
  mongoose.set('strict', 'throw');
}

export async function connectDb(uri = env.MONGO_URI): Promise<void> {
  configureMongoose();
  mongoose.connection.on('error', (err) => log.error({ err }, 'mongo connection error'));
  mongoose.connection.on('disconnected', () => log.warn('mongo disconnected'));
  await mongoose.connect(uri, {
    serverSelectionTimeoutMS: 10_000,
    maxPoolSize: 20,
    // Fail a query rather than buffering it forever behind a dead connection.
    bufferCommands: false,
  });
  log.info({ db: mongoose.connection.name }, 'mongo connected');
}

export async function disconnectDb(): Promise<void> {
  await mongoose.disconnect();
}

export const dbReady = (): boolean => mongoose.connection.readyState === 1;

export async function pingDb(): Promise<{ ok: boolean; latencyMs: number }> {
  const started = performance.now();
  try {
    await mongoose.connection.db?.admin().command({ ping: 1 });
    return { ok: true, latencyMs: Math.round(performance.now() - started) };
  } catch {
    return { ok: false, latencyMs: Math.round(performance.now() - started) };
  }
}
