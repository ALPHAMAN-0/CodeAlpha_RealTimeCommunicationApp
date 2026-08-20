/**
 * Integration-test environment.
 *
 * Runs BEFORE any test module is imported, because config/env.ts validates
 * process.env at import time and calls process.exit(1) on failure — which is
 * the behaviour we want in production and which would otherwise kill the test
 * runner with no explanation.
 */
import { generateKeyPairSync, randomBytes } from 'node:crypto';

const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const b64 = (n: number) => randomBytes(n).toString('base64');
const pem = (k: { export: (o: never) => string | Buffer }, type: 'pkcs8' | 'spki') =>
  Buffer.from(k.export({ type, format: 'pem' } as never) as string).toString('base64');

Object.assign(process.env, {
  NODE_ENV: 'test',
  // Silent by default so passing runs are readable; override from the shell
  // (LOG_LEVEL=error pnpm test) when a test fails for a non-obvious reason.
  LOG_LEVEL: process.env.LOG_LEVEL ?? 'silent',
  // PORT is intentionally left at its default: the test server binds port 0
  // directly via http.listen, so this value is never used.
  // Overwritten per-suite by the in-memory server's real URI.
  MONGO_URI: process.env.MONGO_URI ?? 'mongodb://127.0.0.1:27017/rtc-test',
  APP_ORIGIN: 'http://localhost:5173',
  ALLOWED_ORIGINS: 'http://localhost:5173',
  COOKIE_SAMESITE: 'strict',
  TRUST_PROXY: '0',
  JWT_PRIVATE_KEY_B64: pem(privateKey as never, 'pkcs8'),
  JWT_PUBLIC_KEY_B64: pem(publicKey as never, 'spki'),
  JWT_KID: 'test',
  CSRF_KEY: b64(32),
  PASSWORD_PEPPER: b64(32),
  DATA_ENCRYPTION_KEY: b64(32),
  BLIND_INDEX_KEY: b64(32),
  IP_HASH_KEY: b64(32),
  ENUM_KEY: b64(32),
  ACCESS_TOKEN_TTL_S: '600',
  // Rate limits are exercised by their own dedicated test, which re-enables
  // them explicitly. Leaving them on globally would make every other test's
  // outcome depend on how many tests ran before it.
  RATE_LIMIT_DISABLED: 'true',
  DEMO_MODE: 'false',
  SERVE_STATIC: 'false',
});
