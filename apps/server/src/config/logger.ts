import { createHmac } from 'node:crypto';
import pino from 'pino';
import { env, isProduction, keyBuf } from './env.js';

/**
 * Structured logging with an explicit redaction list.
 *
 * Ciphertext is redacted along with the obvious secrets. That is not
 * paranoia about the crypto — it is that logs are routinely shipped to
 * aggregators with weaker access control than the database, and ciphertext is
 * bulky enough to make that expensive as well as unwise.
 */
export const log = pino({
  level: env.LOG_LEVEL,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.headers["x-csrf-token"]',
      'res.headers["set-cookie"]',
      '*.password',
      '*.authProof',
      '*.oldAuthProof',
      '*.newAuthProof',
      '*.token',
      '*.accessToken',
      '*.refreshToken',
      '*.ciphertext',
      '*.ct',
      '*.wrapped',
      '*.envelope',
      '*.privateKey',
      '*.pkcs8',
      '*.sdp',
      '*.candidate',
      '*.email',
      '*.kek',
      '*.recoveryCode',
      'payload.envelope',
      'payload.accessToken',
    ],
    censor: '[redacted]',
  },
  formatters: { level: (label) => ({ level: label }) },
  base: { service: 'rtc-api' },
  ...(isProduction ? {} : { transport: { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } } }),
});

/**
 * A dedicated channel for authentication and authorization events.
 *
 * Separate from application logs so it can be retained longer and alerted on
 * without dragging along request noise.
 */
export const securityLog = log.child({ channel: 'security' });

/**
 * Store an HMAC of the client IP, never the address itself.
 *
 * Rate limiting and abuse investigation both work on a stable pseudonym, so
 * there is no reason to accumulate a plaintext database of who connected from
 * where.
 */
export const hashIp = (ip: string | undefined): string =>
  ip ? createHmac('sha256', keyBuf(env.IP_HASH_KEY)).update(ip).digest('base64url').slice(0, 22) : 'unknown';

/** Errors returned to clients carry a code and a request id — never internals. */
export const publicError = (code: string, requestId?: string) => ({
  error: { code, ...(requestId ? { requestId } : {}) },
});
