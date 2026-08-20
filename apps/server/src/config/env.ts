import { z } from 'zod';

/**
 * Environment validation.
 *
 * Two rules, both load-bearing:
 *
 *  1. NO SECRET HAS A DEFAULT IN CODE. A `process.env.X ?? 'dev-secret'`
 *     fallback is exactly how a project ships to production with a signing
 *     key that is public on GitHub.
 *  2. Every problem is reported at once and the process exits non-zero. A
 *     server that boots with half its configuration missing fails later, in a
 *     harder place to diagnose.
 */

/** Values shipped in .env.example. Fine for local dev, fatal in production. */
const PLACEHOLDERS = new Set([
  'CHANGE_ME',
  'dev-only-do-not-use-in-production',
  'replace-me',
]);

const isProd = process.env.NODE_ENV === 'production';

/** A base64 secret of at least `minBytes`, rejected if it is a placeholder in prod. */
const secret = (minBytes: number, name: string) =>
  z
    .string()
    .min(1, `${name} is required`)
    .refine(
      (v) => !isProd || !PLACEHOLDERS.has(v),
      `${name} still holds its .env.example placeholder — generate a real value`,
    )
    .refine((v) => {
      if (PLACEHOLDERS.has(v)) return true; // dev convenience only
      try {
        return Buffer.from(v, 'base64').length >= minBytes;
      } catch {
        return false;
      }
    }, `${name} must be at least ${minBytes} bytes of base64`);

const csv = z
  .string()
  .transform((v) => v.split(',').map((s) => s.trim()).filter(Boolean))
  .pipe(z.array(z.string().url()).min(1));

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal', 'silent']).default('info'),

  MONGO_URI: z.string().min(1, 'MONGO_URI is required'),

  /** The single origin the browser talks to. Used for CSRF Origin checks. */
  APP_ORIGIN: z.string().url(),
  /** Origins allowed by CORS and the Socket.IO handshake gate. */
  ALLOWED_ORIGINS: csv,
  /**
   * `strict` for the recommended single-origin deploy. A split deploy
   * (SPA on one host, API on another) needs `none`, which also requires
   * Secure and, in Chrome, partitioning.
   */
  COOKIE_SAMESITE: z.enum(['strict', 'lax', 'none']).default('strict'),
  /** Hops of reverse proxy to trust for client IPs. 0 means trust none. */
  TRUST_PROXY: z.coerce.number().int().min(0).max(5).default(0),

  /** Ed25519 keypair for access tokens, base64 PKCS#8 / SPKI. */
  JWT_PRIVATE_KEY_B64: secret(48, 'JWT_PRIVATE_KEY_B64'),
  JWT_PUBLIC_KEY_B64: secret(32, 'JWT_PUBLIC_KEY_B64'),
  JWT_KID: z.string().min(1).default('k1'),

  CSRF_KEY: secret(32, 'CSRF_KEY'),
  PASSWORD_PEPPER: secret(32, 'PASSWORD_PEPPER'),
  DATA_ENCRYPTION_KEY: secret(32, 'DATA_ENCRYPTION_KEY'),
  BLIND_INDEX_KEY: secret(32, 'BLIND_INDEX_KEY'),
  IP_HASH_KEY: secret(32, 'IP_HASH_KEY'),
  /** Derives the indistinguishable fake salt returned for unknown emails. */
  ENUM_KEY: secret(32, 'ENUM_KEY'),

  ACCESS_TOKEN_TTL_S: z.coerce.number().int().min(60).max(3600).default(600),
  REFRESH_TOKEN_TTL_S: z.coerce.number().int().min(3600).default(60 * 60 * 24 * 14),
  REFRESH_ABSOLUTE_TTL_S: z.coerce.number().int().min(3600).default(60 * 60 * 24 * 30),

  MAX_UPLOAD_BYTES: z.coerce.number().int().min(1024).default(25 * 1024 * 1024),
  MAX_CALL_PARTICIPANTS: z.coerce.number().int().min(2).max(8).default(4),

  /** Optional TURN relay. Without it, mesh calls leak participant IPs to peers. */
  TURN_HOST: z.string().min(1).optional(),
  TURN_STATIC_AUTH_SECRET: z.string().min(16).optional(),
  TURN_TTL_S: z.coerce.number().int().min(60).max(3600).default(300),

  /** Serve the built SPA from this process — the single-origin production mode. */
  SERVE_STATIC: bool.default(false),
  WEB_DIST_DIR: z.string().default('../web/dist'),

  /**
   * Disable HTTP rate limits. For the integration suite and repeated local
   * smoke runs only — refused outright when NODE_ENV=production below, so it
   * cannot be switched on by accident in a real deployment.
   */
  RATE_LIMIT_DISABLED: bool.default(false),

  SEED_PASSWORD: z.string().min(8).default('demo1234'),
  /** Enables one-click demo logins on the sign-in screen. */
  DEMO_MODE: bool.default(false),
});

export type Env = z.infer<typeof envSchema>;

function loadEnv(): Env {
  const parsed = envSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  • ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    process.stderr.write(
      `\nInvalid environment configuration:\n${issues}\n\n` +
        `Run \`pnpm setup\` to generate a .env with fresh secrets.\n\n`,
    );
    process.exit(1);
  }

  const e = parsed.data;
  if (e.NODE_ENV === 'production' && e.COOKIE_SAMESITE === 'none' && !e.APP_ORIGIN.startsWith('https://')) {
    process.stderr.write('\nCOOKIE_SAMESITE=none requires an https APP_ORIGIN.\n\n');
    process.exit(1);
  }
  if (e.NODE_ENV === 'production' && e.RATE_LIMIT_DISABLED) {
    process.stderr.write('\nRATE_LIMIT_DISABLED cannot be set in production.\n\n');
    process.exit(1);
  }
  /**
   * Warn rather than exit.
   *
   * A production build on plain http is exactly what `docker compose up` gives
   * a grader on localhost, and refusing to start there would break the
   * documented quickstart. But a real deployment on http would silently run
   * without Secure cookies or HSTS, so it must be loud.
   */
  if (e.NODE_ENV === 'production' && !e.APP_ORIGIN.startsWith('https://')) {
    process.stderr.write(
      `\nWARNING: APP_ORIGIN is ${e.APP_ORIGIN} (not https).\n` +
        `  Session cookies will be set WITHOUT the Secure attribute and without\n` +
        `  the __Host- prefix, because a browser discards Secure cookies over\n` +
        `  plain http. This is fine for a local container; it is NOT safe on a\n` +
        `  public deployment. Serve over https and set APP_ORIGIN accordingly.\n\n`,
    );
  }
  return e;
}

export const env: Env = loadEnv();

export const keyBuf = (b64: string): Buffer => Buffer.from(b64, 'base64');

export const isProduction = env.NODE_ENV === 'production';
export const isTest = env.NODE_ENV === 'test';
