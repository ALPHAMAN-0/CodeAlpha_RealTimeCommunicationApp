import cors from 'cors';
import express, { type Express, type RequestHandler } from 'express';
import helmet from 'helmet';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import { env, isProduction } from '../config/env.js';
import { blindIndex } from '../crypto/sealedField.js';

/**
 * Security headers, with an honest dev/prod split.
 *
 * Vite's dev server needs inline scripts and a ws: connection for HMR.
 * Pretending one policy covers both modes gets you either a broken dev server
 * or a prod policy that only looks strict — so the difference is explicit.
 */
export function securityHeaders(): RequestHandler {
  const dev = !isProduction;
  return helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'none'"],
        /**
         * `'wasm-unsafe-eval'` is required, not optional.
         *
         * The account KDF is Argon2id compiled to WebAssembly (WebCrypto has
         * no Argon2), and `script-src 'self'` alone blocks
         * `WebAssembly.instantiate` outright — so login would fail in
         * production with a CSP violation and nothing else.
         *
         * This is the narrow directive designed for the case: it permits
         * WebAssembly compilation and specifically does NOT permit `eval()` of
         * JavaScript strings. Reaching for `'unsafe-eval'` instead would grant
         * far more than is needed.
         *
         * Worth noting how this was found: a dev server never sees this header
         * at all, because Vite serves index.html itself. Only the built,
         * single-origin deployment exercises the real policy — which is a good
         * argument for testing the production image rather than trusting that
         * dev passing means prod works.
         */
        'script-src': dev
          ? ["'self'", "'unsafe-inline'", "'wasm-unsafe-eval'"]
          : ["'self'", "'wasm-unsafe-eval'"],
        'style-src': dev ? ["'self'", "'unsafe-inline'"] : ["'self'"],
        'img-src': ["'self'", 'blob:', 'data:'],
        // blob: and mediastream: are required for video elements fed by WebRTC
        // tracks and for decrypted attachments rendered from object URLs.
        'media-src': ["'self'", 'blob:', 'mediastream:'],
        'font-src': ["'self'"],
        'connect-src': dev
          ? ["'self'", 'ws://localhost:5173', 'ws://localhost:8080', 'ws://localhost:4000']
          : ["'self'"],
        // The Argon2id KDF runs in a Worker instantiated from a blob.
        'worker-src': ["'self'", 'blob:'],
        'manifest-src': ["'self'"],
        // No HTML form ever posts anywhere in this app.
        'form-action': ["'none'"],
        'base-uri': ["'self'"],
        'frame-ancestors': ["'none'"],
        'frame-src': ["'none'"],
        'object-src': ["'none'"],
        ...(dev ? {} : { 'upgrade-insecure-requests': [] }),
      },
    },
    strictTransportSecurity: dev ? false : { maxAge: 15_552_000, includeSubDomains: true },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    xFrameOptions: { action: 'deny' },
    xContentTypeOptions: true,
    xDnsPrefetchControl: { allow: false },
  });
}

/**
 * Trusted Types, report-only first.
 *
 * This matters more here than in an ordinary app: the entire E2EE model
 * collapses under XSS, and Trusted Types eliminates the DOM-XSS sink class
 * outright rather than filtering it.
 */
export const trustedTypesReport: RequestHandler = (_req, res, next) => {
  if (isProduction) {
    res.setHeader(
      'Content-Security-Policy-Report-Only',
      "require-trusted-types-for 'script'; trusted-types default",
    );
  }
  next();
};

/**
 * CORS for /api.
 *
 * Note that Socket.IO does NOT inherit this — it needs its own allowlist plus
 * an `allowRequest` origin gate. Forgetting that second allowlist is the most
 * common Socket.IO security bug.
 */
export const apiCors = cors({
  origin: (origin, cb) => cb(null, !origin || env.ALLOWED_ORIGINS.includes(origin)),
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  maxAge: 600,
});

/** Body caps, applied before any handler can allocate on a client's behalf. */
export function bodyParsers(app: Express): void {
  app.use(express.json({ limit: '256kb', strict: true, type: 'application/json' }));
  app.use(express.urlencoded({ extended: false, limit: '16kb' }));
}

const limiter = (windowMs: number, limit: number, keyFn?: (req: express.Request) => string) =>
  rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    // env.ts refuses this flag in production, so the escape hatch cannot
    // follow the code into a real deployment.
    skip: () => env.RATE_LIMIT_DISABLED,
    ...(keyFn ? { keyGenerator: keyFn } : {}),
    handler: (req, res) => {
      res.status(429).json({ error: { code: 'RATE_LIMITED', requestId: req.requestId } });
    },
  });

/**
 * Auth-route limits.
 *
 * Login is limited per IP *and* per account. Per-IP alone is bypassed by a
 * botnet; per-account alone is bypassed by spraying many accounts. The
 * account key uses the blind index so no email is held in limiter memory.
 */
export const rateLimits = {
  register: limiter(60 * 60 * 1000, 5),
  loginPerIp: limiter(15 * 60 * 1000, 10),
  loginPerAccount: limiter(15 * 60 * 1000, 5, (req) => {
    const email = (req.body as { email?: unknown } | undefined)?.email;
    return typeof email === 'string'
      ? `acct:${blindIndex(email).toString('base64url')}`
      : ipKeyGenerator(req.ip ?? '');
  }),
  kdfParams: limiter(15 * 60 * 1000, 20),
  refresh: limiter(60 * 60 * 1000, 60),
  changePassword: limiter(60 * 60 * 1000, 5),
  upload: limiter(60 * 60 * 1000, 30),
  download: limiter(60 * 60 * 1000, 300),
  api: limiter(5 * 60 * 1000, 300),
};
