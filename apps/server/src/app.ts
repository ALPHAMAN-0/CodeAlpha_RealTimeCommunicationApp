import path from 'node:path';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import express, { type Express } from 'express';
import pinoHttp from 'pino-http';
import './http/types.js';
import { env, isProduction, isTest } from './config/env.js';
import { log } from './config/logger.js';
import { authRoutes } from './http/routes/auth.routes.js';
import { conversationRoutes } from './http/routes/conversations.routes.js';
import { keysRoutes } from './http/routes/keys.routes.js';
import { filesRoutes } from './http/routes/files.routes.js';
import { rtcRoutes } from './http/routes/rtc.routes.js';
import { usersRoutes } from './http/routes/users.routes.js';
import { healthRoutes, type RuntimeStats } from './http/routes/health.routes.js';
import { errorHandler, notFound, requestId } from './http/middleware/errorHandler.js';
import { apiCors, bodyParsers, rateLimits, securityHeaders, trustedTypesReport } from './http/security.js';

export function createApp(stats?: RuntimeStats): Express {
  const app = express();

  // Never guess this high. Trusting an unvalidated X-Forwarded-For lets a
  // caller forge the key that every rate limit and IP hash is built on.
  app.set('trust proxy', env.TRUST_PROXY);
  app.disable('x-powered-by');

  app.use(requestId);
  if (!isTest) {
    app.use(
      pinoHttp({
        logger: log,
        genReqId: (req) => (req as { requestId?: string }).requestId ?? '',
        autoLogging: { ignore: (req) => req.url?.startsWith('/api/health') ?? false },
      }),
    );
  }

  app.use(securityHeaders());
  app.use(trustedTypesReport);
  app.use(compression());
  app.use(cookieParser());
  bodyParsers(app);

  // Health is mounted before the rate limiters so probes are never throttled.
  app.use('/api/health', healthRoutes(stats));

  // /api/auth gets NO CORS headers at all, so even if a cross-origin caller
  // could send a request, no cross-origin script could read the response.
  app.use('/api/auth', authRoutes());

  app.use('/api', apiCors);
  app.use('/api', rateLimits.api);

  app.use('/api/conversations', conversationRoutes());
  app.use('/api/keys', keysRoutes());
  app.use('/api/files', filesRoutes());
  app.use('/api/rtc', rtcRoutes());
  app.use('/api/users', usersRoutes());

  /**
   * Single-origin production mode: this process also serves the built SPA, so
   * the refresh cookie is same-origin and the CSP needs no exceptions.
   */
  if (env.SERVE_STATIC) {
    const dist = path.resolve(process.cwd(), env.WEB_DIST_DIR);
    app.use(
      express.static(dist, {
        index: false,
        setHeaders: (res, filePath) => {
          // Content-hashed assets are immutable; index.html must never be.
          res.setHeader(
            'Cache-Control',
            /\.[0-9a-f]{8,}\./.test(filePath) ? 'public, max-age=31536000, immutable' : 'no-cache',
          );
        },
      }),
    );
    app.get(/^(?!\/api\/).*/, (_req, res) => {
      res.sendFile(path.join(dist, 'index.html'));
    });
    log.info({ dist }, 'serving built SPA (single-origin mode)');
  }

  app.use(notFound);
  app.use(errorHandler);
  return app;
}

export const productionMode = isProduction;
