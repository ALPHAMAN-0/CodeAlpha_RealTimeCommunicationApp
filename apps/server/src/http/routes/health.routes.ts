import { Router } from 'express';
import { env } from '../../config/env.js';
import { dbReady, pingDb } from '../../db/connect.js';
import { hasherStats } from '../../crypto/passwords.js';

export interface RuntimeStats {
  sockets: () => { connected: number; rooms: number };
  activeCalls: () => number;
}

export function healthRoutes(stats?: RuntimeStats): Router {
  const r = Router();

  /**
   * Liveness only — deliberately checks no dependencies.
   *
   * If this probed Mongo, a brief database blip would make the orchestrator
   * kill and restart a perfectly healthy process, turning a short outage into
   * a restart loop.
   */
  r.get('/', (_req, res) => {
    res.json({ status: 'ok', uptimeSec: Math.round(process.uptime()) });
  });

  /**
   * Public client configuration.
   *
   * Deliberately unauthenticated, because the sign-in screen needs it BEFORE
   * anyone is signed in — reading demo mode from /api/auth/me meant the demo
   * buttons could never appear, which is the one moment they are useful.
   *
   * Only non-sensitive feature flags belong here. Nothing in this response
   * should ever be something an anonymous caller must not know.
   */
  r.get('/config', (_req, res) => {
    res.json({
      demoMode: env.DEMO_MODE,
      maxUploadBytes: env.MAX_UPLOAD_BYTES,
      maxCallParticipants: env.MAX_CALL_PARTICIPANTS,
      relayAvailable: Boolean(env.TURN_HOST && env.TURN_STATIC_AUTH_SECRET),
    });
  });

  /** Readiness: gates the seed container and the Docker healthcheck. */
  r.get('/ready', async (_req, res) => {
    const mongo = dbReady() ? await pingDb() : { ok: false, latencyMs: 0 };
    const ready = mongo.ok;
    res.status(ready ? 200 : 503).json({
      status: ready ? 'ready' : 'not-ready',
      env: env.NODE_ENV,
      uptimeSec: Math.round(process.uptime()),
      mongo,
      hasher: hasherStats(),
      ...(stats ? { sockets: stats.sockets(), activeCalls: stats.activeCalls() } : {}),
    });
  });

  return r;
}
