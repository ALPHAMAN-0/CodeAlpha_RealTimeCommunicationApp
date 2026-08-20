import { createHmac } from 'node:crypto';
import { Router } from 'express';
import type { IceConfigDTO } from '@rtc/shared';
import { env } from '../../config/env.js';
import { requireAuth } from '../middleware/requireAuth.js';

/**
 * ICE configuration.
 *
 * TURN credentials are EPHEMERAL and minted per request. The static auth
 * secret must never reach a browser — shipping it would let anyone use the
 * relay indefinitely, and an open TURN server is a bandwidth bill and an
 * SSRF/port-scan pivot into the internal network.
 */
export function rtcRoutes(): Router {
  const r = Router();

  r.get('/ice', requireAuth, (req, res) => {
    const iceServers: IceConfigDTO['iceServers'] = [
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
    ];

    if (env.TURN_HOST && env.TURN_STATIC_AUTH_SECRET) {
      // coturn's REST convention: username is "<unix-expiry>:<user>" and the
      // credential is its HMAC. Short-lived by construction.
      const username = `${Math.floor(Date.now() / 1000) + env.TURN_TTL_S}:${req.auth!.userId}`;
      const credential = createHmac('sha1', env.TURN_STATIC_AUTH_SECRET).update(username).digest('base64');
      iceServers.push({
        urls: [
          `turn:${env.TURN_HOST}:3478?transport=udp`,
          `turns:${env.TURN_HOST}:5349?transport=tcp`,
        ],
        username,
        credential,
      });
    }

    const body: IceConfigDTO = {
      iceServers,
      ttlSeconds: env.TURN_TTL_S,
      /**
       * Tells the UI whether relay-only mode is even available.
       *
       * It matters because a STUN-only mesh reveals every participant's LAN
       * and public IP to every other participant. That is inherent to
       * peer-to-peer, not a bug — so it is surfaced in the interface rather
       * than buried in a README.
       */
      relayAvailable: Boolean(env.TURN_HOST && env.TURN_STATIC_AUTH_SECRET),
    };
    res.json(body);
  });

  return r;
}
