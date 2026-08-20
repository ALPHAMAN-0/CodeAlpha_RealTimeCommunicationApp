import type { RequestHandler } from 'express';
import { verifyAccessToken } from '../../crypto/tokens.js';

/**
 * Bearer-token authentication.
 *
 * The access token lives only in a JS closure on the client, never in
 * localStorage — so an XSS gets at most the ability to act while the page is
 * alive, and cannot lift a durable credential. The cost is that plain
 * `<img src>` and `<a href>` cannot authenticate, which is why file downloads
 * go through fetch and a blob: URL.
 */
export const requireAuth: RequestHandler = (req, res, next) => {
  const header = req.get('authorization');
  if (!header?.startsWith('Bearer ')) {
    res.status(401).json({ error: { code: 'UNAUTHENTICATED', requestId: req.requestId } });
    return;
  }
  verifyAccessToken(header.slice(7))
    .then((claims) => {
      req.auth = { userId: claims.sub, sessionId: claims.sid, expiresAt: (claims.exp ?? 0) * 1000 };
      next();
    })
    .catch(() => {
      // Distinguish expiry from invalidity: the client needs to know whether
      // to refresh and retry or to send the user back to the login screen.
      res.status(401).json({ error: { code: 'TOKEN_EXPIRED', requestId: req.requestId } });
    });
};

/** Non-fatal variant, for routes that behave differently when signed in. */
export const optionalAuth: RequestHandler = (req, _res, next) => {
  const header = req.get('authorization');
  if (!header?.startsWith('Bearer ')) return next();
  verifyAccessToken(header.slice(7))
    .then((claims) => {
      req.auth = { userId: claims.sub, sessionId: claims.sid, expiresAt: (claims.exp ?? 0) * 1000 };
      next();
    })
    .catch(() => next());
};
