import { Router, type CookieOptions, type Response } from 'express';
import {
  changePasswordBodySchema, kdfParamsBodySchema, loginBodySchema, registerBodySchema,
  type RegisterBody,
} from '@rtc/shared';
import { env } from '../../config/env.js';
import { hashIp } from '../../config/logger.js';
import { createHash } from 'node:crypto';
import { User } from '../../db/models/index.js';
import {
  AuthError, changePassword, emailOf, familyForToken, getKdfParams, login, logout,
  logoutAll, refresh, register, type ClientMeta, type IssuedTokens,
} from '../../services/auth.service.js';
import {
  COOKIE_PREFIX_ACTIVE, CSRF_COOKIE, REFRESH_COOKIE,
  csrfMatchesFamily, requireSameOriginPost,
} from '../middleware/csrf.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { body, validate } from '../middleware/validate.js';
import { rateLimits } from '../security.js';

// Cookie names come from the csrf module, which is the single source of truth.
export const refreshCookieName = REFRESH_COOKIE;
export const csrfCookieName = CSRF_COOKIE;

const cookieBase = (): CookieOptions => ({
  secure: COOKIE_PREFIX_ACTIVE,
  sameSite: env.COOKIE_SAMESITE,
  // __Host- forbids a Domain attribute and requires Path=/, so the refresh
  // cookie cannot be scoped to /api/auth when the prefix is in use.
  path: '/',
});

function setSessionCookies(res: Response, tokens: IssuedTokens): void {
  const maxAge = tokens.refreshExpiresAt.getTime() - Date.now();
  res.cookie(refreshCookieName, tokens.refreshToken, { ...cookieBase(), httpOnly: true, maxAge });
  // Readable by JS on purpose: the client must echo it in the X-CSRF-Token header.
  res.cookie(csrfCookieName, tokens.csrfToken, { ...cookieBase(), httpOnly: false, maxAge });
}

function clearSessionCookies(res: Response): void {
  res.clearCookie(refreshCookieName, { ...cookieBase(), httpOnly: true });
  res.clearCookie(csrfCookieName, { ...cookieBase(), httpOnly: false });
}

const metaOf = (req: { get(n: string): string | undefined; ip?: string | undefined }): ClientMeta => ({
  uaHash: createHash('sha256').update(req.get('user-agent') ?? '').digest('base64url').slice(0, 22),
  ipHash: hashIp(req.ip),
});

const publicUser = (u: {
  id: string; displayName: string; avatarColor: string; keyVersion: number;
}) => ({ id: u.id, displayName: u.displayName, avatarColor: u.avatarColor, keyVersion: u.keyVersion });

export function authRoutes(): Router {
  const r = Router();

  r.post('/register', rateLimits.register, validate({ body: registerBodySchema }), async (req, res, next) => {
    try {
      const input = body<RegisterBody>(req);
      const { user, tokens } = await register(input, metaOf(req));
      setSessionCookies(res, tokens);
      res.status(201).json({
        user: publicUser(user as never),
        accessToken: tokens.accessToken,
        accessExpiresAt: tokens.accessExpiresAt,
        identity: { passwordWrap: input.identity.passwordWrap },
      });
    } catch (e) {
      next(e);
    }
  });

  /**
   * POST rather than GET so the email never lands in an access log, a proxy
   * log or a Referer header. Unknown accounts get a deterministic fake salt,
   * so the response is indistinguishable from a real one.
   */
  r.post('/kdf-params', rateLimits.kdfParams, validate({ body: kdfParamsBodySchema }), async (req, res, next) => {
    try {
      const { email } = body<{ email: string }>(req);
      res.json(await getKdfParams(email));
    } catch (e) {
      next(e);
    }
  });

  r.post(
    '/login',
    rateLimits.loginPerIp,
    rateLimits.loginPerAccount,
    validate({ body: loginBodySchema }),
    async (req, res, next) => {
      try {
        const { email, authProof } = body<{ email: string; authProof: string }>(req);
        const { user, tokens } = await login(email, authProof, metaOf(req));
        setSessionCookies(res, tokens);
        res.json({
          user: publicUser(user as never),
          accessToken: tokens.accessToken,
          accessExpiresAt: tokens.accessExpiresAt,
          // The client needs this to unwrap its identity keys locally. The
          // server holds it but cannot open it.
          identity: { passwordWrap: user.passwordWrap },
        });
      } catch (e) {
        next(e);
      }
    },
  );

  r.post('/refresh', rateLimits.refresh, requireSameOriginPost, async (req, res, next) => {
    try {
      const presented = (req.cookies as Record<string, string> | undefined)?.[refreshCookieName];
      if (!presented) {
        res.status(401).json({ error: { code: 'REFRESH_INVALID', requestId: req.requestId } });
        return;
      }
      /**
       * Bind the CSRF token to the family it was issued for, BEFORE rotating.
       *
       * Order matters: rotation is destructive. Verifying afterwards would
       * consume the presented token, fail the check, and leave the caller
       * holding a token the server has already retired — burning a valid
       * session on a failed CSRF check.
       *
       * Checking only that cookie and header match is also not enough on its
       * own: an attacker who can write cookies for the domain can inject a
       * matching pair. The HMAC binding to this specific family is what makes
       * an injected pair fail.
       */
      const familyId = await familyForToken(presented);
      if (!familyId) {
        /**
         * No live family for this token: it is unknown, expired, or its family
         * was revoked (logout, or reuse detection).
         *
         * This must be 401, not 403. The client branches on it: 401 means
         * "clear local state and sign in again", while 403 would read as a
         * malformed request and could send the client into a retry loop
         * holding a token that will never work again.
         *
         * Distinguishing the two leaks nothing useful — /api/auth carries no
         * CORS headers, so no cross-origin script can read either status.
         */
        clearSessionCookies(res);
        res.status(401).json({ error: { code: 'REFRESH_INVALID', requestId: req.requestId } });
        return;
      }
      if (!csrfMatchesFamily(req, familyId)) {
        res.status(403).json({ error: { code: 'FORBIDDEN', requestId: req.requestId } });
        return;
      }

      const { tokens, userId } = await refresh(presented, metaOf(req));

      const user = await User.findById(userId).select({ displayName: 1, avatarColor: 1, keyVersion: 1, passwordWrap: 1 });
      if (!user) {
        clearSessionCookies(res);
        res.status(401).json({ error: { code: 'REFRESH_INVALID', requestId: req.requestId } });
        return;
      }
      setSessionCookies(res, tokens);
      res.json({
        user: publicUser(user as never),
        accessToken: tokens.accessToken,
        accessExpiresAt: tokens.accessExpiresAt,
        identity: { passwordWrap: user.passwordWrap },
      });
    } catch (e) {
      if (e instanceof AuthError) clearSessionCookies(res);
      next(e);
    }
  });

  r.post('/logout', async (req, res, next) => {
    try {
      await logout((req.cookies as Record<string, string> | undefined)?.[refreshCookieName]);
      clearSessionCookies(res);
      res.status(204).end();
    } catch (e) {
      next(e);
    }
  });

  r.post('/logout-all', requireAuth, async (req, res, next) => {
    try {
      await logoutAll(req.auth!.userId);
      clearSessionCookies(res);
      res.status(204).end();
    } catch (e) {
      next(e);
    }
  });

  r.get('/me', requireAuth, async (req, res, next) => {
    try {
      const user = await User.findById(req.auth!.userId);
      if (!user) {
        res.status(404).json({ error: { code: 'NOT_FOUND', requestId: req.requestId } });
        return;
      }
      res.json({
        user: { ...publicUser(user as never), email: emailOf(user as never) },
        identity: { passwordWrap: user.passwordWrap, keyLog: user.keyLog },
        demoMode: env.DEMO_MODE,
      });
    } catch (e) {
      next(e);
    }
  });

  r.post(
    '/password',
    requireAuth,
    rateLimits.changePassword,
    validate({ body: changePasswordBodySchema }),
    async (req, res, next) => {
      try {
        await changePassword(req.auth!.userId, body(req));
        clearSessionCookies(res);
        res.status(204).end();
      } catch (e) {
        next(e);
      }
    },
  );

  return r;
}
