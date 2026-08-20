import type { RequestHandler } from 'express';
import { env } from '../../config/env.js';
import { securityLog } from '../../config/logger.js';
import { verifyCsrfToken } from '../../crypto/tokens.js';

export const CSRF_HEADER = 'x-csrf-token';

/**
 * Cookie names, resolved ONCE here and imported everywhere else.
 *
 * The `__Host-` prefix is a browser-enforced guarantee: the cookie is refused
 * unless it is Secure, has Path=/ and carries no Domain, which makes
 * subdomain cookie injection impossible. The prefix requires https, so
 * plain-http localhost development falls back to unprefixed names.
 *
 * This resolution lives in one module because it previously lived in two: the
 * routes set `csrf` in dev while this middleware read `__Host-csrf`, so every
 * refresh failed the double-submit check in development and would have
 * silently started working in production. Two copies of one naming rule is
 * exactly the kind of split-brain that ships.
 *
 * The condition is the ORIGIN SCHEME, deliberately not NODE_ENV. `__Host-`
 * implies `Secure`, and a browser silently discards a Secure cookie sent over
 * plain http — so keying this off NODE_ENV meant a production build served on
 * http://localhost (exactly what `docker compose up` gives you) could never
 * establish a session at all. env.ts warns at boot if a production deployment
 * is not on https, which is the real problem that check was reaching for.
 */
const usePrefix = env.APP_ORIGIN.startsWith('https://');
export const REFRESH_COOKIE = usePrefix ? '__Host-rt' : 'rt';
export const CSRF_COOKIE = usePrefix ? '__Host-csrf' : 'csrf';
export const COOKIE_PREFIX_ACTIVE = usePrefix;

/**
 * Four independent checks on the only cookie-authenticated route.
 *
 * SameSite=Strict is the primary defence, but it is not the only one: it has
 * known edge cases around browser-initiated top-level navigation, and a split
 * deployment has to relax it to `none` outright. Each check below is cheap and
 * fails closed.
 */
export const requireSameOriginPost: RequestHandler = (req, res, next) => {
  const reject = (reason: string) => {
    securityLog.warn({ reason, path: req.path }, 'csrf check failed');
    res.status(403).json({ error: { code: 'FORBIDDEN', requestId: req.requestId } });
  };

  if (req.method !== 'POST') return reject('method');

  // 1. Fetch metadata, sent by every current browser. Absent for non-browser
  //    clients, in which case the Origin check below still applies.
  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin' && fetchSite !== 'none') return reject('sec-fetch-site');

  // 2. Exact Origin match — not a prefix or suffix test, which is how
  //    "evil-example.com" gets accepted for "example.com".
  const origin = req.get('origin');
  if (origin && !env.ALLOWED_ORIGINS.includes(origin)) return reject('origin');

  // 3. Double-submit, HMAC-bound to the refresh family. Plain double-submit
  //    is defeatable by an attacker who can set cookies on the domain (e.g.
  //    from a compromised subdomain); the binding is what closes that.
  const cookieToken = (req.cookies as Record<string, string> | undefined)?.[CSRF_COOKIE];
  const headerToken = req.get(CSRF_HEADER);
  if (!cookieToken || !headerToken || cookieToken !== headerToken) return reject('double-submit');

  next();
};

/** Verify the CSRF token really belongs to the presented refresh family. */
export const csrfMatchesFamily = (req: { get(name: string): string | undefined }, familyId: string): boolean =>
  verifyCsrfToken(req.get(CSRF_HEADER), familyId);
