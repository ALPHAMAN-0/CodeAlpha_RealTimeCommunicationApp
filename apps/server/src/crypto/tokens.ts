import {
  createHmac, createPrivateKey, createPublicKey, randomBytes,
  createHash, timingSafeEqual, type KeyObject,
} from 'node:crypto';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { env, keyBuf } from '../config/env.js';

const ISSUER = 'rtc-app';
const AUDIENCE = 'rtc-api';

/**
 * Ed25519 keys are loaded through Node's KeyObject rather than jose's PEM
 * importer so the algorithm identifier is derived from the key itself. Passing
 * an alg string that disagrees with the key material is an easy and
 * confusing mistake to make.
 */
const privateKey: KeyObject = createPrivateKey(keyBuf(env.JWT_PRIVATE_KEY_B64).toString('utf8'));
const publicKey: KeyObject = createPublicKey(keyBuf(env.JWT_PUBLIC_KEY_B64).toString('utf8'));

export interface AccessClaims extends JWTPayload {
  sub: string;
  /** Refresh-token family id. Revoking a family kills every socket on it. */
  sid: string;
}

/**
 * Short-lived access token, held only in a JS closure on the client.
 *
 * 10 minutes is the mitigation for the fact that it is not revocable: a
 * stolen access token buys an attacker one short window, and it cannot be
 * used to mint a replacement because that requires the httpOnly refresh
 * cookie.
 */
export async function signAccessToken(userId: string, sessionId: string): Promise<{ token: string; expiresAt: number }> {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + env.ACCESS_TOKEN_TTL_S;
  const token = await new SignJWT({ sub: userId, sid: sessionId })
    .setProtectedHeader({ alg: 'EdDSA', kid: env.JWT_KID })
    .setIssuedAt(now)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setExpirationTime(exp)
    .setJti(randomBytes(16).toString('base64url'))
    .sign(privateKey);
  return { token, expiresAt: exp * 1000 };
}

/**
 * Verify an access token.
 *
 * `issuer`, `audience` and the algorithm are all pinned. Leaving any of them
 * open is how a token minted for a different service, or an `alg: none`
 * forgery, gets accepted.
 */
export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER,
    audience: AUDIENCE,
    algorithms: ['EdDSA'],
    clockTolerance: 5,
  });
  if (typeof payload.sub !== 'string' || typeof payload.sid !== 'string') {
    throw new Error('malformed access token claims');
  }
  return payload as AccessClaims;
}

/**
 * Refresh tokens are OPAQUE random bytes, not JWTs.
 *
 * Rotation and reuse detection both require a database row per token, so a
 * self-authenticating JWT would buy nothing and cost you a usable credential
 * sitting in your own database.
 */
export const newRefreshToken = (): string => randomBytes(32).toString('base64url');

/**
 * A plain SHA-256 is correct here, unlike for passwords.
 *
 * The input is 32 uniformly random bytes, so there is no guessable keyspace
 * for a slow KDF to protect. A dump of this column yields nothing usable.
 */
export const hashRefreshToken = (token: string): string =>
  createHash('sha256').update(token).digest('base64url');

export const newFamilyId = (): string => randomBytes(16).toString('base64url');

/**
 * CSRF token bound by HMAC to the refresh family.
 *
 * Plain double-submit — "the header matches the cookie" — is defeatable by an
 * attacker who can write cookies for the domain, e.g. from a compromised
 * subdomain. Binding the token to the specific family means an injected
 * cookie pair does not validate.
 */
export const csrfTokenFor = (familyId: string): string =>
  createHmac('sha256', keyBuf(env.CSRF_KEY)).update(familyId).digest('base64url');

export function verifyCsrfToken(presented: string | undefined, familyId: string): boolean {
  if (!presented) return false;
  const expected = Buffer.from(csrfTokenFor(familyId));
  const actual = Buffer.from(presented);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * Deterministic fake KDF salt for an email that has no account.
 *
 * /kdf-params has to answer before the client can even attempt a login, so a
 * "no such user" response would be a free enumeration oracle. This returns a
 * stable, plausible salt instead — stable matters, because a different salt
 * on each request would itself be the tell.
 */
export const fakeSaltFor = (email: string): string =>
  createHmac('sha256', keyBuf(env.ENUM_KEY)).update(email).digest('base64url').slice(0, 43);
