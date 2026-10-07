// Must stay the first import: config/env.ts validates process.env the moment
// it is loaded and exits the process if anything is missing.
import '../__tests__/setup.js';
import { createHmac, createPrivateKey, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';
import { env, keyBuf } from '../config/env.js';
import { csrfTokenFor, signAccessToken, verifyAccessToken, verifyCsrfToken } from './tokens.js';

const ISSUER = 'rtc-app';
const AUDIENCE = 'rtc-api';

const serverKey = (): KeyObject =>
  createPrivateKey(keyBuf(env.JWT_PRIVATE_KEY_B64).toString('utf8'));

const b64u = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');

const validClaims = () => {
  const now = Math.floor(Date.now() / 1000);
  return { sub: 'user-1', sid: 'family-1', iss: ISSUER, aud: AUDIENCE, iat: now, exp: now + 300 };
};

/** A token that is valid in every respect except the ones a test overrides. */
function mint(
  key: KeyObject,
  over: { issuer?: string; audience?: string; expiresInS?: number; claims?: Record<string, unknown> } = {},
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(over.claims ?? { sub: 'user-1', sid: 'family-1' })
    .setProtectedHeader({ alg: 'EdDSA', kid: env.JWT_KID })
    .setIssuedAt(now)
    .setIssuer(over.issuer ?? ISSUER)
    .setAudience(over.audience ?? AUDIENCE)
    .setExpirationTime(now + (over.expiresInS ?? 300))
    .sign(key);
}

describe('access tokens', () => {
  it('round-trips the subject and the session id', async () => {
    const { token, expiresAt } = await signAccessToken('user-1', 'family-1');
    const claims = await verifyAccessToken(token);
    expect(claims).toMatchObject({ sub: 'user-1', sid: 'family-1', iss: ISSUER, aud: AUDIENCE });
    expect(expiresAt).toBe(claims.exp! * 1000);
    expect(expiresAt - Date.now()).toBeLessThanOrEqual(env.ACCESS_TOKEN_TTL_S * 1000);
  });

  it('rejects a token signed with any key but the server’s', async () => {
    // The control: without it, every rejection in this file could be passing
    // because the helper mints something malformed.
    await expect(verifyAccessToken(await mint(serverKey()))).resolves.toMatchObject({ sub: 'user-1' });

    const { privateKey } = generateKeyPairSync('ed25519');
    await expect(verifyAccessToken(await mint(privateKey))).rejects.toThrow();
  });

  it('rejects any algorithm other than the pinned one', async () => {
    const unsigned = `${b64u({ alg: 'none', typ: 'JWT' })}.${b64u(validClaims())}.`;
    await expect(verifyAccessToken(unsigned)).rejects.toThrow();

    // Algorithm confusion: the verifier's PUBLIC key is not a secret, so if
    // the algorithm were negotiable an attacker could use it as an HMAC key.
    const publicPem = keyBuf(env.JWT_PUBLIC_KEY_B64).toString('utf8');
    const signingInput = `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u(validClaims())}`;
    const mac = createHmac('sha256', publicPem).update(signingInput).digest('base64url');
    await expect(verifyAccessToken(`${signingInput}.${mac}`)).rejects.toThrow();
  });

  it('rejects a token minted for another audience or by another issuer', async () => {
    await expect(verifyAccessToken(await mint(serverKey(), { audience: 'some-other-api' }))).rejects.toThrow();
    await expect(verifyAccessToken(await mint(serverKey(), { issuer: 'some-other-app' }))).rejects.toThrow();
  });

  it('rejects an expired token and a payload altered after signing', async () => {
    // Well past the 5 s clock tolerance.
    await expect(verifyAccessToken(await mint(serverKey(), { expiresInS: -60 }))).rejects.toThrow();

    const [header, , signature] = (await mint(serverKey())).split('.');
    const swapped = `${header}.${b64u({ ...validClaims(), sub: 'someone-else' })}.${signature}`;
    await expect(verifyAccessToken(swapped)).rejects.toThrow();
  });

  it('rejects a correctly signed token that carries no session id', async () => {
    // `sid` is what lets a revoked refresh family drop its live sockets.
    const token = await mint(serverKey(), { claims: { sub: 'user-1' } });
    await expect(verifyAccessToken(token)).rejects.toThrow('malformed access token claims');
  });
});

describe('CSRF token', () => {
  it('validates only for the refresh family it was issued to, and fails closed', () => {
    const token = csrfTokenFor('family-a');
    expect(verifyCsrfToken(token, 'family-a')).toBe(true);
    // A cookie/header pair lifted from another session must not validate.
    expect(verifyCsrfToken(token, 'family-b')).toBe(false);

    expect(verifyCsrfToken(undefined, 'family-a')).toBe(false);
    expect(verifyCsrfToken('', 'family-a')).toBe(false);
    expect(verifyCsrfToken(token.slice(0, -1), 'family-a')).toBe(false);
    expect(verifyCsrfToken(`${token}A`, 'family-a')).toBe(false);
  });
});
