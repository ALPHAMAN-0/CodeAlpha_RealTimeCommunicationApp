import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import { b64uDecode, b64uEncode, deriveAccountSecrets } from '@rtc/crypto';
import type { KdfParams } from '@rtc/shared';
import { __resetGraceCache } from '../services/auth.service.js';
import { startTestServer, type TestServer } from './helpers/testServer.js';
import { api, createUser, type TestUser } from './helpers/testUser.js';

let server: TestServer;
let alice: TestUser;
let bob: TestUser;

beforeAll(async () => {
  server = await startTestServer();
}, 120_000);

afterAll(async () => {
  await server?.close();
});

beforeEach(async () => {
  await server.reset();
  [alice, bob] = await Promise.all([
    createUser(server.url, 'Alice'),
    createUser(server.url, 'Bob'),
  ]);
});

type Jar = Map<string, string>;

/** A well-formed proof that belongs to no account. */
const randomProof = (): string => randomBytes(32).toString('base64url');

/** Derive the login proof the way the browser does: fetch the salt, then stretch. */
async function proofFor(user: TestUser): Promise<string> {
  const { body } = await api(server.url, '/api/auth/kdf-params', {
    method: 'POST', body: { email: user.email },
  });
  const { authProof } = await deriveAccountSecrets(
    user.password, b64uDecode(body.kdfSalt), body.kdfParams as KdfParams,
  );
  return b64uEncode(authProof);
}

const login = (email: string, authProof: string, jar?: Jar) =>
  api(server.url, '/api/auth/login', {
    method: 'POST', body: { email, authProof }, ...(jar ? { jar } : {}),
  });

/** `api` echoes the jar's csrf cookie in X-CSRF-Token, as the real client does. */
const refresh = (jar: Jar) => api(server.url, '/api/auth/refresh', { method: 'POST', jar });

describe('sign-in', () => {
  it('answers an unknown address exactly like a wrong password', async () => {
    const wrongPassword = await login(alice.email, randomProof());
    const unknownAccount = await login('nobody@demo.dev', randomProof());
    expect(wrongPassword.status).toBe(401);
    expect(unknownAccount.status).toBe(401);
    expect(wrongPassword.body.error.code).toBe('INVALID_CREDENTIALS');
    expect(unknownAccount.body.error.code).toBe('INVALID_CREDENTIALS');
    expect(Object.keys(unknownAccount.body.error).sort()).toEqual(Object.keys(wrongPassword.body.error).sort());

    // The salt lookup that precedes every login must not be the oracle either:
    // a made-up address gets a plausible salt, and the SAME one every time.
    const kdf = (email: string) =>
      api(server.url, '/api/auth/kdf-params', { method: 'POST', body: { email } });
    const [real, fake, fakeAgain, otherFake] = await Promise.all([
      kdf(alice.email), kdf('nobody@demo.dev'), kdf('nobody@demo.dev'), kdf('somebody-else@demo.dev'),
    ]);
    expect(fake.status).toBe(200);
    expect(fake.body.kdfSalt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(fakeAgain.body).toEqual(fake.body);
    expect(otherFake.body.kdfSalt).not.toBe(fake.body.kdfSalt);
    expect(Object.keys(fake.body).sort()).toEqual(Object.keys(real.body).sort());
  });

  it('issues hardened cookies and never returns stored credential material', async () => {
    const jar: Jar = new Map();
    const res = await login(alice.email, await proofFor(alice), jar);
    expect(res.status).toBe(200);
    expect(res.body.user.id).toBe(alice.userId);
    expect(JSON.stringify(res.body)).not.toMatch(/proofHash|recoveryWrap|emailSealed|emailIndex|failedLogins/);

    const cookies = res.res.headers.getSetCookie();
    const refreshCookie = cookies.find((c) => c.startsWith('rt='));
    const csrfCookie = cookies.find((c) => c.startsWith('csrf='));
    // The refresh token must be unreachable from script; the CSRF token must
    // be readable, because the client echoes it in a header.
    expect(refreshCookie).toMatch(/;\s*HttpOnly/i);
    expect(refreshCookie).toMatch(/;\s*SameSite=Strict/i);
    expect(refreshCookie).toMatch(/;\s*Path=\//i);
    expect(csrfCookie).toMatch(/;\s*SameSite=Strict/i);
    expect(csrfCookie).not.toMatch(/HttpOnly/i);
    // The refresh token is a cookie only — it is never also handed to script.
    const refreshToken = jar.get('rt');
    expect(refreshToken).toBeTruthy();
    expect(JSON.stringify(res.body)).not.toContain(refreshToken!);

    const me = await api(server.url, '/api/auth/me', { token: res.body.accessToken });
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(alice.email);
  });

  it('locks an account after five straight failures, even against the right proof', async () => {
    for (let attempt = 1; attempt <= 5; attempt++) {
      expect((await login(alice.email, randomProof())).status, `attempt ${attempt}`).toBe(401);
    }
    const locked = await login(alice.email, await proofFor(alice));
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('ACCOUNT_LOCKED');
    const retryAfter = Number(locked.res.headers.get('retry-after'));
    expect(retryAfter).toBeGreaterThan(0);
    expect(retryAfter).toBeLessThanOrEqual(30);

    // The lock is per account: nobody else is affected.
    expect((await login(bob.email, await proofFor(bob))).status).toBe(200);
  });
});

describe('refresh-token rotation', () => {
  it('revokes the whole family when a rotated token is replayed', async () => {
    const stolen: Jar = new Map(alice.cookies);
    expect((await refresh(alice.cookies)).status).toBe(200);
    expect(alice.cookies.get('rt')).not.toBe(stolen.get('rt'));

    // The 10 s double-submit grace window has passed.
    __resetGraceCache();
    const replay = await refresh(stolen);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('REFRESH_REUSE');

    // The legitimate successor dies with it. Signing the victim out is the
    // intended outcome: the alternative is a stolen token that keeps working.
    const victim = await refresh(alice.cookies);
    expect(victim.status).toBe(401);
    expect(victim.body.error.code).toBe('REFRESH_INVALID');
  });

  it('gives a benign double-submit the same successor instead of revoking', async () => {
    const tabA = alice.cookies;
    const tabB: Jar = new Map(alice.cookies);
    expect((await refresh(tabA)).status).toBe(200);

    const late = await refresh(tabB);
    expect(late.status).toBe(200);
    expect(tabB.get('rt')).toBe(tabA.get('rt'));

    // And the family is still alive afterwards.
    expect((await refresh(tabA)).status).toBe(200);
  });

  it('refuses a forged, cross-origin or unbound refresh without burning the session', async () => {
    const rt = alice.cookies.get('rt')!;

    // The cookie alone — all a forged cross-site form post could ever send.
    const bare = await api(server.url, '/api/auth/refresh', {
      method: 'POST', headers: { cookie: `rt=${rt}` },
    });
    expect(bare.status).toBe(403);

    const foreign = await api(server.url, '/api/auth/refresh', {
      method: 'POST', jar: new Map(alice.cookies), origin: 'https://evil.example',
    });
    expect(foreign.status).toBe(403);

    // A cookie/header pair that matches, but was issued to ANOTHER session.
    // Plain double-submit accepts this; the HMAC binding to the family must not.
    const injected: Jar = new Map([['rt', rt], ['csrf', bob.cookies.get('csrf')!]]);
    expect((await refresh(injected)).status).toBe(403);

    // None of the refusals consumed the token.
    expect((await refresh(alice.cookies)).status).toBe(200);
  });

  it('is revoked by logout', async () => {
    const kept: Jar = new Map(alice.cookies);
    const out = await api(server.url, '/api/auth/logout', { method: 'POST', jar: alice.cookies });
    expect(out.status).toBe(204);
    expect(alice.cookies.size).toBe(0);

    const after = await refresh(kept);
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('REFRESH_INVALID');
  });
});

describe('bearer authentication', () => {
  it('is required on every non-public API route', async () => {
    const someId = 'a'.repeat(24);
    const routes: Array<[method: string, path: string]> = [
      ['GET', '/api/auth/me'],
      ['POST', '/api/auth/logout-all'],
      ['POST', '/api/auth/password'],
      ['GET', '/api/users'],
      ['GET', '/api/conversations'],
      ['POST', '/api/conversations'],
      ['GET', `/api/conversations/${someId}/messages`],
      ['GET', `/api/keys/${alice.userId}`],
      ['POST', '/api/keys'],
      ['GET', '/api/rtc/ice'],
      ['GET', `/api/files/${someId}`],
      ['POST', `/api/files/${someId}`],
    ];
    for (const [method, path] of routes) {
      const anonymous = await api(server.url, path, { method });
      expect(anonymous.status, `${method} ${path}`).toBe(401);
      const forged = await api(server.url, path, { method, token: 'not.a.token' });
      expect(forged.status, `${method} ${path} with a forged token`).toBe(401);
    }

    // The refresh cookie is not an API credential: cookies alone never authenticate.
    const cookieOnly = await api(server.url, '/api/auth/me', { jar: new Map(alice.cookies) });
    expect(cookieOnly.status).toBe(401);
  });
});

describe('REST history paging', () => {
  it('is members-only and tolerates malformed paging parameters', async () => {
    const created = await api(server.url, '/api/conversations', {
      method: 'POST', token: alice.accessToken,
      body: { type: 'dm', memberIds: [alice.userId, bob.userId] },
    });
    expect(created.status).toBe(201);
    const history = `/api/conversations/${created.body.conversation.id}/messages`;

    // This is the one route that reads the query string by hand rather than
    // through `validate()`, so its handling of junk is pinned here: a bad
    // value is ignored, never passed on as a filter and never a 500.
    for (const query of [
      '', '?limit=10&beforeSeq=5', '?limit=1.5', '?limit=abc&beforeSeq=-1',
      '?limit=1&limit=2', '?beforeSeq[$gt]=0', '?limit=1e99',
    ]) {
      const res = await api(server.url, `${history}${query}`, { token: alice.accessToken });
      expect(res.status, query || '(no query)').toBe(200);
      expect(res.body.messages, query || '(no query)').toEqual([]);
    }

    // Knowing the conversation id is not enough to read its history.
    const carol = await createUser(server.url, 'Carol');
    const outsider = await api(server.url, history, { token: carol.accessToken });
    expect(outsider.status).toBe(403);
    expect(outsider.body.error.code).toBe('NOT_A_MEMBER');
  });
});
