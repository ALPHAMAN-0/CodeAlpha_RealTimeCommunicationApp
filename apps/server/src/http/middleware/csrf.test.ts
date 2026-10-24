// Must stay the first import: config/env.ts validates process.env the moment
// it is loaded and exits the process if anything is missing.
import '../../__tests__/setup.js';
import type { Request, Response } from 'express';
import { describe, expect, it } from 'vitest';
import { CSRF_COOKIE, CSRF_HEADER, requireSameOriginPost } from './csrf.js';

/** The origin the test environment allows (see __tests__/setup.ts). */
const APP = 'http://localhost:5173';

interface Attempt {
  method?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
}

/** Drive the middleware with just enough of a request to exercise each check. */
function attempt({ method = 'POST', headers = {}, cookies = {} }: Attempt): { allowed: boolean; status?: number } {
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
  const req = {
    method,
    path: '/refresh',
    cookies,
    requestId: 'test-request',
    get: (name: string) => lower[name.toLowerCase()],
  } as unknown as Request;

  let status: number | undefined;
  const res = {
    status(code: number) {
      status = code;
      return this;
    },
    json() {
      return this;
    },
  } as unknown as Response;

  let allowed = false;
  requireSameOriginPost(req, res, () => {
    allowed = true;
  });
  return { allowed, ...(status !== undefined ? { status } : {}) };
}

/** What the real client sends from the app's own origin. */
const ownRequest = (over: Record<string, string> = {}, token = 'csrf-token-value'): Attempt => ({
  headers: { origin: APP, 'sec-fetch-site': 'same-origin', [CSRF_HEADER]: token, ...over },
  cookies: { [CSRF_COOKIE]: token },
});

const REFUSED = { allowed: false, status: 403 };

describe('requireSameOriginPost', () => {
  it('lets the app’s own POST through and refuses any other method', () => {
    expect(attempt(ownRequest())).toEqual({ allowed: true });
    expect(attempt({ ...ownRequest(), method: 'GET' })).toEqual(REFUSED);
  });

  it('refuses a request the browser labels cross-site or same-site', () => {
    for (const site of ['cross-site', 'same-site']) {
      expect(attempt(ownRequest({ 'sec-fetch-site': site })), site).toEqual(REFUSED);
    }
  });

  it('matches the Origin exactly, not by prefix or suffix', () => {
    for (const origin of [
      'https://evil.example',
      `${APP}.evil.example`,
      'http://evil-localhost:5173',
      'http://localhost:5174',
      'https://localhost:5173',
      'null',
    ]) {
      expect(attempt(ownRequest({ origin })), origin).toEqual(REFUSED);
    }
  });

  it('demands a matching double-submit pair, even from a client with no fetch metadata', () => {
    const { [CSRF_HEADER]: _dropped, ...withoutHeader } = ownRequest().headers!;
    expect(attempt({ ...ownRequest(), headers: withoutHeader })).toEqual(REFUSED);
    expect(attempt({ ...ownRequest(), cookies: {} })).toEqual(REFUSED);
    expect(attempt(ownRequest({ [CSRF_HEADER]: 'value-an-attacker-guessed' }))).toEqual(REFUSED);

    // Non-browser callers send neither Origin nor Sec-Fetch-Site, so those two
    // checks cannot apply to them — the token pair is what remains.
    expect(attempt({ headers: {}, cookies: {} })).toEqual(REFUSED);
    expect(attempt({ headers: { [CSRF_HEADER]: 't' }, cookies: { [CSRF_COOKIE]: 't' } })).toEqual({ allowed: true });
  });
});
