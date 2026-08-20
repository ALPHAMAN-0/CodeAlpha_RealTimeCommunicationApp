import { randomBytes } from 'node:crypto';
import {
  b64uEncode, deriveAccountSecrets, deriveRecoveryKek, dmRoot, exportPublicKeys,
  generateIdentity, generateRecoveryCode, importPublicKeys, newKdfSalt,
  openIdentity, sealIdentity, signKeyRecord, type IdentityPrivate,
} from '@rtc/crypto';
import type { KdfParams } from '@rtc/shared';

/** Weak on purpose: the suite runs this per user and 64 MiB/t=3 would dominate. */
export const TEST_KDF: KdfParams = { kdf: 'argon2id', memoryKiB: 8192, iterations: 1, parallelism: 1 };

export interface TestUser {
  userId: string;
  email: string;
  password: string;
  displayName: string;
  accessToken: string;
  cookies: Map<string, string>;
  priv: IdentityPrivate;
  pub: { spkiEcdh: string; spkiEcdsa: string };
  keyVersion: number;
}

const absorbCookies = (res: Response, jar: Map<string, string>) => {
  for (const raw of res.headers.getSetCookie?.() ?? []) {
    const pair = raw.split(';')[0]!;
    const i = pair.indexOf('=');
    const name = pair.slice(0, i);
    const value = pair.slice(i + 1);
    if (value === '') jar.delete(name);
    else jar.set(name, value);
  }
};

export const cookieHeader = (jar: Map<string, string>): string =>
  [...jar].map(([k, v]) => `${k}=${v}`).join('; ');

export interface ApiOptions {
  method?: string;
  body?: unknown;
  token?: string;
  jar?: Map<string, string>;
  origin?: string;
  headers?: Record<string, string>;
}

/** Thin fetch wrapper that mimics what a browser sends, including CSRF echo. */
export async function api(
  base: string,
  path: string,
  opts: ApiOptions = {},
): Promise<{ status: number; body: any; res: Response }> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    origin: opts.origin ?? 'http://localhost:5173',
    'sec-fetch-site': 'same-origin',
    ...opts.headers,
  };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.jar?.size) {
    headers.cookie = cookieHeader(opts.jar);
    const csrf = opts.jar.get('csrf') ?? opts.jar.get('__Host-csrf');
    if (csrf) headers['x-csrf-token'] = csrf;
  }
  const res = await fetch(`${base}${path}`, {
    method: opts.method ?? 'GET',
    headers,
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  });
  if (opts.jar) absorbCookies(res, opts.jar);
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null, res };
}

/**
 * Register a user through the real endpoint, doing the real client-side
 * crypto.
 *
 * Inserting rows directly would be faster and would skip exactly the code
 * most worth testing.
 */
export async function createUser(base: string, name: string): Promise<TestUser> {
  const userId = randomBytes(12).toString('hex');
  const email = `${name.toLowerCase()}-${randomBytes(4).toString('hex')}@demo.dev`;
  const password = `pw-${name}-secret`;
  const jar = new Map<string, string>();

  const kdfSalt = newKdfSalt();
  const { authProof, kek } = await deriveAccountSecrets(password, kdfSalt, TEST_KDF);
  const kp = await generateIdentity();
  const pub = await exportPublicKeys(kp);
  const publicKeys = await signKeyRecord(
    userId, { ...pub, keyVersion: 1, createdAt: Date.now() }, kp.sign.privateKey,
  );
  const recoverySalt = newKdfSalt();
  const passwordWrap = await sealIdentity(kp, kek, {
    userId, keyVersion: 1, kdfSalt, kdfParams: TEST_KDF, purpose: 'password',
  });
  const recoveryWrap = await sealIdentity(
    kp, await deriveRecoveryKek(generateRecoveryCode(), recoverySalt),
    { userId, keyVersion: 1, kdfSalt: recoverySalt, kdfParams: TEST_KDF, purpose: 'recovery' },
  );

  const res = await api(base, '/api/auth/register', {
    method: 'POST',
    jar,
    body: {
      userId, email, displayName: name,
      authProof: b64uEncode(authProof), kdfSalt: b64uEncode(kdfSalt), kdfParams: TEST_KDF,
      identity: { publicKeys, passwordWrap, recoveryWrap },
    },
  });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);

  const priv = await openIdentity(passwordWrap, kek, { userId, purpose: 'password' });
  return {
    userId, email, password, displayName: name,
    accessToken: res.body.accessToken,
    cookies: jar, priv, pub, keyVersion: 1,
  };
}

/** Shared DM root between two test users. */
export const rootBetween = async (mine: TestUser, theirs: TestUser) =>
  dmRoot(mine.priv.agreePriv, (await importPublicKeys(theirs.pub)).agreePub);

export const signPubOf = async (u: TestUser) => (await importPublicKeys(u.pub)).signPub;
