import {
  DEFAULT_KDF_PARAMS, b64uEncode, deriveAccountSecrets, deriveRecoveryKek,
  exportPublicKeys, generateIdentity, generateRecoveryCode, newKdfSalt,
  openIdentity, sealIdentity, signKeyRecord, type IdentityPrivate,
} from '@rtc/crypto';
import type { KdfParams, WrappedIdentity } from '@rtc/shared';
import {
  announceLogout, clearAccessToken, refreshSession, request, setAccessToken,
  type SessionResponse,
} from '../lib/api.js';
import { clearIdentity, loadIdentity, saveIdentity, wipeKeystore } from './keystore.js';

export interface AccountUser {
  id: string;
  displayName: string;
  avatarColor: string;
  keyVersion: number;
  email?: string;
}

export interface Session {
  user: AccountUser;
  priv: IdentityPrivate;
}

/** 24 hex chars, generated client-side — see the register schema for why. */
const newAccountId = (): string =>
  Array.from(crypto.getRandomValues(new Uint8Array(12)))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

export interface RegisterResult {
  session: Session;
  /**
   * Shown EXACTLY once and never recoverable.
   *
   * Without it, a forgotten password destroys message history permanently —
   * the server cannot help, because it never held the key. That is not a
   * limitation to hide; it is what end-to-end encryption means.
   */
  recoveryCode: string;
}

export async function register(
  email: string,
  displayName: string,
  password: string,
): Promise<RegisterResult> {
  const userId = newAccountId();
  const kdfSalt = newKdfSalt();
  const kdfParams: KdfParams = DEFAULT_KDF_PARAMS;

  const { authProof, kek } = await deriveAccountSecrets(password, kdfSalt, kdfParams);
  const kp = await generateIdentity();
  const pub = await exportPublicKeys(kp);
  const publicKeys = await signKeyRecord(
    userId, { ...pub, keyVersion: 1, createdAt: Date.now() }, kp.sign.privateKey,
  );

  const recoveryCode = generateRecoveryCode();
  const recoverySalt = newKdfSalt();
  const passwordWrap = await sealIdentity(kp, kek, {
    userId, keyVersion: 1, kdfSalt, kdfParams, purpose: 'password',
  });
  const recoveryWrap = await sealIdentity(
    kp, await deriveRecoveryKek(recoveryCode, recoverySalt),
    { userId, keyVersion: 1, kdfSalt: recoverySalt, kdfParams, purpose: 'recovery' },
  );

  const res = await request<SessionResponse>('/api/auth/register', {
    method: 'POST',
    body: {
      userId, email, displayName,
      authProof: b64uEncode(authProof),
      kdfSalt: b64uEncode(kdfSalt),
      kdfParams,
      identity: { publicKeys, passwordWrap, recoveryWrap },
    },
  });

  setAccessToken(res.accessToken, res.accessExpiresAt);
  const priv = await openIdentity(passwordWrap, kek, { userId, purpose: 'password' });
  await saveIdentity(userId, 1, priv);
  return { session: { user: res.user, priv }, recoveryCode };
}

export async function login(email: string, password: string): Promise<Session> {
  /**
   * The salt and parameters have to be fetched before anything can be
   * derived, which makes this endpoint an enumeration risk. The server answers
   * for unknown addresses with a deterministic fake salt, so a wrong email
   * fails at the proof check like a wrong password rather than earlier.
   */
  const { kdfSalt, kdfParams } = await request<{ kdfSalt: string; kdfParams: KdfParams }>(
    '/api/auth/kdf-params', { method: 'POST', body: { email } },
  );
  const saltBytes = Uint8Array.from(atob(kdfSalt.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const { authProof, kek } = await deriveAccountSecrets(password, saltBytes, kdfParams);

  const res = await request<SessionResponse>('/api/auth/login', {
    method: 'POST',
    body: { email, authProof: b64uEncode(authProof) },
  });
  setAccessToken(res.accessToken, res.accessExpiresAt);

  const priv = await openIdentity(res.identity.passwordWrap, kek, {
    userId: res.user.id, purpose: 'password',
  });
  await saveIdentity(res.user.id, res.user.keyVersion, priv);
  return { user: res.user, priv };
}

/**
 * Restore a session on page load.
 *
 * Two halves have to line up: the refresh cookie gets a new access token, and
 * IndexedDB supplies the identity keys. If the cookie is alive but the keys
 * are gone (different browser profile, cleared storage) the user is signed in
 * but cannot decrypt anything — so that case is treated as no session at all
 * and the password is asked for again.
 */
export async function restore(): Promise<Session | undefined> {
  if (!(await refreshSession())) return undefined;

  const me = await request<{ user: AccountUser; identity: { passwordWrap: WrappedIdentity } }>(
    '/api/auth/me',
  ).catch(() => undefined);
  if (!me) return undefined;

  const stored = await loadIdentity(me.user.id);
  if (!stored) return undefined;
  return { user: me.user, priv: stored.priv };
}

export async function recoverWithCode(
  recoveryCode: string,
  wrap: WrappedIdentity,
  userId: string,
): Promise<IdentityPrivate> {
  const saltBytes = Uint8Array.from(
    atob(wrap.kdfSalt.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0),
  );
  const kek = await deriveRecoveryKek(recoveryCode, saltBytes);
  const priv = await openIdentity(wrap, kek, { userId, purpose: 'recovery' });
  await saveIdentity(userId, wrap.keyVersion, priv);
  return priv;
}

export async function logout(userId?: string): Promise<void> {
  await request('/api/auth/logout', { method: 'POST' }).catch(() => undefined);
  clearAccessToken();
  announceLogout();
  // Wipe local keys: leaving non-extractable handles behind after an explicit
  // sign-out on a shared machine would be indefensible.
  if (userId) await clearIdentity(userId);
  await wipeKeystore();
}
