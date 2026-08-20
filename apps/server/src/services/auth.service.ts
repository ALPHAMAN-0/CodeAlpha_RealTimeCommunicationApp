import { createHash } from 'node:crypto';
import { Types } from 'mongoose';
import type { KdfParams, PublicKeyRecord, WrappedIdentity } from '@rtc/shared';
import { env } from '../config/env.js';
import { securityLog } from '../config/logger.js';
import { RefreshToken, User, type UserDoc } from '../db/models/index.js';
import { blindIndex, openField, sealField } from '../crypto/sealedField.js';
import {
  csrfTokenFor, fakeSaltFor, hashRefreshToken, newFamilyId,
  newRefreshToken, signAccessToken,
} from '../crypto/tokens.js';
import { hashProof, verifyAgainstDummy, verifyProof } from '../crypto/passwords.js';

export class AuthError extends Error {
  constructor(
    readonly code:
      | 'INVALID_CREDENTIALS' | 'EMAIL_TAKEN' | 'REFRESH_INVALID'
      | 'REFRESH_REUSE' | 'ACCOUNT_LOCKED',
    message: string,
    readonly retryAfterSeconds?: number,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export interface IssuedTokens {
  accessToken: string;
  accessExpiresAt: number;
  refreshToken: string;
  refreshExpiresAt: Date;
  csrfToken: string;
  familyId: string;
}

export interface ClientMeta {
  uaHash?: string;
  ipHash?: string;
}

/**
 * Hook for the realtime layer to drop sockets when a session dies.
 *
 * Registered at startup rather than imported, so the auth service has no
 * dependency on Socket.IO and stays trivially testable.
 */
type SessionKiller = (familyId: string, reason: 'revoked' | 'rate-banned') => void;
let killSessions: SessionKiller = () => {};
export const onSessionRevoked = (fn: SessionKiller): void => {
  killSessions = fn;
};

/**
 * Successors cached for the grace window below.
 *
 * Deliberately in-memory and process-local: it exists to absorb a
 * double-submit within a few seconds, not to be durable. Losing it on restart
 * costs one spurious logout at worst.
 */
const GRACE_MS = 10_000;
const successorCache = new Map<string, { tokens: IssuedTokens; at: number }>();

function cacheSuccessor(usedHash: string, tokens: IssuedTokens): void {
  successorCache.set(usedHash, { tokens, at: Date.now() });
  // Opportunistic sweep — no timer, so nothing keeps the process alive.
  if (successorCache.size > 500) {
    const cutoff = Date.now() - GRACE_MS;
    for (const [k, v] of successorCache) if (v.at < cutoff) successorCache.delete(k);
  }
}

function takeSuccessor(usedHash: string): IssuedTokens | undefined {
  const hit = successorCache.get(usedHash);
  if (!hit) return undefined;
  if (Date.now() - hit.at > GRACE_MS) {
    successorCache.delete(usedHash);
    return undefined;
  }
  return hit.tokens;
}

/** Test hook: the cache is module state, so suites must be able to reset it. */
export const __resetGraceCache = (): void => successorCache.clear();

const AVATAR_COLORS = [
  '#e11d48', '#db2777', '#c026d3', '#7c3aed', '#4f46e5',
  '#2563eb', '#0891b2', '#059669', '#65a30d', '#ea580c',
];

/** Stable per-account colour, so avatars never shuffle between sessions. */
const colorFor = (id: string): string =>
  AVATAR_COLORS[createHash('sha256').update(id).digest()[0]! % AVATAR_COLORS.length]!;

async function issueTokens(
  userId: string,
  meta: ClientMeta,
  existing?: { familyId: string; familyExpiresAt: Date; prevTokenHash: string },
): Promise<IssuedTokens> {
  const now = Date.now();
  const familyId = existing?.familyId ?? newFamilyId();
  const familyExpiresAt = existing?.familyExpiresAt ?? new Date(now + env.REFRESH_ABSOLUTE_TTL_S * 1000);
  const refreshToken = newRefreshToken();
  // The individual token slides, but never past the family's hard ceiling.
  const refreshExpiresAt = new Date(
    Math.min(now + env.REFRESH_TOKEN_TTL_S * 1000, familyExpiresAt.getTime()),
  );

  await RefreshToken.create({
    userId: new Types.ObjectId(userId),
    familyId,
    tokenHash: hashRefreshToken(refreshToken),
    ...(existing ? { prevTokenHash: existing.prevTokenHash } : {}),
    issuedAt: new Date(now),
    expiresAt: refreshExpiresAt,
    familyExpiresAt,
    ...(meta.uaHash ? { uaHash: meta.uaHash } : {}),
    ...(meta.ipHash ? { ipHash: meta.ipHash } : {}),
  });

  const { token: accessToken, expiresAt: accessExpiresAt } = await signAccessToken(userId, familyId);
  return {
    accessToken,
    accessExpiresAt,
    refreshToken,
    refreshExpiresAt,
    csrfToken: csrfTokenFor(familyId),
    familyId,
  };
}

export interface RegisterInput {
  /** Client-generated ObjectId; see registerBodySchema for why. */
  userId: string;
  email: string;
  displayName: string;
  authProof: string;
  kdfSalt: string;
  kdfParams: KdfParams;
  identity: {
    publicKeys: PublicKeyRecord;
    passwordWrap: WrappedIdentity;
    recoveryWrap: WrappedIdentity;
  };
}

export async function register(input: RegisterInput, meta: ClientMeta): Promise<{ user: UserDoc & { _id: Types.ObjectId }; tokens: IssuedTokens }> {
  const _id = new Types.ObjectId(input.userId);
  const emailIndex = blindIndex(input.email);

  /**
   * The server deliberately does NOT verify the published key log's
   * signatures.
   *
   * Clients must verify them regardless — the whole design treats this server
   * as untrusted — so checking here would add cost while creating the
   * impression that a server-side check means something. The one thing the
   * server does enforce is append-only: it never deletes a key record and
   * never lowers a version, which is what makes client-side tamper detection
   * possible.
   */
  if (await User.exists({ _id })) {
    throw new AuthError('EMAIL_TAKEN', 'That account id is already registered');
  }

  // Check first for a friendly error, but the unique index below is the real
  // guarantee — two simultaneous registrations must not both succeed.
  if (await User.exists({ emailIndex })) {
    throw new AuthError('EMAIL_TAKEN', 'That email is already registered');
  }

  const proofHash = await hashProof(input.authProof);
  try {
    const user = await User.create({
      _id,
      emailSealed: sealField(input.email, 'users', 'email', _id.toHexString()),
      emailIndex,
      displayName: input.displayName,
      avatarColor: colorFor(_id.toHexString()),
      proofHash,
      kdfSalt: input.kdfSalt,
      kdfParams: input.kdfParams,
      keyLog: [input.identity.publicKeys],
      keyVersion: input.identity.publicKeys.keyVersion,
      passwordWrap: input.identity.passwordWrap,
      recoveryWrap: input.identity.recoveryWrap,
      presence: { status: 'offline', lastSeenAt: new Date() },
    });
    securityLog.info({ userId: _id.toHexString(), ...meta }, 'register success');
    const tokens = await issueTokens(_id.toHexString(), meta);
    return { user: user as UserDoc & { _id: Types.ObjectId }, tokens };
  } catch (err) {
    if ((err as { code?: number }).code === 11000) {
      throw new AuthError('EMAIL_TAKEN', 'That email is already registered');
    }
    throw err;
  }
}

/**
 * The client needs the account's KDF salt and parameters before it can derive
 * anything, which makes this endpoint an enumeration risk.
 *
 * An unknown email therefore gets a DETERMINISTIC fake salt plus the default
 * parameters — indistinguishable from a real account. Determinism matters as
 * much as plausibility: a fresh random salt on each request would itself
 * reveal that no account exists.
 */
export async function getKdfParams(email: string): Promise<{ kdfSalt: string; kdfParams: KdfParams }> {
  const user = await User.findOne({ emailIndex: blindIndex(email) })
    .select({ kdfSalt: 1, kdfParams: 1 })
    .lean();
  if (user) return { kdfSalt: user.kdfSalt, kdfParams: user.kdfParams as KdfParams };
  return {
    kdfSalt: fakeSaltFor(email),
    kdfParams: { kdf: 'argon2id', memoryKiB: 65_536, iterations: 3, parallelism: 1 },
  };
}

/** Progressive per-account delay, so rotating IPs does not bypass the limit. */
const lockoutMs = (failures: number): number =>
  failures < 5 ? 0 : Math.min(2 ** (failures - 5) * 30_000, 15 * 60_000);

export async function login(
  email: string,
  authProof: string,
  meta: ClientMeta,
): Promise<{ user: UserDoc & { _id: Types.ObjectId }; tokens: IssuedTokens }> {
  const user = await User.findOne({ emailIndex: blindIndex(email) });

  if (!user) {
    // Same work, same shape, same timing as a wrong password. Returning early
    // here would make login response time an enumeration oracle.
    await verifyAgainstDummy(authProof);
    securityLog.warn({ ...meta }, 'login failed: unknown account');
    throw new AuthError('INVALID_CREDENTIALS', 'Incorrect email or password');
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > Date.now()) {
    const retryAfterSeconds = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000);
    securityLog.warn({ userId: user.id, retryAfterSeconds, ...meta }, 'login blocked: locked out');
    throw new AuthError('ACCOUNT_LOCKED', 'Too many failed attempts', retryAfterSeconds);
  }

  if (!(await verifyProof(user.proofHash, authProof))) {
    const failures = user.failedLogins + 1;
    const delay = lockoutMs(failures);
    await User.updateOne(
      { _id: user._id },
      { $set: { failedLogins: failures, ...(delay ? { lockedUntil: new Date(Date.now() + delay) } : {}) } },
    );
    securityLog.warn({ userId: user.id, failures, ...meta }, 'login failed: bad proof');
    throw new AuthError('INVALID_CREDENTIALS', 'Incorrect email or password');
  }

  if (user.failedLogins > 0 || user.lockedUntil) {
    await User.updateOne({ _id: user._id }, { $set: { failedLogins: 0 }, $unset: { lockedUntil: 1 } });
  }

  securityLog.info({ userId: user.id, ...meta }, 'login success');
  const tokens = await issueTokens(user.id as string, meta);
  return { user: user as UserDoc & { _id: Types.ObjectId }, tokens };
}

/**
 * Rotate a refresh token, detecting reuse.
 *
 * The order of checks matters, and so does the grace window. Two tabs or a
 * retried request can legitimately present the same token twice; without the
 * window, correct reuse detection reads to the user as "the app randomly
 * logged me out". Within 10 seconds the original successor is returned
 * idempotently instead of nuking the family.
 */
export async function refresh(
  presented: string,
  meta: ClientMeta,
): Promise<{ tokens: IssuedTokens; userId: string }> {
  const tokenHash = hashRefreshToken(presented);
  const row = await RefreshToken.findOne({ tokenHash });

  if (!row) {
    securityLog.warn({ ...meta }, 'refresh rejected: unknown token');
    throw new AuthError('REFRESH_INVALID', 'Session expired');
  }
  if (row.revokedAt) {
    securityLog.warn({ userId: String(row.userId), reason: row.revokedReason, ...meta }, 'refresh rejected: revoked');
    throw new AuthError('REFRESH_INVALID', 'Session expired');
  }
  const now = Date.now();
  if (row.expiresAt.getTime() < now || row.familyExpiresAt.getTime() < now) {
    throw new AuthError('REFRESH_INVALID', 'Session expired');
  }

  if (row.usedAt) {
    const cached = takeSuccessor(tokenHash);
    if (cached) {
      // Benign double-submit: hand back the exact same successor pair.
      securityLog.debug({ userId: String(row.userId) }, 'refresh served from grace window');
      return { tokens: cached, userId: String(row.userId) };
    }
    // Genuine reuse. Revoke the whole family and cut every live socket on it:
    // both the thief and the victim are logged out, which is the intended
    // outcome — the alternative is letting a stolen token keep working.
    await RefreshToken.updateMany(
      { familyId: row.familyId, revokedAt: null },
      { $set: { revokedAt: new Date(), revokedReason: 'reuse' } },
    );
    killSessions(row.familyId, 'revoked');
    securityLog.error({ userId: String(row.userId), familyId: row.familyId, ...meta }, 'refresh REUSE detected: family revoked');
    throw new AuthError('REFRESH_REUSE', 'Session revoked for security');
  }

  const tokens = await issueTokens(String(row.userId), meta, {
    familyId: row.familyId,
    familyExpiresAt: row.familyExpiresAt,
    prevTokenHash: tokenHash,
  });
  await RefreshToken.updateOne(
    { _id: row._id },
    { $set: { usedAt: new Date(), replacedByHash: hashRefreshToken(tokens.refreshToken) } },
  );
  cacheSuccessor(tokenHash, tokens);
  return { tokens, userId: String(row.userId) };
}

/**
 * Look up which refresh family a token belongs to, WITHOUT consuming it.
 *
 * Exists so the CSRF check can run before rotation. Deliberately returns
 * nothing for a revoked or expired row, so a dead token cannot be used to
 * probe for a live family id.
 */
export async function familyForToken(presented: string): Promise<string | undefined> {
  const row = await RefreshToken.findOne({ tokenHash: hashRefreshToken(presented), revokedAt: null })
    .select({ familyId: 1 })
    .lean();
  return row?.familyId;
}

export async function logout(presented: string | undefined): Promise<void> {
  if (!presented) return;
  const row = await RefreshToken.findOne({ tokenHash: hashRefreshToken(presented) }).select({ familyId: 1, userId: 1 });
  if (!row) return;
  await RefreshToken.updateMany(
    { familyId: row.familyId, revokedAt: null },
    { $set: { revokedAt: new Date(), revokedReason: 'logout' } },
  );
  killSessions(row.familyId, 'revoked');
  securityLog.info({ userId: String(row.userId), familyId: row.familyId }, 'logout');
}

export async function logoutAll(userId: string): Promise<void> {
  const families = await RefreshToken.distinct('familyId', {
    userId: new Types.ObjectId(userId),
    revokedAt: null,
  });
  await RefreshToken.updateMany(
    { userId: new Types.ObjectId(userId), revokedAt: null },
    { $set: { revokedAt: new Date(), revokedReason: 'logout-all' } },
  );
  for (const f of families) killSessions(String(f), 'revoked');
  securityLog.info({ userId, families: families.length }, 'logout-all');
}

/**
 * Change the password.
 *
 * The new proof and the re-wrapped identity are applied in ONE update. If they
 * could diverge, a user would end up able to log in but unable to decrypt
 * anything they had ever sent — an unrecoverable state, since the server
 * cannot re-wrap the key itself.
 */
export async function changePassword(
  userId: string,
  input: { oldAuthProof: string; newAuthProof: string; kdfSalt: string; kdfParams: KdfParams; passwordWrap: WrappedIdentity },
): Promise<void> {
  const user = await User.findById(userId);
  if (!user) throw new AuthError('INVALID_CREDENTIALS', 'Incorrect password');
  if (!(await verifyProof(user.proofHash, input.oldAuthProof))) {
    throw new AuthError('INVALID_CREDENTIALS', 'Incorrect password');
  }
  await User.updateOne(
    { _id: user._id },
    {
      $set: {
        proofHash: await hashProof(input.newAuthProof),
        kdfSalt: input.kdfSalt,
        kdfParams: input.kdfParams,
        passwordWrap: input.passwordWrap,
      },
    },
  );
  // Every other session is now holding a KEK that no longer matches.
  await logoutAll(userId);
  securityLog.info({ userId }, 'password changed');
}

/** Decrypt a user's email — only for the account owner's own /me response. */
export const emailOf = (user: { _id: Types.ObjectId; emailSealed: Buffer }): string =>
  openField(user.emailSealed, 'users', 'email', user._id.toHexString());
