import os from 'node:os';
import { hash, verify } from '@node-rs/argon2';
import { env, keyBuf } from '../config/env.js';
import { log } from '../config/logger.js';

/**
 * Server-side Argon2id over the client's `authProof`.
 *
 * The proof is derived in the browser so the raw password never crosses the
 * wire — but it is password-EQUIVALENT, so it must still be slow-hashed here.
 * Skipping this step would make a database leak a set of working credentials
 * and turn "we hash on the client" into a downgrade rather than an upgrade.
 *
 * m=19 MiB / t=2 / p=1 is OWASP's minimum for Argon2id, chosen over the
 * alternative 46 MiB point because 19 MiB × 64 concurrent logins is already
 * ~1.2 GB and this is expected to run on a laptop and a free-tier container.
 */
/**
 * 2 === Algorithm.Argon2id.
 *
 * The library exports that as an ambient const enum, which cannot be
 * referenced under verbatimModuleSyntax, so the value is pinned here with the
 * mapping written down rather than left as a bare magic number.
 */
const ARGON2ID = 2;

const PARAMS = {
  algorithm: ARGON2ID,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
  outputLen: 32,
} as const;

/**
 * A pepper turns a database-only leak into an uncrackable one.
 *
 * Honest scope: it lives in the same .env as MONGO_URI, so it protects
 * against exfiltration of the database or a backup — not against compromise
 * of the application host.
 */
const pepper = () => keyBuf(env.PASSWORD_PEPPER);

/**
 * Bound concurrent hashing.
 *
 * Password hashing is a deliberate CPU amplifier: a few hundred concurrent
 * logins can saturate every core and stall the event loop for everyone,
 * including traffic that has nothing to do with auth. Rate limits alone do
 * not cover a distributed attempt, so requests past the limit are refused
 * with a Retry-After rather than queued indefinitely.
 */
const MAX_CONCURRENT = 4 * Math.max(1, os.availableParallelism?.() ?? os.cpus().length);
let inFlight = 0;

export class HashCapacityError extends Error {
  readonly retryAfterSeconds = 2;
  constructor() {
    super('Password hashing at capacity');
    this.name = 'HashCapacityError';
  }
}

async function withCapacity<T>(fn: () => Promise<T>): Promise<T> {
  if (inFlight >= MAX_CONCURRENT) throw new HashCapacityError();
  inFlight++;
  try {
    return await fn();
  } finally {
    inFlight--;
  }
}

export const hashProof = (proof: string): Promise<string> =>
  withCapacity(() => hash(proof, { ...PARAMS, secret: pepper() }));

export const verifyProof = (stored: string, proof: string): Promise<boolean> =>
  withCapacity(() => verify(stored, proof, { ...PARAMS, secret: pepper() }).catch(() => false));

/**
 * A real hash to verify against when the account does not exist.
 *
 * Returning early on an unknown email would make login timing a user
 * enumeration oracle: ~40 ms for "no such user" versus ~60 ms for "wrong
 * password" is trivially measurable. Doing the same work in both branches
 * removes the signal.
 */
let dummyHash: string | undefined;

export async function initDummyHash(): Promise<void> {
  dummyHash = await hashProof(Buffer.alloc(32, 0x5a).toString('base64url'));
  log.debug('password hasher warmed');
}

export async function verifyAgainstDummy(proof: string): Promise<false> {
  if (!dummyHash) dummyHash = await hashProof(Buffer.alloc(32, 0x5a).toString('base64url'));
  await verifyProof(dummyHash, proof);
  return false;
}

/** Exposed for the readiness probe, so saturation is observable. */
export const hasherStats = () => ({ inFlight, maxConcurrent: MAX_CONCURRENT });
