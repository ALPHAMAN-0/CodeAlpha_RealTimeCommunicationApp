import { openDB, type IDBPDatabase } from 'idb';
import type { IdentityPrivate } from '@rtc/crypto';

/**
 * Local key storage.
 *
 * The identity private keys are stored as NON-EXTRACTABLE CryptoKey objects.
 * `CryptoKey` is structured-cloneable, so IndexedDB can hold the handle
 * itself rather than raw bytes — which means injected script can *use* the key
 * while the page is alive but cannot exfiltrate it for offline or future
 * decryption.
 *
 * That is a genuine reduction in blast radius, not elimination: an XSS that
 * survives can still read and send as the victim while it runs. The honest
 * framing is in SECURITY.md.
 */
const DB_NAME = 'rtc-keystore';
const DB_VERSION = 1;
const KEYS = 'keys';
const PINS = 'pins';
const META = 'meta';

let dbPromise: Promise<IDBPDatabase> | undefined;

const db = (): Promise<IDBPDatabase> => {
  dbPromise ??= openDB(DB_NAME, DB_VERSION, {
    upgrade(database) {
      if (!database.objectStoreNames.contains(KEYS)) database.createObjectStore(KEYS);
      if (!database.objectStoreNames.contains(PINS)) database.createObjectStore(PINS);
      if (!database.objectStoreNames.contains(META)) database.createObjectStore(META);
    },
  });
  return dbPromise;
};

interface StoredIdentity {
  userId: string;
  keyVersion: number;
  agreePriv: CryptoKey;
  signPriv: CryptoKey;
}

export async function saveIdentity(userId: string, keyVersion: number, priv: IdentityPrivate): Promise<void> {
  const store: StoredIdentity = {
    userId,
    keyVersion,
    agreePriv: priv.agreePriv as CryptoKey,
    signPriv: priv.signPriv as CryptoKey,
  };
  await (await db()).put(KEYS, store, `identity:${userId}`);
}

export async function loadIdentity(userId: string): Promise<{ priv: IdentityPrivate; keyVersion: number } | undefined> {
  const stored = (await (await db()).get(KEYS, `identity:${userId}`)) as StoredIdentity | undefined;
  if (!stored) return undefined;
  return {
    priv: { agreePriv: stored.agreePriv as never, signPriv: stored.signPriv as never },
    keyVersion: stored.keyVersion,
  };
}

export async function clearIdentity(userId: string): Promise<void> {
  await (await db()).delete(KEYS, `identity:${userId}`);
}

/**
 * Trust-on-first-use pins.
 *
 * The first fingerprint seen for a peer is remembered. A later change means
 * either a legitimate key rotation or a server substituting a key — the client
 * cannot tell, so it must stop and ask rather than silently accepting.
 */
export async function pinnedFingerprint(peerId: string): Promise<string | undefined> {
  return (await (await db()).get(PINS, peerId)) as string | undefined;
}

export async function pinFingerprint(peerId: string, fingerprint: string): Promise<void> {
  await (await db()).put(PINS, fingerprint, peerId);
}

export type TrustVerdict = 'first-seen' | 'unchanged' | 'CHANGED';

/**
 * Compare a peer's fingerprint against what we pinned.
 *
 * Returning a distinct 'CHANGED' rather than a boolean is deliberate: the
 * caller must be forced to handle it, because the correct response is to block
 * sending and show a warning, not to fall through to the happy path.
 */
export async function checkTrust(peerId: string, fingerprint: string): Promise<TrustVerdict> {
  const pinned = await pinnedFingerprint(peerId);
  if (pinned === undefined) {
    await pinFingerprint(peerId, fingerprint);
    return 'first-seen';
  }
  return pinned === fingerprint ? 'unchanged' : 'CHANGED';
}

/** Explicit re-verification after the user confirms a safety number. */
export async function acceptNewFingerprint(peerId: string, fingerprint: string): Promise<void> {
  await pinFingerprint(peerId, fingerprint);
}

export async function setMeta(key: string, value: unknown): Promise<void> {
  await (await db()).put(META, value, key);
}

export async function getMeta<T>(key: string): Promise<T | undefined> {
  return (await (await db()).get(META, key)) as T | undefined;
}

/** Full local wipe on logout. */
export async function wipeKeystore(): Promise<void> {
  const d = await db();
  await Promise.all([d.clear(KEYS), d.clear(PINS), d.clear(META)]);
}
