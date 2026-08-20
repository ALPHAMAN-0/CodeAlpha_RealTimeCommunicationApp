import type { EpochRecord } from '@rtc/shared';
import { emit } from '../lib/socket.js';
import { epochRoot, hasEpoch, ingestEpoch } from '../crypto/e2ee.js';
import { useSession } from '../stores/session.store.js';

/**
 * Fetch a group epoch key on demand.
 *
 * After a reload only the current epoch is in memory, but history — messages
 * and whiteboard strokes alike — can span several. Fetching lazily beats
 * downloading every epoch a room has ever had.
 */
const inFlight = new Map<string, Promise<void>>();

export async function epochRootFor(conversationId: string, epoch: number): Promise<CryptoKey> {
  const { user, priv } = useSession.getState();
  if (!user || !priv) throw new Error('not signed in');

  if (!hasEpoch(conversationId, epoch)) {
    const key = `${conversationId}:${epoch}`;
    // De-duplicate concurrent requests: replaying a board can ask for the same
    // epoch dozens of times within a single frame.
    let pending = inFlight.get(key);
    if (!pending) {
      pending = (async () => {
        const result = await emit<{ epoch: EpochRecord }>('epoch:get', { conversationId, epoch });
        await ingestEpoch(priv, user.id, conversationId, result.epoch);
      })().finally(() => inFlight.delete(key));
      inFlight.set(key, pending);
    }
    await pending;
  }

  const root = epochRoot(conversationId, epoch);
  if (!root) throw new Error(`No key for epoch ${epoch}`);
  return root;
}
