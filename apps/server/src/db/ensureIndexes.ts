import { log } from '../config/logger.js';
import {
  Attachment, Conversation, Epoch, Message, Participant, RefreshToken, User, WhiteboardOp,
} from './models/index.js';

/**
 * Build every declared index at boot and log what was created.
 *
 * Indexes declared in a schema but never actually present in the database is
 * a classic slow-burn failure: everything works on a seeded dev dataset and
 * degrades quietly under real volume. Making it loud at startup is cheap.
 */
export async function ensureIndexes(): Promise<void> {
  const models = [
    User, RefreshToken, Conversation, Participant, Message, Attachment, WhiteboardOp, Epoch,
  ] as const;

  for (const m of models) {
    const created = await m.syncIndexes();
    log.debug({ model: m.modelName, created }, 'indexes synced');
  }

  const counts = await Promise.all(
    models.map(async (m) => `${m.modelName}:${(await m.listIndexes()).length}`),
  );
  log.info({ indexes: counts.join(' ') }, 'index verification complete');
}
