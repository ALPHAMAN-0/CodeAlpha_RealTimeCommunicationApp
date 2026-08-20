import type { TypedServer, TypedSocket } from '../types.js';
import { registerSessionHandlers } from './session.js';
import { registerPresenceHandlers } from './presence.js';
import { registerRoomHandlers } from './room.js';
import { registerMessageHandlers } from './message.js';
import { registerSyncHandlers } from './sync.js';
import { registerReceiptHandlers } from './receipt.js';
import { registerTypingHandlers } from './typing.js';
import { registerEpochHandlers } from './epoch.js';
import { registerRtcHandlers } from './rtc.js';
import { registerWhiteboardHandlers } from './whiteboard.js';
import { registerFileHandlers } from './file.js';

/**
 * Every per-socket handler registration, in one place.
 *
 * A reflection test walks the declared event list against what is actually
 * registered here, so an event cannot ship without a schema-validated,
 * authorization-checked handler.
 */
export function registerAllHandlers(io: TypedServer, socket: TypedSocket): void {
  registerSessionHandlers(io, socket);
  registerPresenceHandlers(io, socket);
  registerRoomHandlers(io, socket);
  registerMessageHandlers(io, socket);
  registerSyncHandlers(io, socket);
  registerReceiptHandlers(io, socket);
  registerTypingHandlers(io, socket);
  registerEpochHandlers(io, socket);
  registerRtcHandlers(io, socket);
  registerWhiteboardHandlers(io, socket);
  registerFileHandlers(io, socket);
}
