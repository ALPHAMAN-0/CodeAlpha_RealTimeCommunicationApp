import type { UserId } from '../ids.js';

export interface UserDTO {
  id: UserId;
  displayName: string;
  /** Deterministic from the id — no avatar uploads needed for the demo. */
  avatarColor: string;
  /** Current identity key version, for cheap staleness checks. */
  keyVersion: number;
}

export interface PresenceDTO {
  userId: UserId;
  status: 'online' | 'offline';
  /** Truncated to one-minute granularity — precise last-seen is surveillance. */
  lastSeenAt: number;
}
