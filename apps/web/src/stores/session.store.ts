import { create } from 'zustand';
import type { IdentityPrivate } from '@rtc/crypto';
import type { AccountUser } from '../crypto/session.js';

export type ConnectionState = 'offline' | 'connecting' | 'online' | 'draining';

interface SessionState {
  user: AccountUser | undefined;
  priv: IdentityPrivate | undefined;
  status: 'loading' | 'signed-out' | 'signed-in';
  connection: ConnectionState;
  /** Shown once after registration and never retrievable again. */
  recoveryCode: string | undefined;
  error: string | undefined;
  setSession: (user: AccountUser, priv: IdentityPrivate) => void;
  setRecoveryCode: (code: string | undefined) => void;
  setConnection: (connection: ConnectionState) => void;
  setStatus: (status: SessionState['status']) => void;
  setError: (error: string | undefined) => void;
  signOut: () => void;
}

export const useSession = create<SessionState>((set) => ({
  user: undefined,
  priv: undefined,
  status: 'loading',
  connection: 'offline',
  recoveryCode: undefined,
  error: undefined,
  setSession: (user, priv) => set({ user, priv, status: 'signed-in', error: undefined }),
  setRecoveryCode: (recoveryCode) => set({ recoveryCode }),
  setConnection: (connection) => set({ connection }),
  setStatus: (status) => set({ status }),
  setError: (error) => set({ error }),
  signOut: () => set({ user: undefined, priv: undefined, status: 'signed-out', recoveryCode: undefined }),
}));
