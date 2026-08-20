import { create } from 'zustand';
import type { MediaState } from '@rtc/shared';
import type { RemotePeer } from '../rtc/MeshManager.js';

interface CallState {
  /** Conversation whose call we are in, or undefined when not in a call. */
  activeConversationId: string | undefined;
  peers: RemotePeer[];
  local: MediaState;
  joining: boolean;
  error: string | undefined;
  /** Peer socketId -> call safety number, once both descriptions exist. */
  safetyNumbers: Record<string, string>;
  relayOnly: boolean;
  relayAvailable: boolean;
  setActive: (conversationId: string | undefined) => void;
  setPeers: (peers: RemotePeer[]) => void;
  setLocal: (local: MediaState) => void;
  setJoining: (joining: boolean) => void;
  setError: (error: string | undefined) => void;
  setSafetyNumber: (socketId: string, value: string) => void;
  setRelay: (relayOnly: boolean, relayAvailable: boolean) => void;
  reset: () => void;
}

export const useCall = create<CallState>((set) => ({
  activeConversationId: undefined,
  peers: [],
  local: { audio: true, video: true, screen: false },
  joining: false,
  error: undefined,
  safetyNumbers: {},
  relayOnly: false,
  relayAvailable: false,
  setActive: (activeConversationId) => set({ activeConversationId }),
  setPeers: (peers) => set({ peers }),
  setLocal: (local) => set({ local }),
  setJoining: (joining) => set({ joining }),
  setError: (error) => set({ error }),
  setSafetyNumber: (socketId, value) =>
    set((s) => ({ safetyNumbers: { ...s.safetyNumbers, [socketId]: value } })),
  setRelay: (relayOnly, relayAvailable) => set({ relayOnly, relayAvailable }),
  reset: () =>
    set({
      activeConversationId: undefined,
      peers: [],
      local: { audio: true, video: true, screen: false },
      joining: false,
      error: undefined,
      safetyNumbers: {},
    }),
}));
