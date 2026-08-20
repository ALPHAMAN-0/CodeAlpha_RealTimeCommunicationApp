import { create } from 'zustand';
import type { ConversationDTO, ParticipantDTO, PresenceDTO } from '@rtc/shared';

export interface ConversationView {
  conversation: ConversationDTO;
  participants: ParticipantDTO[];
  unread: number;
  /** Highest seq seen, used as the reconnect backfill cursor. */
  latestSeq: number;
  myReadSeq: number;
  /** Set while a group's key is being rotated: sending is blocked. */
  rekeyPending: boolean;
  /** Peer whose identity key changed and has not been re-verified. */
  untrustedPeers: string[];
}

export interface Profile {
  userId: string;
  displayName: string;
  avatarColor: string;
  keyVersion: number;
}

interface ConversationsState {
  order: string[];
  byId: Record<string, ConversationView>;
  /**
   * Known display names, populated by the conversation list and the directory.
   *
   * Kept separate from participants because the sidebar needs to label a
   * conversation before it has been joined.
   */
  profiles: Record<string, Profile>;
  presence: Record<string, PresenceDTO>;
  /** conversationId -> userIds currently typing. */
  typing: Record<string, string[]>;
  activeId: string | undefined;

  setList: (entries: Array<{ conversation: ConversationDTO; members: Profile[] }>) => void;
  setProfiles: (profiles: Profile[]) => void;
  upsert: (view: Partial<ConversationView> & { conversation: ConversationDTO }) => void;
  setParticipants: (conversationId: string, participants: ParticipantDTO[]) => void;
  setUnread: (conversationId: string, unread: number) => void;
  setLatestSeq: (conversationId: string, seq: number) => void;
  setRekeyPending: (conversationId: string, pending: boolean) => void;
  markUntrusted: (conversationId: string, peerId: string) => void;
  clearUntrusted: (conversationId: string, peerId: string) => void;
  setPresence: (entries: PresenceDTO[]) => void;
  setTyping: (conversationId: string, userId: string, isTyping: boolean) => void;
  setActive: (conversationId: string | undefined) => void;
  /** Cursors for the batched reconnect backfill. */
  syncCursors: () => Array<{ conversationId: string; lastSeq: number }>;
  reset: () => void;
}

/** Newest activity first; conversations with no messages fall back to creation. */
const sortKey = (v: ConversationView): number =>
  v.conversation.lastMessage?.createdAt ?? v.conversation.createdAt;

export const useConversations = create<ConversationsState>((set, get) => ({
  order: [],
  byId: {},
  profiles: {},
  presence: {},
  typing: {},
  activeId: undefined,

  setProfiles: (profiles) =>
    set((state) => {
      const next = { ...state.profiles };
      for (const p of profiles) next[p.userId] = p;
      return { profiles: next };
    }),

  setList: (entries) => {
    set((state) => {
      const byId = { ...state.byId };
      const profiles = { ...state.profiles };
      for (const entry of entries) {
        const c = entry.conversation;
        for (const m of entry.members) profiles[m.userId] = m;
        const id = String(c.id);
        byId[id] = {
          ...(byId[id] ?? {
            participants: [], unread: 0, latestSeq: 0, myReadSeq: 0,
            rekeyPending: false, untrustedPeers: [],
          }),
          conversation: c,
          rekeyPending: c.rekeyPending,
          latestSeq: Math.max(byId[id]?.latestSeq ?? 0, c.messageSeq),
        };
      }
      const order = Object.values(byId)
        .sort((a, b) => sortKey(b) - sortKey(a))
        .map((v) => String(v.conversation.id));
      return { byId, order, profiles };
    });
  },

  upsert: (view) => {
    set((state) => {
      const id = String(view.conversation.id);
      const existing = state.byId[id];
      const merged: ConversationView = {
        participants: view.participants ?? existing?.participants ?? [],
        unread: view.unread ?? existing?.unread ?? 0,
        latestSeq: Math.max(view.latestSeq ?? 0, existing?.latestSeq ?? 0),
        myReadSeq: view.myReadSeq ?? existing?.myReadSeq ?? 0,
        rekeyPending: view.rekeyPending ?? view.conversation.rekeyPending,
        untrustedPeers: view.untrustedPeers ?? existing?.untrustedPeers ?? [],
        conversation: view.conversation,
      };
      const byId = { ...state.byId, [id]: merged };
      const order = Object.values(byId)
        .sort((a, b) => sortKey(b) - sortKey(a))
        .map((v) => String(v.conversation.id));
      return { byId, order };
    });
  },

  setParticipants: (conversationId, participants) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing) return state;
      return { byId: { ...state.byId, [conversationId]: { ...existing, participants } } };
    }),

  setUnread: (conversationId, unread) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing) return state;
      return { byId: { ...state.byId, [conversationId]: { ...existing, unread } } };
    }),

  setLatestSeq: (conversationId, seq) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing) return state;
      // Monotonic: a late event must not move the cursor backwards, or the
      // next backfill would re-request messages already held.
      return {
        byId: {
          ...state.byId,
          [conversationId]: { ...existing, latestSeq: Math.max(existing.latestSeq, seq) },
        },
      };
    }),

  setRekeyPending: (conversationId, pending) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing) return state;
      return { byId: { ...state.byId, [conversationId]: { ...existing, rekeyPending: pending } } };
    }),

  markUntrusted: (conversationId, peerId) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing || existing.untrustedPeers.includes(peerId)) return state;
      return {
        byId: {
          ...state.byId,
          [conversationId]: { ...existing, untrustedPeers: [...existing.untrustedPeers, peerId] },
        },
      };
    }),

  clearUntrusted: (conversationId, peerId) =>
    set((state) => {
      const existing = state.byId[conversationId];
      if (!existing) return state;
      return {
        byId: {
          ...state.byId,
          [conversationId]: {
            ...existing,
            untrustedPeers: existing.untrustedPeers.filter((p) => p !== peerId),
          },
        },
      };
    }),

  setPresence: (entries) =>
    set((state) => {
      const presence = { ...state.presence };
      for (const e of entries) presence[String(e.userId)] = e;
      return { presence };
    }),

  setTyping: (conversationId, userId, isTyping) =>
    set((state) => {
      const current = state.typing[conversationId] ?? [];
      const next = isTyping
        ? current.includes(userId) ? current : [...current, userId]
        : current.filter((u) => u !== userId);
      return { typing: { ...state.typing, [conversationId]: next } };
    }),

  setActive: (conversationId) => set({ activeId: conversationId }),

  syncCursors: () =>
    Object.values(get().byId).map((v) => ({
      conversationId: String(v.conversation.id),
      lastSeq: v.latestSeq,
    })),

  reset: () => set({ order: [], byId: {}, profiles: {}, presence: {}, typing: {}, activeId: undefined }),
}));
