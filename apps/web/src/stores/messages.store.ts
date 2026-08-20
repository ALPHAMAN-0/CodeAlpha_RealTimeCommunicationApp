import { create } from 'zustand';
import type { MessageDTO } from '@rtc/shared';
import type { PendingSend, SendStatus } from '../realtime/Outbox.js';

/**
 * A message as rendered.
 *
 * `plaintext` is filled in after decryption; `undefined` means "not decrypted
 * yet" and `null` means "could not be decrypted", which the UI must show
 * differently — a spinner versus a warning.
 */
export interface RenderedMessage {
  id: string;
  clientMsgId: string;
  conversationId: string;
  seq: number | undefined;
  senderId: string;
  kind: 'text' | 'file' | 'system';
  plaintext?: string | null;
  filePayload?: unknown;
  system?: MessageDTO['system'];
  /** Client clock, authenticated in the AAD. This is what the UI displays. */
  sentAt: number;
  deletedAt?: number;
  status: SendStatus;
  lastError?: string;
  raw?: MessageDTO;
}

interface ConversationTimeline {
  /** Confirmed messages, keyed by server id. */
  byId: Map<string, RenderedMessage>;
  /** Sorted seq index into `byId`. */
  order: number[];
  seqToId: Map<number, string>;
  /** Optimistic rows with no seq yet, ordered by local queue time. */
  pending: RenderedMessage[];
  oldestSeq: number | null;
  hasMore: boolean;
}

const emptyTimeline = (): ConversationTimeline => ({
  byId: new Map(),
  order: [],
  seqToId: new Map(),
  pending: [],
  oldestSeq: null,
  hasMore: true,
});

/**
 * Binary-search insertion into the seq index.
 *
 * Appending is the bug that ships: messages do NOT arrive in seq order —
 * backfill, history pagination and live fan-out interleave — so an append
 * produces a timeline that looks right in testing and scrambles under real
 * network conditions.
 */
function insertSeq(order: number[], seq: number): number[] {
  let lo = 0;
  let hi = order.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (order[mid]! < seq) lo = mid + 1;
    else hi = mid;
  }
  if (order[lo] === seq) return order; // already present
  const next = order.slice();
  next.splice(lo, 0, seq);
  return next;
}

interface MessagesState {
  timelines: Record<string, ConversationTimeline>;
  /** Insert or update confirmed messages. Idempotent on message id. */
  upsert: (conversationId: string, messages: MessageDTO[]) => void;
  /** Attach decrypted content once it is available. */
  setPlaintext: (conversationId: string, messageId: string, plaintext: string | null, filePayload?: unknown) => void;
  /** Mirror the outbox's optimistic rows into the timeline. */
  syncPending: (entries: PendingSend[]) => void;
  markDeleted: (conversationId: string, messageId: string, deletedAt: number) => void;
  setHistoryMeta: (conversationId: string, oldestSeq: number | null, hasMore: boolean) => void;
  /** Ordered for rendering: confirmed by seq, then pending by queue time. */
  list: (conversationId: string) => RenderedMessage[];
  latestSeq: (conversationId: string) => number;
  reset: () => void;
}

const toRendered = (m: MessageDTO): RenderedMessage => ({
  id: String(m.id),
  clientMsgId: String(m.clientMsgId),
  conversationId: String(m.conversationId),
  seq: m.seq,
  senderId: String(m.senderId),
  kind: m.kind,
  ...(m.system ? { system: m.system } : {}),
  sentAt: m.sentAt,
  ...(m.deletedAt ? { deletedAt: m.deletedAt } : {}),
  status: 'sent',
  raw: m,
});

export const useMessages = create<MessagesState>((set, get) => ({
  timelines: {},

  upsert: (conversationId, messages) => {
    if (messages.length === 0) return;
    set((state) => {
      const current = state.timelines[conversationId] ?? emptyTimeline();
      const byId = new Map(current.byId);
      const seqToId = new Map(current.seqToId);
      let order = current.order;

      for (const dto of messages) {
        const id = String(dto.id);
        const existing = byId.get(id);
        const rendered = toRendered(dto);
        // Preserve already-decrypted content across a re-upsert (backfill can
        // redeliver a message we have already opened).
        if (existing?.plaintext !== undefined) rendered.plaintext = existing.plaintext;
        if (existing?.filePayload !== undefined) rendered.filePayload = existing.filePayload;
        byId.set(id, rendered);
        if (!seqToId.has(dto.seq)) {
          order = insertSeq(order, dto.seq);
          seqToId.set(dto.seq, id);
        }
      }

      /**
       * Retire optimistic rows whose server message has arrived.
       *
       * Matching on clientMsgId — not on text or timestamp — is what makes the
       * optimistic bubble collapse into the confirmed one instead of leaving a
       * ghost duplicate.
       */
      const confirmedClientIds = new Set(messages.map((m) => String(m.clientMsgId)));
      const pending = current.pending.filter((p) => !confirmedClientIds.has(p.clientMsgId));

      const oldest = order.length > 0 ? order[0]! : null;
      return {
        timelines: {
          ...state.timelines,
          [conversationId]: {
            byId, order, seqToId, pending,
            oldestSeq: current.oldestSeq === null ? oldest : Math.min(current.oldestSeq, oldest ?? current.oldestSeq),
            hasMore: current.hasMore,
          },
        },
      };
    });
  },

  setPlaintext: (conversationId, messageId, plaintext, filePayload) => {
    set((state) => {
      const t = state.timelines[conversationId];
      const existing = t?.byId.get(messageId);
      if (!t || !existing) return state;
      const byId = new Map(t.byId);
      byId.set(messageId, { ...existing, plaintext, ...(filePayload !== undefined ? { filePayload } : {}) });
      return { timelines: { ...state.timelines, [conversationId]: { ...t, byId } } };
    });
  },

  syncPending: (entries) => {
    set((state) => {
      const grouped = new Map<string, PendingSend[]>();
      for (const e of entries) {
        const list = grouped.get(e.conversationId) ?? [];
        list.push(e);
        grouped.set(e.conversationId, list);
      }
      const timelines = { ...state.timelines };
      // Every conversation with pending rows, plus any that just emptied.
      const touched = new Set([...grouped.keys(), ...Object.keys(timelines)]);
      for (const conversationId of touched) {
        const t = timelines[conversationId] ?? emptyTimeline();
        const list = (grouped.get(conversationId) ?? [])
          .slice()
          .sort((a, b) => a.queuedAt - b.queuedAt);
        timelines[conversationId] = {
          ...t,
          pending: list.map((e) => ({
            id: `pending:${e.clientMsgId}`,
            clientMsgId: e.clientMsgId,
            conversationId: e.conversationId,
            seq: undefined,
            senderId: 'self',
            kind: e.kind,
            plaintext: e.preview,
            sentAt: e.sentAt,
            status: e.status,
            ...(e.lastError ? { lastError: e.lastError } : {}),
          })),
        };
      }
      return { timelines };
    });
  },

  markDeleted: (conversationId, messageId, deletedAt) => {
    set((state) => {
      const t = state.timelines[conversationId];
      const existing = t?.byId.get(messageId);
      if (!t || !existing) return state;
      const byId = new Map(t.byId);
      // The row and its seq stay: removing it would punch a hole in ordering.
      byId.set(messageId, { ...existing, deletedAt, plaintext: null });
      return { timelines: { ...state.timelines, [conversationId]: { ...t, byId } } };
    });
  },

  setHistoryMeta: (conversationId, oldestSeq, hasMore) => {
    set((state) => {
      const t = state.timelines[conversationId] ?? emptyTimeline();
      return { timelines: { ...state.timelines, [conversationId]: { ...t, oldestSeq, hasMore } } };
    });
  },

  list: (conversationId) => {
    const t = get().timelines[conversationId];
    if (!t) return [];
    const confirmed = t.order.flatMap((seq) => {
      const id = t.seqToId.get(seq);
      const m = id ? t.byId.get(id) : undefined;
      return m ? [m] : [];
    });
    // Pending rows sort AFTER everything confirmed: they have no seq yet, so
    // there is no correct position for them among numbered messages.
    return [...confirmed, ...t.pending];
  },

  latestSeq: (conversationId) => {
    const t = get().timelines[conversationId];
    return t && t.order.length > 0 ? t.order[t.order.length - 1]! : 0;
  },

  reset: () => set({ timelines: {} }),
}));

/** Exported for tests: the pure insertion primitive. */
export const __insertSeq = insertSeq;
