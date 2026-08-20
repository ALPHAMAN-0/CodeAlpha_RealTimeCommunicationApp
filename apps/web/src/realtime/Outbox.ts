import type { CipherEnvelope } from '@rtc/shared';
import { emit, SocketError } from '../lib/socket.js';

/**
 * Persisted outbound queue.
 *
 * The whole reliability story rests on one property: `clientMsgId` is minted
 * ONCE when the user hits send and is never regenerated on retry. The server's
 * unique index on (conversationId, clientMsgId) then makes a replay a no-op,
 * so retrying is always safe — even across a reload, a crash, or a race with
 * another retry of the same message.
 */
export type SendStatus = 'queued' | 'sending' | 'sent' | 'failed';

export interface PendingSend {
  clientMsgId: string;
  conversationId: string;
  kind: 'text' | 'file';
  envelope: CipherEnvelope;
  sentAt: number;
  attachmentId?: string;
  replyToId?: string;
  /** Local only: the plaintext, so an optimistic bubble can render. */
  preview: string;
  queuedAt: number;
  attempts: number;
  status: SendStatus;
  lastError?: string;
}

const KEY = (userId: string) => `rtc.outbox.v1.${userId}`;
const MAX_ATTEMPTS = 6;

export interface OutboxListener {
  (entries: PendingSend[]): void;
}

export interface SendAck {
  messageId: string;
  clientMsgId: string;
  seq: number;
  createdAt: number;
  deduped: boolean;
}

/**
 * Called when the server confirms a send.
 *
 * This hook exists because the sender does NOT receive its own `message:new`
 * event — the server excludes the originating socket, since it already has the
 * ack. Without surfacing that ack, a sender's own message would vanish from
 * the timeline the moment it left the outbox and only reappear after a reload
 * pulled it back through backfill.
 */
export interface SentListener {
  (entry: PendingSend, ack: SendAck): void;
}

export class Outbox {
  private entries: PendingSend[] = [];
  private listeners = new Set<OutboxListener>();
  private sentListeners = new Set<SentListener>();
  private flushing = false;

  constructor(private readonly userId: string) {
    this.entries = this.read();
  }

  private read(): PendingSend[] {
    try {
      const raw = localStorage.getItem(KEY(this.userId));
      if (!raw) return [];
      const parsed = JSON.parse(raw) as PendingSend[];
      // Anything left mid-flight from a previous session is queued, not sent:
      // we do not know whether it landed, and retrying is safe by design.
      return parsed.map((e) => (e.status === 'sending' ? { ...e, status: 'queued' } : e));
    } catch {
      return [];
    }
  }

  private persist(): void {
    try {
      // Only unfinished work is persisted; sent entries live in the message store.
      const keep = this.entries.filter((e) => e.status !== 'sent');
      localStorage.setItem(KEY(this.userId), JSON.stringify(keep));
    } catch {
      // Private-browsing quota failures must not break sending. The message is
      // still on the server; only the local optimistic row would be lost on a
      // reload, and backfill restores it.
    }
    for (const l of this.listeners) l([...this.entries]);
  }

  subscribe(listener: OutboxListener): () => void {
    this.listeners.add(listener);
    listener([...this.entries]);
    return () => this.listeners.delete(listener);
  }

  onSent(listener: SentListener): () => void {
    this.sentListeners.add(listener);
    return () => this.sentListeners.delete(listener);
  }

  pending(): PendingSend[] {
    return this.entries.filter((e) => e.status !== 'sent');
  }

  forConversation(conversationId: string): PendingSend[] {
    return this.entries.filter((e) => e.conversationId === conversationId && e.status !== 'sent');
  }

  enqueue(entry: Omit<PendingSend, 'queuedAt' | 'attempts' | 'status'>): void {
    if (this.entries.some((e) => e.clientMsgId === entry.clientMsgId)) return;
    this.entries.push({ ...entry, queuedAt: Date.now(), attempts: 0, status: 'queued' });
    this.persist();
    void this.flush();
  }

  retry(clientMsgId: string): void {
    const entry = this.entries.find((e) => e.clientMsgId === clientMsgId);
    if (!entry) return;
    entry.status = 'queued';
    entry.attempts = 0;
    delete entry.lastError;
    this.persist();
    void this.flush();
  }

  discard(clientMsgId: string): void {
    this.entries = this.entries.filter((e) => e.clientMsgId !== clientMsgId);
    this.persist();
  }

  /**
   * Flush queued sends.
   *
   * Sequential PER CONVERSATION so the user's intended order survives, and
   * concurrent across conversations because they have independent orderings.
   */
  async flush(): Promise<void> {
    if (this.flushing) return;
    this.flushing = true;
    try {
      const byConversation = new Map<string, PendingSend[]>();
      for (const e of this.entries) {
        if (e.status !== 'queued') continue;
        const list = byConversation.get(e.conversationId) ?? [];
        list.push(e);
        byConversation.set(e.conversationId, list);
      }

      await Promise.all(
        [...byConversation.values()].map(async (list) => {
          list.sort((a, b) => a.queuedAt - b.queuedAt);
          for (const entry of list) {
            const ok = await this.attempt(entry);
            // Stop this conversation's chain on failure so a later message
            // cannot overtake an earlier one that is still retrying.
            if (!ok) break;
          }
        }),
      );
    } finally {
      this.flushing = false;
    }
  }

  private async attempt(entry: PendingSend): Promise<boolean> {
    entry.status = 'sending';
    entry.attempts += 1;
    this.persist();
    try {
      const ack = await emit<SendAck>('message:send', {
        conversationId: entry.conversationId,
        clientMsgId: entry.clientMsgId,
        kind: entry.kind,
        envelope: entry.envelope,
        sentAt: entry.sentAt,
        ...(entry.attachmentId ? { attachmentId: entry.attachmentId } : {}),
        ...(entry.replyToId ? { replyToId: entry.replyToId } : {}),
      });
      entry.status = 'sent';
      // Hand the confirmation over BEFORE dropping the entry, so the timeline
      // gains the real message in the same tick that it loses the optimistic
      // row. Doing it the other way round makes the message flicker out.
      for (const listener of this.sentListeners) listener({ ...entry }, ack);
      this.entries = this.entries.filter((e) => e.clientMsgId !== entry.clientMsgId);
      this.persist();
      return true;
    } catch (err) {
      const code = err instanceof SocketError ? err.code : 'UNKNOWN';
      entry.lastError = code;

      /**
       * A permanent error must NOT be auto-retried.
       *
       * VALIDATION and FORBIDDEN will fail identically forever, so retrying
       * them is an infinite loop that also hides the problem from the user.
       */
      const permanent = code === 'VALIDATION' || code === 'FORBIDDEN' || code === 'NOT_A_MEMBER';
      if (permanent || entry.attempts >= MAX_ATTEMPTS) {
        entry.status = 'failed';
        this.persist();
        return false;
      }

      entry.status = 'queued';
      this.persist();
      // Exponential backoff with jitter, capped — so a server restart does not
      // produce a synchronised retry storm.
      const base = Math.min(500 * 2 ** (entry.attempts - 1), 15_000);
      await new Promise((r) => setTimeout(r, base * (0.5 + Math.random() * 0.5)));
      return false;
    }
  }

  clear(): void {
    this.entries = [];
    try {
      localStorage.removeItem(KEY(this.userId));
    } catch {
      /* nothing to do */
    }
    this.persist();
  }
}

let instance: Outbox | undefined;
export const outbox = (userId: string): Outbox => {
  if (!instance || (instance as unknown as { userId: string }).userId !== userId) {
    instance = new Outbox(userId);
  }
  return instance;
};
export const currentOutbox = (): Outbox | undefined => instance;
