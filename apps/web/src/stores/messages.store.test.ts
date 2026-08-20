import { beforeEach, describe, expect, it } from 'vitest';
import { asClientMsgId, type MessageDTO } from '@rtc/shared';
import { __insertSeq, useMessages } from './messages.store.js';

const CONV = 'c'.repeat(24);

const msg = (seq: number, over: Partial<MessageDTO> = {}): MessageDTO =>
  ({
    id: `m${seq}`.padEnd(24, '0'),
    conversationId: CONV,
    seq,
    senderId: 'a'.repeat(24),
    clientMsgId: `client-${seq}`,
    kind: 'text',
    sentAt: 1_700_000_000_000 + seq,
    createdAt: 1_700_000_000_000 + seq,
    ...over,
  }) as MessageDTO;

beforeEach(() => {
  useMessages.getState().reset();
});

describe('insertSeq', () => {
  it('keeps the index sorted regardless of arrival order', () => {
    let order: number[] = [];
    for (const seq of [5, 1, 9, 3, 7, 2]) order = __insertSeq(order, seq);
    expect(order).toEqual([1, 2, 3, 5, 7, 9]);
  });

  it('is idempotent for an already-present seq', () => {
    const order = __insertSeq(__insertSeq([], 4), 4);
    expect(order).toEqual([4]);
  });

  it('tolerates gaps, which the protocol allows by design', () => {
    let order: number[] = [];
    for (const seq of [1, 2, 5, 9]) order = __insertSeq(order, seq);
    expect(order).toEqual([1, 2, 5, 9]);
  });
});

describe('messages store', () => {
  it('renders in seq order even when messages arrive shuffled', () => {
    const { upsert, list } = useMessages.getState();
    upsert(CONV, [msg(3), msg(1), msg(2)]);
    expect(list(CONV).map((m) => m.seq)).toEqual([1, 2, 3]);
  });

  it('is idempotent on message id', () => {
    const { upsert, list } = useMessages.getState();
    upsert(CONV, [msg(1)]);
    upsert(CONV, [msg(1)]);
    upsert(CONV, [msg(1), msg(2)]);
    expect(list(CONV)).toHaveLength(2);
  });

  it('preserves decrypted content across a re-upsert', () => {
    // Backfill can redeliver a message that has already been opened; losing
    // the plaintext would make it flash back to a spinner.
    const s = useMessages.getState();
    s.upsert(CONV, [msg(1)]);
    s.setPlaintext(CONV, msg(1).id as string, 'hello');
    s.upsert(CONV, [msg(1)]);
    expect(useMessages.getState().list(CONV)[0]!.plaintext).toBe('hello');
  });

  it('collapses an optimistic row into the confirmed message', () => {
    const s = useMessages.getState();
    s.syncPending([{
      clientMsgId: 'client-1', conversationId: CONV, kind: 'text',
      envelope: {} as never, sentAt: 1, preview: 'hi', queuedAt: 1,
      attempts: 1, status: 'sending',
    }]);
    expect(useMessages.getState().list(CONV)).toHaveLength(1);

    // The server confirms it under the SAME clientMsgId.
    useMessages.getState().upsert(CONV, [msg(1, { clientMsgId: asClientMsgId('client-1') })]);
    const rows = useMessages.getState().list(CONV);
    // Exactly one row: no ghost duplicate.
    expect(rows).toHaveLength(1);
    expect(rows[0]!.seq).toBe(1);
    expect(rows[0]!.status).toBe('sent');
  });

  it('sorts pending rows after every confirmed message', () => {
    const s = useMessages.getState();
    s.upsert(CONV, [msg(1), msg(2)]);
    s.syncPending([{
      clientMsgId: 'client-new', conversationId: CONV, kind: 'text',
      envelope: {} as never, sentAt: 9, preview: 'later', queuedAt: 9,
      attempts: 0, status: 'queued',
    }]);
    const rows = useMessages.getState().list(CONV);
    expect(rows.map((r) => r.seq)).toEqual([1, 2, undefined]);
  });

  it('keeps the row and seq when a message is deleted', () => {
    const s = useMessages.getState();
    s.upsert(CONV, [msg(1), msg(2)]);
    s.markDeleted(CONV, msg(1).id as string, 123);
    const rows = useMessages.getState().list(CONV);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.deletedAt).toBe(123);
    expect(rows[0]!.plaintext).toBeNull();
  });

  it('reports the highest seq for use as a sync cursor', () => {
    const s = useMessages.getState();
    expect(s.latestSeq(CONV)).toBe(0);
    s.upsert(CONV, [msg(4), msg(2)]);
    expect(useMessages.getState().latestSeq(CONV)).toBe(4);
  });
});
