# Delivery guarantees

Real-time chat is easy to demo and hard to get right. The difficult part is not
sending a message — it is what happens when the network drops mid-send, when a
retry races another retry, or when two messages from the same person arrive in
the wrong order. This document states exactly what is guaranteed.

## Exactly-once, precisely

Three separate hops, three separate guarantees. Conflating them is where chat
apps go wrong.

| Hop | Guarantee | Mechanism |
|---|---|---|
| Client → server transport | **at-least-once** | the outbox retries the byte-identical payload |
| Server persistence | **exactly-once** | unique index on `(conversationId, clientMsgId)`; a duplicate returns the existing row with `deduped: true` |
| Server → other clients | **at-least-once** | emit after commit; reconnect backfill may redeliver |
| Rendered timeline | **exactly-once, eventually total-ordered** | the client dedupes on message id and reconciles optimistic rows on `clientMsgId` |

The load-bearing claim is that `message:send` is **idempotent**, so a retry is
always safe. Everything else follows from that.

`clientMsgId` is a UUID minted once when the user hits send and **never
regenerated on retry**. That single rule is the whole trick.

## Failure cases, enumerated

1. **Ack lost after commit.** The client retries; the server finds the existing row and returns `deduped: true` with the original id and sequence number. One row, one timeline entry.
2. **Server crashes before commit.** The client retries; a normal insert happens. One row.
3. **Server crashes after commit, before fan-out.** Receivers never got `message:new`, so their next `sync:since` picks it up by sequence number. Delivered.
4. **Tab closes before the ack, outbox persisted.** The next session flushes the outbox and dedupe collapses it.
5. **Tab closes before the ack, outbox lost** (private browsing, quota failure). The optimistic bubble is gone from the UI but the row is on the server, so backfill restores it. No data loss, only a transient gap.
6. **Duplicate `message:new` for the same id.** The client's per-conversation map makes application idempotent.

What is explicitly **not** promised: cross-conversation causal ordering, and
gap-free sequence numbers.

## Ordering

1. **Total order per conversation.** Every message gets a unique server-assigned `seq`, so all clients sort identically.
2. **Per-sender order is preserved.** This needs an async mutex, and it is the subtlest bug in the system. Socket.IO dispatches handlers in packet arrival order, but an `async` handler yields at its first `await` — so two rapid sends from the same socket can interleave inside sequence allocation, and message #2 can win a lower `seq` than message #1. The sender's own two messages then render out of order **for everyone**, permanently. A `SerialQueue` per `(socket, conversation)` fixes it; the cost is one queued promise.
3. **Arrival order ≠ seq order.** Clients must **insert by seq**, not append. Backfill, history pagination and live fan-out all interleave. Appending is the bug that ships: it looks correct in testing and scrambles under real network conditions. The store uses binary-search insertion.
4. **Optimistic rows sort last.** A pending send has no `seq`, so there is no correct position for it among numbered messages. They render in a tail bucket ordered by local queue time, and migrate into the sorted region on ack.

## Sequence numbers have gaps, by design

MongoDB runs standalone here — no replica set, so no multi-document
transactions. Sequence numbers come from an atomic `$inc` on the conversation
document, which is atomic even without transactions.

The consequence is that `seq` is **monotonic but not gap-free**: a lost
duplicate race or a failed insert after allocation burns a number. Every query
is a `seq > cursor` or `seq < cursor` range scan and nothing ever expects
`cursor + 1`, so gaps are inert.

This is the tradeoff that keeps grader startup to one command instead of adding
a replica-set init container. It is documented rather than hidden.

A related refinement: the `$inc` filter carries *every* precondition —
membership, not-mid-rekey, and for groups the current epoch — so a message that
is going to be rejected never increments the counter at all.

## Reconnect: order matters

```
1. sync:since   — backfill first
2. room:join    — re-join rooms
3. outbox.flush — only then send
```

Backfill runs **first** deliberately. If a send actually landed before the
connection dropped, backfill delivers it, the store reconciles the optimistic
row on `clientMsgId`, and the outbox entry retires without re-emitting.
Flushing first would work — sends are idempotent — but it would emit requests
that backfill was about to make unnecessary.

`connectionStateRecovery` is enabled with a 120-second window, but it is an
**optimization, never the correctness mechanism**: its buffer is bounded and
process-local. `sync:since` therefore runs on *every* connect, recovered or
not. When recovery worked, it returns zero rows and costs one cheap indexed
range scan.

## Why the client sets `retries: 0`

Socket.IO can buffer and retry unacked packets itself. It is tempting and wrong
here: that buffer is in-memory only so it does not survive a reload, and it
provides no hook to reconcile optimistic UI. The `localStorage`-backed outbox
does both. Two retry mechanisms would double-send, so there is exactly one.

## Retries that must not happen

`AppError` carries a `retryable` flag. `VALIDATION`, `FORBIDDEN` and
`NOT_A_MEMBER` are permanent: retrying them is an infinite loop that also hides
the problem from the user. They surface as a failed bubble with explicit
**Retry** and **Discard** actions instead.

## Unread counts

`unread = conversation.messageSeq - participant.lastReadSeq`.

Arithmetic, not a query: O(1), no `countDocuments`, no maintained counter that
can drift. Receipts are watermarks on the participant row rather than
`readBy: [userId]` arrays on each message, which in a group of *n* would mean
O(messages × members) updates and unbounded document growth on the hottest
collection.

Sequence gaps and deletions can inflate a badge by one or two. A badge reading
4 instead of 3 is not a correctness incident, and it is documented rather than
papered over with a nightly reconcile job nobody would run.

## Tests that hold these properties true

- **Idempotent send** — the same `clientMsgId` sent twice, and five times concurrently, yields exactly one row with identical id and seq in every ack.
- **Per-sender ordering** — eight concurrent sends land with sequence numbers in submission order.
- **Two-client round trip** — send, receive, decrypt, read receipt, unread resolves to zero.
- **Ciphertext only** — the raw Mongo document is asserted not to contain the plaintext.
- **Reconnect backfill** — exactly the missed messages, ascending, no duplicates; and the inverse, three offline sends flushing exactly once in order.
- **`SerialQueue`** — 100 interleaved tasks complete in submission order, and a rejection does not poison the queue.
