/**
 * A per-key async mutex.
 *
 * Socket.IO invokes handlers in packet arrival order, but an `async` handler
 * yields at its first `await`. Two rapid `message:send` calls from the SAME
 * socket can therefore interleave inside sequence allocation, and message #2
 * can win a lower seq than message #1 — so the sender's own two messages
 * render out of order for everyone, permanently.
 *
 * Serialising per (socket, conversation) costs one queued promise and fixes it.
 * Throughput is unaffected: the critical section is a single $inc round trip.
 */
export class SerialQueue {
  private tail: Promise<unknown> = Promise.resolve();

  run<T>(fn: () => Promise<T>): Promise<T> {
    // Chain on both settle paths, so one rejection cannot wedge the queue.
    const result = this.tail.then(fn, fn);
    this.tail = result.catch(() => undefined);
    return result;
  }
}

/**
 * Queues keyed by an arbitrary string, with explicit disposal.
 *
 * Without `delete`, a long-lived socket that visits many conversations would
 * accumulate a queue per conversation for the life of the connection.
 */
export class SerialQueueMap {
  private readonly queues = new Map<string, SerialQueue>();

  for(key: string): SerialQueue {
    let q = this.queues.get(key);
    if (!q) {
      q = new SerialQueue();
      this.queues.set(key, q);
    }
    return q;
  }

  delete(key: string): void {
    this.queues.delete(key);
  }

  deletePrefix(prefix: string): void {
    for (const k of this.queues.keys()) if (k.startsWith(prefix)) this.queues.delete(k);
  }

  get size(): number {
    return this.queues.size;
  }
}
