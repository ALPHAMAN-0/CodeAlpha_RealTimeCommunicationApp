import { describe, expect, it } from 'vitest';
import { SerialQueue, SerialQueueMap } from './SerialQueue.js';

const tick = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('SerialQueue', () => {
  it('runs tasks in submission order despite inverted durations', async () => {
    // The failure this prevents: a slow first task and a fast second one, both
    // allocating a sequence number, completing in the wrong order.
    const q = new SerialQueue();
    const order: number[] = [];
    const tasks = [30, 1, 20, 0, 10].map((delay, i) =>
      q.run(async () => {
        await tick(delay);
        order.push(i);
      }),
    );
    await Promise.all(tasks);
    expect(order).toEqual([0, 1, 2, 3, 4]);
  });

  it('preserves order across 100 interleaved tasks', async () => {
    const q = new SerialQueue();
    const order: number[] = [];
    await Promise.all(
      Array.from({ length: 100 }, (_, i) =>
        q.run(async () => {
          await tick(i % 3);
          order.push(i);
        }),
      ),
    );
    expect(order).toEqual(Array.from({ length: 100 }, (_, i) => i));
  });

  it('is not poisoned by a rejection', async () => {
    // A queue that stops working after one failed handler would take the whole
    // conversation down with it.
    const q = new SerialQueue();
    const order: string[] = [];
    const failing = q.run(async () => {
      order.push('boom');
      throw new Error('boom');
    });
    const after = q.run(async () => {
      order.push('after');
      return 'ok';
    });
    await expect(failing).rejects.toThrow('boom');
    await expect(after).resolves.toBe('ok');
    expect(order).toEqual(['boom', 'after']);
  });

  it('propagates results and errors to the right caller', async () => {
    const q = new SerialQueue();
    const a = q.run(async () => 1);
    const b = q.run(async () => {
      throw new Error('second');
    });
    const c = q.run(async () => 3);
    expect(await a).toBe(1);
    await expect(b).rejects.toThrow('second');
    expect(await c).toBe(3);
  });

  it('serialises a real read-modify-write', async () => {
    // Without the queue this races and the final value is wrong.
    const q = new SerialQueue();
    let counter = 0;
    await Promise.all(
      Array.from({ length: 50 }, () =>
        q.run(async () => {
          const read = counter;
          await tick(1);
          counter = read + 1;
        }),
      ),
    );
    expect(counter).toBe(50);
  });
});

describe('SerialQueueMap', () => {
  it('keeps distinct keys independent', async () => {
    const map = new SerialQueueMap();
    const order: string[] = [];
    await Promise.all([
      map.for('a').run(async () => {
        await tick(20);
        order.push('a');
      }),
      map.for('b').run(async () => {
        await tick(1);
        order.push('b');
      }),
    ]);
    // 'b' finishes first because it is a different key — not serialised behind 'a'.
    expect(order).toEqual(['b', 'a']);
  });

  it('reuses one queue per key and disposes on demand', () => {
    const map = new SerialQueueMap();
    expect(map.for('x')).toBe(map.for('x'));
    expect(map.size).toBe(1);
    map.for('sock1:conv1');
    map.for('sock1:conv2');
    expect(map.size).toBe(3);
    // Disconnect must release every queue for that socket, or a long-lived
    // connection leaks one per conversation it ever visited.
    map.deletePrefix('sock1:');
    expect(map.size).toBe(1);
    map.delete('x');
    expect(map.size).toBe(0);
  });
});
