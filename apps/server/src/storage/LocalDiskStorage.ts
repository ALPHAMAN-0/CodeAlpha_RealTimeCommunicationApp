import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rm, stat } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { StorageAdapter } from './StorageAdapter.js';

/**
 * Filesystem storage. Kept as a working second implementation so the
 * StorageAdapter seam is real rather than aspirational.
 */
export class LocalDiskStorage implements StorageAdapter {
  constructor(private readonly root: string) {}

  /**
   * Paths are built entirely from a server-generated UUID.
   *
   * No user-supplied byte ever reaches a path component, so traversal is
   * structurally impossible rather than "sanitised" — which is the only kind
   * of impossible worth relying on. The resolve assertion below is a
   * belt-and-braces check against a future refactor.
   */
  private pathFor(storageId: string): string {
    const safe = /^[0-9a-f-]{36}$/.test(storageId) ? storageId : randomUUID();
    const full = path.join(this.root, safe.slice(0, 2), safe);
    const resolved = path.resolve(full);
    if (!resolved.startsWith(path.resolve(this.root) + path.sep)) {
      throw new Error('refusing to write outside the upload root');
    }
    return resolved;
  }

  async put({ stream }: { stream: Readable; filename: string }) {
    const storageId = randomUUID();
    const target = this.pathFor(storageId);
    await mkdir(path.dirname(target), { recursive: true });
    await pipeline(stream, createWriteStream(target, { mode: 0o600 }));
    const { size } = await stat(target);
    return { storageId, size };
  }

  async get(storageId: string, range?: { start: number; end: number }): Promise<Readable> {
    return createReadStream(this.pathFor(storageId), range ? { start: range.start, end: range.end } : {});
  }

  async size(storageId: string): Promise<number | undefined> {
    try {
      return (await stat(this.pathFor(storageId))).size;
    } catch {
      return undefined;
    }
  }

  async delete(storageId: string): Promise<void> {
    await rm(this.pathFor(storageId), { force: true });
  }
}
