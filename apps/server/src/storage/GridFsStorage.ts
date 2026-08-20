import type { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import mongoose from 'mongoose';
import type { StorageAdapter } from './StorageAdapter.js';

/**
 * GridFS is reached through `mongoose.mongo` rather than by importing the
 * `mongodb` package directly.
 *
 * The driver is a transitive dependency of mongoose, and declaring it
 * separately invites a version skew between the driver mongoose uses and the
 * one this file imports — which surfaces as confusing runtime type errors
 * rather than an install-time conflict.
 */
const { GridFSBucket, ObjectId } = mongoose.mongo;
const BUCKET = 'attachments';

const bucket = () =>
  new GridFSBucket(mongoose.connection.db!, { bucketName: BUCKET, chunkSizeBytes: 261_120 });

export class GridFsStorage implements StorageAdapter {
  async put({ stream, filename }: { stream: Readable; filename: string }) {
    const upload = bucket().openUploadStream(filename);
    // Streamed straight through: nothing is buffered whole in memory, so a
    // 25 MB upload costs 25 MB of disk and a chunk of RAM, not 25 MB of heap.
    await pipeline(stream, upload);
    return { storageId: String(upload.id), size: upload.length };
  }

  async get(storageId: string, range?: { start: number; end: number }): Promise<Readable> {
    const opts = range ? { start: range.start, end: range.end + 1 } : {};
    return bucket().openDownloadStream(new ObjectId(storageId), opts);
  }

  async size(storageId: string): Promise<number | undefined> {
    const files = await bucket().find({ _id: new ObjectId(storageId) }).limit(1).toArray();
    return files[0]?.length;
  }

  async delete(storageId: string): Promise<void> {
    try {
      await bucket().delete(new ObjectId(storageId));
    } catch {
      // Already gone. Deletion is idempotent by design so the orphan reaper
      // can run repeatedly without special-casing races.
    }
  }
}
