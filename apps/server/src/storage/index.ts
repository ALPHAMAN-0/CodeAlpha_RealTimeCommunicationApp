import { GridFsStorage } from './GridFsStorage.js';
import type { StorageAdapter } from './StorageAdapter.js';

let adapter: StorageAdapter = new GridFsStorage();

export const storage = (): StorageAdapter => adapter;

/** Swap the implementation — used by tests and by a future S3 deployment. */
export const setStorage = (next: StorageAdapter): void => {
  adapter = next;
};

export type { StorageAdapter };
