import { LIMITS, THROTTLE, WB_CANVAS } from '@rtc/shared';

export interface StrokeChunk {
  strokeId: string;
  chunk: number;
  done: boolean;
  /** Flat [x0,y0,x1,y1,…] integers in the WB_CANVAS logical space. */
  points: number[];
}

/**
 * Coalesce pointer samples into network-sized chunks.
 *
 * A pointermove can fire at 240 Hz on a high-refresh trackpad. Sending one
 * message per sample would be thousands of packets per second for a single
 * drawer; batching to ~25 chunks/s costs 1–2 KB/s and is visually identical.
 *
 * Local rendering never waits for any of this — the pen must feel attached to
 * the cursor, and a round trip is instantly perceptible.
 */
export class StrokeBatcher {
  private buffer: number[] = [];
  private strokeId: string | undefined;
  private chunkIndex = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly onFlush: (chunk: StrokeChunk) => void) {}

  /** Quantise to integers so every client renders identically at any DPR. */
  private quantise(x: number, y: number): [number, number] {
    return [
      Math.round(Math.min(Math.max(0, x), WB_CANVAS.width)),
      Math.round(Math.min(Math.max(0, y), WB_CANVAS.height)),
    ];
  }

  begin(strokeId: string, x: number, y: number): void {
    this.strokeId = strokeId;
    this.chunkIndex = 0;
    this.buffer = [];
    this.push(x, y);
  }

  push(x: number, y: number): void {
    if (!this.strokeId) return;
    const [qx, qy] = this.quantise(x, y);
    // Skip a sample that quantises onto the previous point: it carries no
    // information and would still cost a slot in the chunk.
    const n = this.buffer.length;
    if (n >= 2 && this.buffer[n - 2] === qx && this.buffer[n - 1] === qy) return;
    this.buffer.push(qx, qy);

    if (this.buffer.length / 2 >= LIMITS.WB_POINTS_PER_CHUNK_MAX) {
      this.flush(false);
      return;
    }
    this.timer ??= setTimeout(() => this.flush(false), THROTTLE.WB_FLUSH_MS);
  }

  /** Final flush at pointerup, marking the stroke complete. */
  end(): void {
    if (!this.strokeId) return;
    this.flush(true);
    this.strokeId = undefined;
  }

  private flush(done: boolean): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    if (!this.strokeId) return;
    // A `done` flush must still be sent even with no new points, so receivers
    // know the stroke is finished and can move it to the committed layer.
    if (this.buffer.length === 0 && !done) return;

    const points = this.buffer;
    this.buffer = [];
    // Carry the last point into the next chunk so segments join seamlessly
    // rather than showing a visible gap at every chunk boundary.
    if (!done && points.length >= 2) {
      this.buffer = [points[points.length - 2]!, points[points.length - 1]!];
    }
    this.onFlush({ strokeId: this.strokeId, chunk: this.chunkIndex++, done, points });
  }

  cancel(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.buffer = [];
    this.strokeId = undefined;
  }
}
