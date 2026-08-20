import getStroke from 'perfect-freehand';
import { WB_CANVAS } from '@rtc/shared';
import type { WhiteboardTool } from '@rtc/shared';

export interface StrokeState {
  strokeId: string;
  authorId: string;
  tool: WhiteboardTool;
  color: string;
  width: number;
  points: number[];
  done: boolean;
}

/**
 * Two stacked canvases.
 *
 * The committed layer holds finished strokes and is only redrawn on undo,
 * clear or resize. The live layer holds in-progress strokes and is cleared
 * every frame. Without the split, every incoming chunk would trigger a
 * full-history redraw and the board dies around 500 strokes — which is a
 * perfectly ordinary amount of drawing.
 */
export class CanvasRenderer {
  private strokes = new Map<string, StrokeState>();
  /** Undone stroke ids. Tombstones, so undo is a commutative append. */
  private tombstones = new Set<string>();
  private committedDirty = true;
  private raf = 0;

  constructor(
    private readonly committed: HTMLCanvasElement,
    private readonly live: HTMLCanvasElement,
  ) {}

  resize(): void {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    for (const canvas of [this.committed, this.live]) {
      const rect = canvas.getBoundingClientRect();
      canvas.width = Math.round(rect.width * dpr);
      canvas.height = Math.round(rect.height * dpr);
    }
    this.committedDirty = true;
    this.schedule();
  }

  upsertStroke(state: StrokeState): void {
    const existing = this.strokes.get(state.strokeId);
    if (existing) {
      // Chunks append; the carried-over point means a duplicate at the seam,
      // which is visually harmless and cheaper than de-duplicating.
      existing.points.push(...state.points);
      existing.done = state.done;
      if (state.done) this.committedDirty = true;
    } else {
      this.strokes.set(state.strokeId, { ...state, points: [...state.points] });
      if (state.done) this.committedDirty = true;
    }
    this.schedule();
  }

  setUndone(strokeId: string, undone: boolean): void {
    if (undone) this.tombstones.add(strokeId);
    else this.tombstones.delete(strokeId);
    this.committedDirty = true;
    this.schedule();
  }

  clear(): void {
    this.strokes.clear();
    this.tombstones.clear();
    this.committedDirty = true;
    this.schedule();
  }

  private schedule(): void {
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      this.draw();
    });
  }

  private scale(canvas: HTMLCanvasElement): { sx: number; sy: number } {
    return { sx: canvas.width / WB_CANVAS.width, sy: canvas.height / WB_CANVAS.height };
  }

  private drawStroke(ctx: CanvasRenderingContext2D, stroke: StrokeState, canvas: HTMLCanvasElement): void {
    const { sx, sy } = this.scale(canvas);
    const pts: Array<[number, number]> = [];
    for (let i = 0; i + 1 < stroke.points.length; i += 2) {
      pts.push([stroke.points[i]! * sx, stroke.points[i + 1]! * sy]);
    }
    if (pts.length === 0) return;

    const outline = getStroke(pts, {
      size: stroke.width * Math.max(sx, 0.1),
      thinning: stroke.tool === 'highlighter' ? 0 : 0.5,
      smoothing: 0.5,
      streamline: 0.5,
      last: stroke.done,
    });
    if (outline.length === 0) return;

    ctx.save();
    if (stroke.tool === 'eraser') {
      // Recorded as a normal op so it replays and can be undone, rather than
      // mutating the strokes underneath it.
      ctx.globalCompositeOperation = 'destination-out';
      ctx.fillStyle = '#000';
    } else {
      ctx.globalCompositeOperation = 'source-over';
      ctx.fillStyle = stroke.color;
      if (stroke.tool === 'highlighter') ctx.globalAlpha = 0.35;
    }

    ctx.beginPath();
    ctx.moveTo(outline[0]![0], outline[0]![1]);
    for (const [x, y] of outline.slice(1)) ctx.lineTo(x, y);
    ctx.closePath();
    ctx.fill();
    ctx.restore();
  }

  private draw(): void {
    const committedCtx = this.committed.getContext('2d');
    const liveCtx = this.live.getContext('2d');
    if (!committedCtx || !liveCtx) return;

    if (this.committedDirty) {
      committedCtx.clearRect(0, 0, this.committed.width, this.committed.height);
      for (const stroke of this.strokes.values()) {
        if (!stroke.done || this.tombstones.has(stroke.strokeId)) continue;
        this.drawStroke(committedCtx, stroke, this.committed);
      }
      this.committedDirty = false;
    }

    liveCtx.clearRect(0, 0, this.live.width, this.live.height);
    for (const stroke of this.strokes.values()) {
      if (stroke.done || this.tombstones.has(stroke.strokeId)) continue;
      this.drawStroke(liveCtx, stroke, this.live);
    }
  }

  /** Client-side snapshot for export or a thumbnail. */
  toDataUrl(): string {
    const out = document.createElement('canvas');
    out.width = this.committed.width;
    out.height = this.committed.height;
    const ctx = out.getContext('2d');
    if (!ctx) return '';
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.drawImage(this.committed, 0, 0);
    ctx.drawImage(this.live, 0, 0);
    return out.toDataURL('image/png');
  }

  /** Strokes this author could still undo, most recent first. */
  undoableBy(authorId: string): string[] {
    return [...this.strokes.values()]
      .filter((s) => s.authorId === authorId && s.done && !this.tombstones.has(s.strokeId))
      .map((s) => s.strokeId)
      .reverse();
  }

  destroy(): void {
    if (this.raf) cancelAnimationFrame(this.raf);
  }
}
