import type { UserId, StrokeId, Seq } from '../ids.js';
import type { CipherEnvelope } from './crypto.js';

export type WhiteboardTool = 'pen' | 'highlighter' | 'eraser';

/**
 * The PLAINTEXT of a stroke op. Lives only in browsers; the server sees the
 * sealed form in `WhiteboardOpRecord.envelope`.
 */
export interface StrokePayload {
  tool: WhiteboardTool;
  /** CSS color string. */
  color: string;
  width: number;
  /** Flat [x0,y0,x1,y1,…] integers in the WB_CANVAS logical space. */
  points: number[];
}

export type WhiteboardOpKind = 'stroke' | 'undo' | 'redo' | 'clear';

/**
 * One op in the board's totally-ordered log.
 *
 * `kind`, `strokeId` and `chunk` are deliberately server-visible: the server
 * needs them to authorize undo (author must own the stroke), to prune on
 * clear, and to serve late joiners — none of which it could do on opaque
 * bytes. Stroke GEOMETRY, COLOR and WIDTH stay encrypted. So the server
 * learns "user X drew a stroke, then undid it", never what was drawn.
 */
export interface WhiteboardOpRecord {
  seq: Seq;
  authorId: UserId;
  kind: WhiteboardOpKind;
  strokeId?: StrokeId;
  /** Chunk index within a stroke; strokes stream as they are drawn. */
  chunk?: number;
  /** True on the final chunk of a stroke. */
  done?: boolean;
  /** Present for kind === 'stroke' only. */
  envelope?: CipherEnvelope;
  at: number;
}
