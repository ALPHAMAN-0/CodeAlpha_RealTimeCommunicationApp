import { useEffect, useRef, useState } from 'react';
import { WB_CANVAS, newStrokeId, type StrokePayload, type WhiteboardOpRecord, type WhiteboardTool } from '@rtc/shared';
import { emit, emitVolatile, socket } from '../../lib/socket.js';
import { CanvasRenderer } from '../../whiteboard/CanvasRenderer.js';
import { StrokeBatcher } from '../../whiteboard/StrokeBatcher.js';
import { useSession } from '../../stores/session.store.js';
import { useConversations } from '../../stores/conversations.store.js';
import { sealWhiteboardOp, openWhiteboardOp } from '../../whiteboard/crypto.js';
import { Badge, Button } from '../../components/ui.js';

const COLORS = ['#e6edff', '#4dd8e6', '#a78bfa', '#34d399', '#fbbf24', '#f87171'];
const TOOLS: Array<{ id: WhiteboardTool; label: string; icon: string }> = [
  { id: 'pen', label: 'Pen', icon: '✏️' },
  { id: 'highlighter', label: 'Highlighter', icon: '🖍' },
  { id: 'eraser', label: 'Eraser', icon: '🧽' },
];

export function WhiteboardPanel({ conversationId, onClose }: { conversationId: string; onClose: () => void }) {
  const user = useSession((s) => s.user)!;
  const view = useConversations((s) => s.byId[conversationId]);
  const committedRef = useRef<HTMLCanvasElement>(null);
  const liveRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<CanvasRenderer>(null);
  const batcherRef = useRef<StrokeBatcher>(null);
  const drawing = useRef(false);
  const activeStroke = useRef<string | undefined>(undefined);
  const seqRef = useRef(0);

  const [tool, setTool] = useState<WhiteboardTool>('pen');
  const [color, setColor] = useState(COLORS[1]!);
  const [width, setWidth] = useState(6);
  const [truncated, setTruncated] = useState(false);
  const [cursors, setCursors] = useState<Record<string, { x: number; y: number; name: string; color: string }>>({});
  const [confirmClear, setConfirmClear] = useState(false);
  const [status, setStatus] = useState<string | undefined>('Loading board…');

  const styleRef = useRef({ tool, color, width });
  styleRef.current = { tool, color, width };

  useEffect(() => {
    if (!committedRef.current || !liveRef.current) return;
    const renderer = new CanvasRenderer(committedRef.current, liveRef.current);
    rendererRef.current = renderer;
    renderer.resize();

    const onResize = () => renderer.resize();
    window.addEventListener('resize', onResize);

    /** Decrypt an op and hand it to the renderer. */
    const apply = async (record: WhiteboardOpRecord) => {
      seqRef.current = Math.max(seqRef.current, record.seq);
      if (record.kind === 'clear') {
        renderer.clear();
        return;
      }
      if (record.kind === 'undo' && record.strokeId) {
        renderer.setUndone(String(record.strokeId), true);
        return;
      }
      if (record.kind === 'redo' && record.strokeId) {
        renderer.setUndone(String(record.strokeId), false);
        return;
      }
      if (record.kind !== 'stroke' || !record.envelope || !record.strokeId) return;
      try {
        const payload = await openWhiteboardOp(conversationId, record);
        renderer.upsertStroke({
          strokeId: String(record.strokeId),
          authorId: String(record.authorId),
          tool: payload.tool,
          color: payload.color,
          width: payload.width,
          points: payload.points,
          done: record.done ?? false,
        });
      } catch {
        // A single undecryptable op must not blank the whole board.
      }
    };

    void (async () => {
      try {
        let sinceSeq = 0;
        let hasMore = true;
        while (hasMore) {
          const page = await emit<{
            ops: WhiteboardOpRecord[]; hasMore: boolean; latestSeq: number; truncated: boolean;
          }>('wb:sync', { conversationId, sinceSeq });
          for (const op of page.ops) await apply(op);
          setTruncated(page.truncated);
          hasMore = page.hasMore;
          sinceSeq = page.ops.length > 0 ? page.ops[page.ops.length - 1]!.seq : page.latestSeq;
        }
        setStatus(undefined);
      } catch {
        setStatus('Could not load the board.');
      }
    })();

    const onOp = (p: { conversationId: string; record: WhiteboardOpRecord }) => {
      if (String(p.conversationId) !== conversationId) return;
      void apply(p.record);
    };
    const onReset = (p: { conversationId: string; byUserId: string }) => {
      if (String(p.conversationId) !== conversationId) return;
      renderer.clear();
      const who = view?.participants.find((x) => String(x.userId) === String(p.byUserId))?.displayName;
      // Attributed destruction beats mysterious destruction.
      setStatus(`${who ?? 'Someone'} cleared the board`);
      setTimeout(() => setStatus(undefined), 4000);
    };
    const onCursor = (p: { conversationId: string; userId: string; x: number; y: number }) => {
      if (String(p.conversationId) !== conversationId) return;
      const participant = view?.participants.find((x) => String(x.userId) === String(p.userId));
      setCursors((prev) => ({
        ...prev,
        [String(p.userId)]: {
          x: p.x, y: p.y,
          name: participant?.displayName ?? 'Someone',
          color: participant?.avatarColor ?? '#8b5cf6',
        },
      }));
    };

    socket.on('wb:op', onOp as never);
    socket.on('wb:reset', onReset as never);
    socket.on('wb:cursor', onCursor as never);

    return () => {
      window.removeEventListener('resize', onResize);
      socket.off('wb:op', onOp as never);
      socket.off('wb:reset', onReset as never);
      socket.off('wb:cursor', onCursor as never);
      renderer.destroy();
    };
  }, [conversationId, view?.participants]);

  useEffect(() => {
    const batcher = new StrokeBatcher((chunk) => {
      const style = styleRef.current;
      void (async () => {
        const payload: StrokePayload = {
          tool: style.tool, color: style.color, width: style.width, points: chunk.points,
        };
        const envelope = await sealWhiteboardOp(conversationId, chunk.strokeId, chunk.chunk, payload);
        await emit('wb:op', {
          conversationId,
          kind: 'stroke',
          strokeId: chunk.strokeId,
          chunk: chunk.chunk,
          done: chunk.done,
          envelope,
        }).catch(() => undefined);
      })();
    });
    batcherRef.current = batcher;
    return () => batcher.cancel();
  }, [conversationId]);

  /** Pointer position mapped into the fixed logical drawing space. */
  const toLogical = (event: React.PointerEvent): { x: number; y: number } => {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    return {
      x: ((event.clientX - rect.left) / rect.width) * WB_CANVAS.width,
      y: ((event.clientY - rect.top) / rect.height) * WB_CANVAS.height,
    };
  };

  const onPointerDown = (event: React.PointerEvent) => {
    if (event.button !== 0 && event.pointerType === 'mouse') return;
    try {
      (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
    } catch {
      // A pointer that is already released cannot be captured; drawing still
      // works, it just stops tracking outside the element.
    }
    drawing.current = true;
    const { x, y } = toLogical(event);
    const strokeId = String(newStrokeId());
    activeStroke.current = strokeId;
    batcherRef.current?.begin(strokeId, x, y);
    // Render locally at once. Waiting for the server would make the pen feel
    // detached from the cursor, which is instantly noticeable — and the sender
    // never receives its own wb:op, so without this the author would see
    // nothing at all.
    rendererRef.current?.upsertStroke({
      strokeId, authorId: user.id,
      tool, color, width, points: [Math.round(x), Math.round(y)], done: false,
    });
  };

  const lastCursor = useRef(0);
  const onPointerMove = (event: React.PointerEvent) => {
    const { x, y } = toLogical(event);
    const now = Date.now();
    if (now - lastCursor.current > 100) {
      lastCursor.current = now;
      emitVolatile('wb:cursor', { conversationId, x: Math.round(x), y: Math.round(y) });
    }
    if (!drawing.current) return;
    batcherRef.current?.push(x, y);

    /**
     * Append to the LOCAL render as well as the batcher.
     *
     * The batcher only seals and transmits. The author does not get their own
     * wb:op back from the server, so this is the only thing that draws the
     * stroke for the person actually drawing it.
     */
    const strokeId = activeStroke.current;
    if (strokeId) {
      rendererRef.current?.upsertStroke({
        strokeId, authorId: user.id,
        tool, color, width, points: [Math.round(x), Math.round(y)], done: false,
      });
    }
  };

  const onPointerUp = () => {
    if (!drawing.current) return;
    drawing.current = false;
    batcherRef.current?.end();
    // Move the finished stroke to the committed layer, so the live layer stops
    // redrawing it every frame.
    const strokeId = activeStroke.current;
    if (strokeId) {
      rendererRef.current?.upsertStroke({
        strokeId, authorId: user.id, tool, color, width, points: [], done: true,
      });
    }
    activeStroke.current = undefined;
  };

  const undo = async () => {
    const undoable = rendererRef.current?.undoableBy(user.id) ?? [];
    const strokeId = undoable[0];
    if (!strokeId) return;
    rendererRef.current?.setUndone(strokeId, true);
    await emit('wb:op', { conversationId, kind: 'undo', strokeId }).catch(() => {
      // Roll the optimistic tombstone back if the server refused it.
      rendererRef.current?.setUndone(strokeId, false);
    });
  };

  return (
    <section className="flex h-full flex-col bg-ink-950/60">
      <header className="flex flex-wrap items-center gap-2 border-b border-ink-700/70 px-4 py-2.5">
        <h2 className="mr-1 text-sm font-semibold text-ink-200">Whiteboard</h2>
        <Badge tone="accent">Strokes are encrypted</Badge>

        <div className="ml-2 flex items-center gap-1">
          {TOOLS.map((t) => (
            <button
              key={t.id}
              onClick={() => setTool(t.id)}
              aria-pressed={tool === t.id}
              title={t.label}
              className={`rounded-md px-2 py-1.5 text-sm transition-colors ${
                tool === t.id ? 'bg-ink-700 ring-1 ring-accent-500/40' : 'hover:bg-ink-800'
              }`}
            >
              {t.icon}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1">
          {COLORS.map((c) => (
            <button
              key={c}
              onClick={() => setColor(c)}
              aria-label={`Colour ${c}`}
              aria-pressed={color === c}
              className={`size-5 rounded-full ring-2 transition-transform ${
                color === c ? 'scale-110 ring-white' : 'ring-transparent'
              }`}
              style={{ background: c }}
            />
          ))}
        </div>

        <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
          Size
          <input
            type="range" min={2} max={24} value={width}
            onChange={(e) => setWidth(Number(e.target.value))}
            className="w-20 accent-[var(--color-accent-500)]"
          />
        </label>

        <div className="ml-auto flex items-center gap-1.5">
          <Button size="sm" variant="ghost" onClick={() => void undo()}>Undo</Button>
          <Button size="sm" variant="danger" onClick={() => setConfirmClear(true)}>Clear</Button>
          <Button size="sm" variant="subtle" onClick={onClose}>Close</Button>
        </div>
      </header>

      {truncated && (
        <p className="border-b border-warn/25 bg-warn/10 px-4 py-2 text-[11px] text-warn">
          This board reached its history limit, so the earliest strokes were trimmed.
        </p>
      )}
      {status && (
        <p className="border-b border-ink-700/50 px-4 py-2 text-[11px] text-ink-400" aria-live="polite">{status}</p>
      )}

      <div
        className="relative flex-1 touch-none bg-ink-900/50"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        style={{ cursor: 'crosshair' }}
      >
        <canvas ref={committedRef} className="absolute inset-0 size-full" />
        <canvas ref={liveRef} className="absolute inset-0 size-full" />
        {Object.entries(cursors).map(([id, c]) => (
          <span
            key={id}
            className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 text-[10px] font-medium"
            style={{
              left: `${(c.x / WB_CANVAS.width) * 100}%`,
              top: `${(c.y / WB_CANVAS.height) * 100}%`,
              color: c.color,
            }}
          >
            ● {c.name}
          </span>
        ))}
      </div>

      {confirmClear && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-ink-950/70 p-6">
          <div className="panel max-w-sm p-6">
            <p className="text-sm font-semibold text-ink-200">Clear the board for everyone?</p>
            <p className="mt-2 text-[13px] leading-relaxed text-ink-400">
              This cannot be undone, and every participant will be told that you did it.
            </p>
            <div className="mt-4 flex gap-2">
              <Button
                size="sm"
                variant="danger"
                onClick={() => {
                  setConfirmClear(false);
                  void emit('wb:op', { conversationId, kind: 'clear' }).catch(() => undefined);
                }}
              >
                Clear board
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirmClear(false)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
