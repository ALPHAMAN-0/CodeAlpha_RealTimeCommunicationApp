import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { FilePayload } from '@rtc/shared';
import { LIMITS } from '@rtc/shared';
import { emitVolatile } from '../../lib/socket.js';
import {
  dmPeerId, downloadAttachment, joinConversation, loadHistory, markRead,
  safetyNumberFor, sendFile, sendText,
} from '../../realtime/chat.js';
import { currentOutbox, outbox } from '../../realtime/Outbox.js';
import { useConversations } from '../../stores/conversations.store.js';
import { useMessages, type RenderedMessage } from '../../stores/messages.store.js';
import { useSession } from '../../stores/session.store.js';
import { acceptNewFingerprint } from '../../crypto/keystore.js';
import { forgetPeer, peerKeys } from '../../crypto/e2ee.js';
import {
  Avatar, Badge, Button, EmptyState, EncryptionBadge, Spinner,
  dayOf, formatBytes, timeOf,
} from '../../components/ui.js';

/** Shared empty array, so an absent value has a stable identity. */
const EMPTY: readonly string[] = [];

export function ChatView({
  conversationId,
  onStartCall,
  onOpenWhiteboard,
}: {
  conversationId: string;
  onStartCall: () => void;
  onOpenWhiteboard: () => void;
}) {
  const user = useSession((s) => s.user)!;
  const view = useConversations((s) => s.byId[conversationId]);
  /**
   * The selector must NOT allocate.
   *
   * `s.typing[id] ?? []` returns a fresh array every render, and zustand
   * compares snapshots with Object.is — so the store would look changed on
   * every render and re-render forever. The fallback belongs outside.
   */
  const typingIds = useConversations((s) => s.typing[conversationId]);
  const typing = typingIds ?? EMPTY;
  const presence = useConversations((s) => s.presence);
  const timelines = useMessages((s) => s.timelines[conversationId]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | undefined>();
  const scroller = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);

  const messages = useMemo(
    () => useMessages.getState().list(conversationId),
    // Recompute whenever the timeline object identity changes.
    [conversationId, timelines],
  );

  useEffect(() => {
    setLoading(true);
    setError(undefined);
    useConversations.getState().setActive(conversationId);
    joinConversation(conversationId)
      .catch(() => setError('Could not open this conversation.'))
      .finally(() => setLoading(false));
    return () => useConversations.getState().setActive(undefined);
  }, [conversationId]);

  // Mirror the outbox's optimistic rows into the timeline.
  useEffect(() => {
    const box = outbox(user.id);
    return box.subscribe((entries) => useMessages.getState().syncPending(entries));
  }, [user.id]);

  const latestSeq = messages.reduce((max, m) => Math.max(max, m.seq ?? 0), 0);

  // Only mark read while the newest message is actually on screen. Marking on
  // mount would clear the badge for a conversation the user scrolled away from.
  useEffect(() => {
    if (!loading && atBottom.current && latestSeq > 0) void markRead(conversationId, latestSeq);
  }, [conversationId, latestSeq, loading]);

  useEffect(() => {
    const el = scroller.current;
    if (el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [messages.length]);

  const onScroll = useCallback(() => {
    const el = scroller.current;
    if (!el) return;
    atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    // Infinite scroll upwards.
    if (el.scrollTop < 60 && timelines?.hasMore && timelines.oldestSeq) {
      void loadHistory(conversationId, timelines.oldestSeq);
    }
  }, [conversationId, timelines?.hasMore, timelines?.oldestSeq]);

  if (!view) {
    return <EmptyState title="Loading conversation" body="Fetching participants and keys…" />;
  }

  const peerId = dmPeerId(view.conversation, user.id);
  const peer = view.participants.find((p) => String(p.userId) === peerId);
  const title = view.conversation.type === 'group'
    ? view.participants.filter((p) => String(p.userId) !== user.id).map((p) => p.displayName).join(', ') || 'Group'
    : peer?.displayName ?? 'Direct message';
  const online = peerId ? presence[peerId]?.status === 'online' : undefined;
  const untrusted = view.untrustedPeers;

  return (
    <section className="flex h-full min-w-0 flex-col">
      <header className="flex items-center gap-3 border-b border-ink-700/70 px-4 py-3">
        <Avatar
          name={title}
          color={view.conversation.type === 'group' ? '#8b5cf6' : '#22c3d6'}
          {...(online !== undefined ? { online } : {})}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <h2 className="truncate text-sm font-semibold text-ink-200">{title}</h2>
            <EncryptionBadge verified={untrusted.length === 0} />
            {view.rekeyPending && <Badge tone="warn">Rotating keys</Badge>}
          </div>
          <p className="mt-0.5 truncate text-[11px] text-ink-400" aria-live="polite">
            {typing.length > 0
              ? `${typing.map((id) => view.participants.find((p) => String(p.userId) === id)?.displayName ?? 'Someone').join(', ')} is typing…`
              : view.conversation.type === 'group'
                ? `${view.participants.length} members`
                : online ? 'Online' : 'Offline'}
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <Button size="sm" variant="subtle" onClick={onOpenWhiteboard}>Whiteboard</Button>
          <Button size="sm" onClick={onStartCall}>Call</Button>
        </div>
      </header>

      {untrusted.length > 0 && <TrustBanner conversationId={conversationId} peerIds={untrusted} />}

      <div
        ref={scroller}
        onScroll={onScroll}
        className="flex-1 overflow-y-auto px-4 py-4"
        role="log"
        aria-live="polite"
        aria-label="Messages"
      >
        {loading && <div className="grid place-items-center py-8"><Spinner label="Decrypting messages…" /></div>}
        {error && <p className="rounded-lg border border-bad/25 bg-bad/10 p-3 text-sm text-bad">{error}</p>}
        {!loading && messages.length === 0 && (
          <EmptyState
            title="No messages yet"
            body="Say something. It will be encrypted in this browser before it leaves."
          />
        )}
        {timelines?.hasMore && messages.length > 0 && (
          <div className="mb-3 text-center">
            <Button size="sm" variant="ghost" onClick={() => void loadHistory(conversationId, timelines.oldestSeq ?? undefined)}>
              Load earlier messages
            </Button>
          </div>
        )}
        <ul className="space-y-1">
          {messages.map((m, i) => (
            <MessageRow
              key={m.id}
              message={m}
              mine={m.senderId === user.id || m.senderId === 'self'}
              sender={view.participants.find((p) => String(p.userId) === m.senderId)}
              showDay={i === 0 || dayOf(messages[i - 1]!.sentAt) !== dayOf(m.sentAt)}
              readByCount={
                m.seq === undefined ? 0
                : view.participants.filter((p) => String(p.userId) !== user.id && p.lastReadSeq >= m.seq!).length
              }
              othersCount={view.participants.length - 1}
            />
          ))}
        </ul>
      </div>

      <Composer conversationId={conversationId} disabled={view.rekeyPending || untrusted.length > 0} />
    </section>
  );
}

/**
 * A changed identity key blocks sending until a human decides.
 *
 * This is the one defence against a server that substituted a key before the
 * first message was ever exchanged — a signed key log proves tampering AFTER
 * first contact, but nothing except an out-of-band comparison covers the very
 * first fetch. So it is a blocking banner, not a toast.
 */
function TrustBanner({ conversationId, peerIds }: { conversationId: string; peerIds: string[] }) {
  const [safety, setSafety] = useState<string | undefined>();
  const peerId = peerIds[0]!;

  return (
    <div className="border-b border-warn/25 bg-warn/10 px-4 py-3">
      <p className="text-[13px] font-medium text-warn">This contact’s security code changed.</p>
      <p className="mt-1 text-xs leading-relaxed text-ink-300">
        Either they reinstalled, or someone is intercepting this conversation. Compare the code
        below with them over a channel you already trust — in person, or by phone — before
        continuing. Sending is paused until you do.
      </p>
      {safety && (
        <pre className="mt-2 overflow-x-auto rounded-md bg-ink-950/70 p-3 font-mono text-xs tracking-wider text-accent-400">
          {safety}
        </pre>
      )}
      <div className="mt-2.5 flex gap-2">
        <Button size="sm" variant="subtle" onClick={() => void safetyNumberFor(peerId).then(setSafety)}>
          Show security code
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={async () => {
            const keys = await peerKeys(peerId, { force: true });
            await acceptNewFingerprint(peerId, keys.fingerprint);
            forgetPeer(peerId);
            useConversations.getState().clearUntrusted(conversationId, peerId);
          }}
        >
          I verified it — continue
        </Button>
      </div>
    </div>
  );
}

function MessageRow({
  message, mine, sender, showDay, readByCount, othersCount,
}: {
  message: RenderedMessage;
  mine: boolean;
  sender: { displayName: string; avatarColor: string } | undefined;
  showDay: boolean;
  readByCount: number;
  othersCount: number;
}) {
  return (
    <>
      {showDay && (
        <li className="my-3 flex items-center gap-3" aria-hidden>
          <span className="h-px flex-1 bg-ink-700/60" />
          <span className="text-[11px] font-medium text-ink-400">{dayOf(message.sentAt)}</span>
          <span className="h-px flex-1 bg-ink-700/60" />
        </li>
      )}
      <li className={`flex gap-2.5 ${mine ? 'flex-row-reverse' : ''}`}>
        {!mine && (
          <Avatar name={sender?.displayName ?? '?'} color={sender?.avatarColor ?? '#2b3760'} size={28} />
        )}
        <div className={`max-w-[min(34rem,78%)] ${mine ? 'items-end text-right' : ''}`}>
          {!mine && sender && (
            <p className="mb-0.5 px-1 text-[11px] font-medium text-ink-400">{sender.displayName}</p>
          )}
          <div
            className={`rounded-2xl px-3.5 py-2 text-left text-sm leading-relaxed ${
              mine
                ? 'bg-accent-500/15 text-ink-200 ring-1 ring-accent-500/25'
                : 'bg-ink-800 text-ink-200 ring-1 ring-ink-700'
            } ${message.status === 'failed' ? 'ring-bad/40' : ''}`}
          >
            <MessageBody message={message} />
          </div>
          <div className={`mt-1 flex items-center gap-2 px-1 text-[11px] text-ink-400 ${mine ? 'justify-end' : ''}`}>
            {/* The CLIENT's timestamp, which is the one inside the authenticated AAD. */}
            <span>{timeOf(message.sentAt)}</span>
            {mine && <SendStatus message={message} readByCount={readByCount} othersCount={othersCount} />}
          </div>
        </div>
      </li>
    </>
  );
}

function MessageBody({ message }: { message: RenderedMessage }) {
  if (message.deletedAt) {
    return <span className="italic text-ink-400">This message was deleted</span>;
  }
  if (message.kind === 'file' && message.filePayload) {
    return <FileBubble payload={message.filePayload as FilePayload} caption={message.plaintext ?? ''} />;
  }
  if (message.plaintext === undefined) {
    return <Spinner label="Decrypting…" />;
  }
  if (message.plaintext === null) {
    // Distinguish "cannot decrypt" from "empty": the causes and the fixes are
    // completely different, and a blank bubble would look like a bug.
    return (
      <span className="text-ink-400">
        <span className="mr-1" aria-hidden>⚠</span>
        Could not decrypt this message with the keys on this device.
      </span>
    );
  }
  return <span className="whitespace-pre-wrap break-words">{message.plaintext}</span>;
}

function FileBubble({ payload, caption }: { payload: FilePayload; caption: string }) {
  const [busy, setBusy] = useState(false);
  const [warning, setWarning] = useState<string | undefined>();

  const open = async () => {
    setBusy(true);
    setWarning(undefined);
    try {
      const { url, revoke } = await downloadAttachment(payload);

      /**
       * Magic-byte sniffing AFTER decryption.
       *
       * This can only happen here: the server holds high-entropy ciphertext,
       * so any server-side content check would be decoration. The honest cost
       * of E2EE attachments is that no antivirus can scan them, so the least
       * we can do is tell the user when a file's real type disagrees with its
       * name.
       */
      const { fileTypeFromBuffer } = await import('file-type');
      const head = await fetch(url).then((r) => r.arrayBuffer());
      const sniffed = await fileTypeFromBuffer(new Uint8Array(head.slice(0, 4100)));
      const ext = payload.filename.split('.').pop()?.toLowerCase();
      if (sniffed && ext && sniffed.ext !== ext) {
        setWarning(`This file is named .${ext} but its contents are actually ${sniffed.ext}.`);
      }

      const a = Object.assign(document.createElement('a'), { href: url, download: payload.filename });
      a.click();
      setTimeout(revoke, 30_000);
    } catch {
      setWarning('Could not decrypt this attachment.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <button
        onClick={() => void open()}
        disabled={busy}
        className="flex w-full items-center gap-3 rounded-lg bg-ink-950/40 p-2.5 text-left transition-colors hover:bg-ink-950/70"
      >
        <span className="grid size-9 shrink-0 place-items-center rounded-md bg-violet-500/20 text-base" aria-hidden>📄</span>
        <span className="min-w-0 flex-1">
          <span className="block truncate text-[13px] font-medium text-ink-200">{payload.filename}</span>
          <span className="block text-[11px] text-ink-400">
            {formatBytes(payload.plainSize)} · {busy ? 'Decrypting…' : 'Click to decrypt and save'}
          </span>
        </span>
      </button>
      {warning && <p className="mt-1.5 text-[11px] text-warn">⚠ {warning}</p>}
      {caption && <p className="mt-1.5 whitespace-pre-wrap break-words">{caption}</p>}
    </div>
  );
}

function SendStatus({
  message, readByCount, othersCount,
}: { message: RenderedMessage; readByCount: number; othersCount: number }) {
  if (message.status === 'queued') return <span className="text-ink-400">Queued</span>;
  if (message.status === 'sending') return <span className="text-ink-400">Sending…</span>;
  if (message.status === 'failed') {
    return (
      <span className="flex items-center gap-1.5">
        <span className="text-bad">Failed</span>
        <button
          className="underline hover:text-ink-200"
          onClick={() => currentOutbox()?.retry(message.clientMsgId)}
        >
          Retry
        </button>
        <button
          className="underline hover:text-ink-200"
          onClick={() => currentOutbox()?.discard(message.clientMsgId)}
        >
          Discard
        </button>
      </span>
    );
  }
  if (readByCount > 0) {
    return <span className="text-accent-400">{othersCount > 1 ? `Read by ${readByCount}` : 'Read'}</span>;
  }
  return <span className="text-ink-400">Sent</span>;
}

function Composer({ conversationId, disabled }: { conversationId: string; disabled: boolean }) {
  const [text, setText] = useState('');
  const [uploading, setUploading] = useState<number | undefined>();
  const [error, setError] = useState<string | undefined>();
  const typingSentAt = useRef(0);
  const fileInput = useRef<HTMLInputElement>(null);

  const send = async () => {
    if (!text.trim() || disabled) return;
    const body = text;
    setText('');
    setError(undefined);
    try {
      await sendText(conversationId, body);
      emitVolatile('typing:stop', { conversationId });
    } catch (err) {
      setText(body);
      setError((err as Error).message);
    }
  };

  const onType = (value: string) => {
    setText(value);
    // Throttled: re-emitting on every keystroke would be pure noise, and the
    // server refreshes its own expiry timer on each event it does receive.
    const now = Date.now();
    if (value && now - typingSentAt.current > 2500) {
      typingSentAt.current = now;
      emitVolatile('typing:start', { conversationId });
    }
  };

  const pickFile = async (file: File | undefined) => {
    if (!file) return;
    if (file.size > LIMITS.UPLOAD_BYTES_MAX) {
      setError(`Files must be under ${formatBytes(LIMITS.UPLOAD_BYTES_MAX)}.`);
      return;
    }
    setError(undefined);
    setUploading(0);
    try {
      await sendFile(conversationId, file, setUploading);
    } catch {
      setError('Upload failed. Please try again.');
    } finally {
      setUploading(undefined);
      if (fileInput.current) fileInput.current.value = '';
    }
  };

  return (
    <div className="border-t border-ink-700/70 px-4 py-3">
      {error && <p className="mb-2 text-[13px] text-bad" role="alert">{error}</p>}
      {uploading !== undefined && (
        <div className="mb-2 flex items-center gap-2 text-xs text-ink-400">
          <span className="h-1 flex-1 overflow-hidden rounded-full bg-ink-800">
            <span className="block h-full bg-accent-500 transition-[width]" style={{ width: `${uploading * 100}%` }} />
          </span>
          <span>Encrypting &amp; uploading {Math.round(uploading * 100)}%</span>
        </div>
      )}
      <div className="flex items-end gap-2">
        <input
          ref={fileInput}
          type="file"
          className="hidden"
          onChange={(e) => void pickFile(e.target.files?.[0])}
        />
        <Button
          variant="ghost"
          size="sm"
          disabled={disabled || uploading !== undefined}
          onClick={() => fileInput.current?.click()}
          aria-label="Attach a file"
        >
          📎
        </Button>
        <textarea
          value={text}
          onChange={(e) => onType(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void send();
            }
          }}
          onBlur={() => emitVolatile('typing:stop', { conversationId })}
          disabled={disabled}
          rows={1}
          maxLength={LIMITS.MESSAGE_TEXT_MAX}
          placeholder={disabled ? 'Sending is paused' : 'Write an encrypted message…'}
          className="max-h-32 min-h-[2.6rem] flex-1 resize-none rounded-xl border border-ink-700 bg-ink-950/60 px-3 py-2.5 text-sm text-ink-200 placeholder:text-ink-400 focus:border-accent-500 focus:outline-none disabled:opacity-50"
        />
        <Button size="sm" disabled={disabled || !text.trim()} onClick={() => void send()}>
          Send
        </Button>
      </div>
    </div>
  );
}
