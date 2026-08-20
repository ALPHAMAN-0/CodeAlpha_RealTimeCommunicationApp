import { useState } from 'react';
import type { ConversationDTO } from '@rtc/shared';
import { request } from '../../lib/api.js';
import { createDm, createGroup, dmPeerId } from '../../realtime/chat.js';
import { useConversations } from '../../stores/conversations.store.js';
import { useSession } from '../../stores/session.store.js';
import { Avatar, Badge, Button, EmptyState, dayOf, inputClass } from '../../components/ui.js';

interface Directory {
  users: Array<{ id: string; displayName: string; avatarColor: string }>;
}

function titleFor(c: ConversationDTO, myId: string, names: Map<string, string>): string {
  if (c.type === 'group') {
    // The group title is E2EE and only readable once the room key is held, so
    // the fallback names members rather than showing a bare uuid.
    const others = c.memberIds.map(String).filter((id) => id !== myId).map((id) => names.get(id) ?? 'Member');
    return others.length > 0 ? others.slice(0, 3).join(', ') + (others.length > 3 ? `+${others.length - 3}` : '') : 'Group';
  }
  const peer = dmPeerId(c, myId);
  return (peer && names.get(peer)) ?? 'Direct message';
}

export function Sidebar({ onSelect }: { onSelect: (conversationId: string) => void }) {
  const user = useSession((s) => s.user)!;
  const { order, byId, activeId, presence, profiles } = useConversations();
  const [composing, setComposing] = useState(false);
  const [directory, setDirectory] = useState<Directory['users']>([]);
  const [selected, setSelected] = useState<string[]>([]);
  const [query, setQuery] = useState('');

  // Profiles arrive with the conversation list, so labels are correct on first
  // paint rather than after joining each conversation.
  const names = new Map<string, string>();
  for (const p of Object.values(profiles)) names.set(p.userId, p.displayName);
  for (const view of Object.values(byId)) {
    for (const p of view.participants) names.set(String(p.userId), p.displayName);
  }
  for (const u of directory) names.set(u.id, u.displayName);

  const openComposer = async () => {
    setComposing(true);
    const dir = await request<Directory>('/api/users').catch(() => ({ users: [] }));
    setDirectory(dir.users.filter((u) => u.id !== user.id));
    useConversations.getState().setProfiles(
      dir.users.map((u) => ({ userId: u.id, displayName: u.displayName, avatarColor: u.avatarColor, keyVersion: 1 })),
    );
  };

  const start = async () => {
    if (selected.length === 0) return;
    const conversation = selected.length === 1
      ? await createDm(selected[0]!)
      : await createGroup(selected);
    setComposing(false);
    setSelected([]);
    onSelect(String(conversation.id));
  };

  const filtered = directory.filter((u) =>
    u.displayName.toLowerCase().includes(query.trim().toLowerCase()),
  );

  return (
    <aside className="flex h-full w-full flex-col border-r border-ink-700/70 bg-ink-900/40 md:w-[19rem]">
      <header className="flex items-center justify-between gap-2 border-b border-ink-700/70 px-4 py-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <Avatar name={user.displayName} color={user.avatarColor} size={32} online />
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-ink-200">{user.displayName}</p>
            <p className="truncate text-[11px] text-ink-400">Keys held locally</p>
          </div>
        </div>
        <Button size="sm" variant="subtle" onClick={() => void openComposer()} aria-label="New conversation">
          New
        </Button>
      </header>

      {composing && (
        <div className="border-b border-ink-700/70 bg-ink-950/40 p-3">
          <input
            className={inputClass}
            placeholder="Search people…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
          />
          <div className="mt-2 max-h-52 overflow-y-auto">
            {filtered.length === 0 && <p className="px-1 py-3 text-xs text-ink-400">No other accounts yet.</p>}
            {filtered.map((u) => {
              const picked = selected.includes(u.id);
              return (
                <button
                  key={u.id}
                  onClick={() => setSelected((s) => (picked ? s.filter((x) => x !== u.id) : [...s, u.id]))}
                  className={`flex w-full items-center gap-2.5 rounded-lg px-2 py-2 text-left text-sm transition-colors ${
                    picked ? 'bg-accent-500/12 text-accent-400' : 'text-ink-300 hover:bg-ink-800'
                  }`}
                >
                  <Avatar name={u.displayName} color={u.avatarColor} size={26} />
                  <span className="truncate">{u.displayName}</span>
                  {picked && <span className="ml-auto text-xs">✓</span>}
                </button>
              );
            })}
          </div>
          <div className="mt-2 flex gap-2">
            <Button size="sm" disabled={selected.length === 0} onClick={() => void start()}>
              {selected.length > 1 ? `Create group (${selected.length})` : 'Start chat'}
            </Button>
            <Button size="sm" variant="ghost" onClick={() => { setComposing(false); setSelected([]); }}>
              Cancel
            </Button>
          </div>
        </div>
      )}

      <nav className="flex-1 overflow-y-auto p-2" aria-label="Conversations">
        {order.length === 0 && !composing && (
          <EmptyState
            title="No conversations yet"
            body="Start one to see end-to-end encrypted messaging, calls and a shared whiteboard."
            action={<Button size="sm" onClick={() => void openComposer()}>New conversation</Button>}
          />
        )}
        {order.map((id) => {
          const view = byId[id]!;
          const peer = dmPeerId(view.conversation, user.id);
          const online = peer ? presence[peer]?.status === 'online' : undefined;
          const title = titleFor(view.conversation, user.id, names);
          const last = view.conversation.lastMessage;
          return (
            <button
              key={id}
              onClick={() => onSelect(id)}
              aria-current={activeId === id ? 'true' : undefined}
              className={`mb-1 flex w-full items-center gap-3 rounded-xl px-2.5 py-2.5 text-left transition-colors ${
                activeId === id ? 'bg-ink-800 ring-1 ring-ink-600' : 'hover:bg-ink-800/60'
              }`}
            >
              <Avatar
                name={title}
                color={view.conversation.type === 'group' ? '#8b5cf6' : '#22c3d6'}
                {...(online !== undefined ? { online } : {})}
              />
              <span className="min-w-0 flex-1">
                <span className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-sm font-medium text-ink-200">{title}</span>
                  {last && <span className="shrink-0 text-[11px] text-ink-400">{dayOf(last.createdAt)}</span>}
                </span>
                <span className="mt-0.5 flex items-center gap-1.5">
                  {view.rekeyPending
                    ? <span className="text-[11px] text-warn">Rotating keys…</span>
                    : <span className="truncate text-[11px] text-ink-400">
                        {last ? (last.kind === 'file' ? 'Sent a file' : 'Encrypted message') : 'No messages yet'}
                      </span>}
                </span>
              </span>
              {view.unread > 0 && <Badge tone="accent">{view.unread}</Badge>}
            </button>
          );
        })}
      </nav>

      <footer className="border-t border-ink-700/70 px-4 py-2.5">
        <p className="text-[11px] leading-relaxed text-ink-400">
          Messages are sealed in this browser. The server stores ciphertext it cannot read.
        </p>
      </footer>
    </aside>
  );
}
