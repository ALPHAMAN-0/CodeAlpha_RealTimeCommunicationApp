import { useEffect, useState } from 'react';
import { restore, logout } from './crypto/session.js';
import { request } from './lib/api.js';
import { connectSocket, disconnectSocket } from './lib/socket.js';
import { installBindings } from './realtime/bindings.js';
import { installSendConfirmation, loadConversations } from './realtime/chat.js';
import { clearCryptoCaches } from './crypto/e2ee.js';
import { useConversations } from './stores/conversations.store.js';
import { useMessages } from './stores/messages.store.js';
import { useSession } from './stores/session.store.js';
import { AuthScreen, RecoveryCodeScreen } from './features/auth/AuthScreen.js';
import { Sidebar } from './features/chat/Sidebar.js';
import { ChatView } from './features/chat/ChatView.js';
import { CallPanel } from './features/call/CallPanel.js';
import { WhiteboardPanel } from './features/whiteboard/WhiteboardPanel.js';
import { Badge, Button, EmptyState, Spinner } from './components/ui.js';

type Panel = 'chat' | 'call' | 'whiteboard';

export function App() {
  const { user, status, recoveryCode, connection } = useSession();
  const [demoMode, setDemoMode] = useState(false);
  const [activeId, setActiveId] = useState<string | undefined>();
  const [panel, setPanel] = useState<Panel>('chat');
  const [mobileSidebar, setMobileSidebar] = useState(true);

  // Restore a session on load: the refresh cookie yields a token, IndexedDB
  // yields the keys. Both are required — a token without keys can sign in but
  // cannot decrypt anything, so that is treated as no session at all.
  useEffect(() => {
    void (async () => {
      const session = await restore().catch(() => undefined);
      if (session) useSession.getState().setSession(session.user, session.priv);
      else useSession.getState().setStatus('signed-out');
      // Public endpoint on purpose: the sign-in screen needs this before any
      // token exists.
      const config = await request<{ demoMode?: boolean }>('/api/health/config').catch(() => undefined);
      setDemoMode(Boolean(config?.demoMode));
    })();
  }, []);

  useEffect(() => {
    if (status !== 'signed-in' || !user) return;
    const cleanup = installBindings();
    // The sender does not receive its own message:new, so the outbox ack is
    // what puts an outgoing message into the timeline.
    const stopConfirm = installSendConfirmation(user.id);
    useSession.getState().setConnection('connecting');
    connectSocket();
    void loadConversations().catch(() => undefined);
    return () => {
      cleanup();
      stopConfirm();
      disconnectSocket();
    };
  }, [status, user?.id]);

  if (status === 'loading') {
    return (
      <main className="grid min-h-full place-items-center">
        <Spinner label="Unlocking your keys…" />
      </main>
    );
  }

  if (status === 'signed-out' || !user) return <AuthScreen demoMode={demoMode} />;

  if (recoveryCode) {
    return (
      <RecoveryCodeScreen
        code={recoveryCode}
        onAcknowledge={() => useSession.getState().setRecoveryCode(undefined)}
      />
    );
  }

  const select = (conversationId: string) => {
    setActiveId(conversationId);
    setPanel('chat');
    setMobileSidebar(false);
  };

  const signOut = async () => {
    await logout(user.id);
    clearCryptoCaches();
    useConversations.getState().reset();
    useMessages.getState().reset();
    useSession.getState().signOut();
  };

  return (
    <div className="flex h-full flex-col">
      {connection !== 'online' && (
        <div
          className={`px-4 py-1.5 text-center text-[12px] ${
            connection === 'draining' ? 'bg-warn/15 text-warn' : 'bg-ink-800 text-ink-300'
          }`}
          role="status"
        >
          {connection === 'draining'
            ? 'The server is restarting. Reconnecting shortly — anything you send is queued.'
            : 'Reconnecting… messages you send are queued and will deliver automatically.'}
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <div className={`${mobileSidebar ? 'flex' : 'hidden'} md:flex`}>
          <Sidebar onSelect={select} />
        </div>

        <main className="flex min-w-0 flex-1 flex-col">
          <div className="flex items-center gap-2 border-b border-ink-700/70 px-3 py-1.5 md:hidden">
            <Button size="sm" variant="ghost" onClick={() => setMobileSidebar((v) => !v)}>
              {mobileSidebar ? 'Hide' : 'Chats'}
            </Button>
            <span className="ml-auto">
              <Button size="sm" variant="ghost" onClick={() => void signOut()}>Sign out</Button>
            </span>
          </div>

          {!activeId && (
            <EmptyState
              title="Pick a conversation"
              body="Everything you send is encrypted in this browser first. The server only ever holds ciphertext it cannot read."
            />
          )}

          {activeId && panel === 'chat' && (
            <ChatView
              conversationId={activeId}
              onStartCall={() => setPanel('call')}
              onOpenWhiteboard={() => setPanel('whiteboard')}
            />
          )}
          {activeId && panel === 'call' && (
            <CallPanel conversationId={activeId} onClose={() => setPanel('chat')} />
          )}
          {activeId && panel === 'whiteboard' && (
            <WhiteboardPanel conversationId={activeId} onClose={() => setPanel('chat')} />
          )}
        </main>

        <aside className="hidden w-11 flex-col items-center gap-2 border-l border-ink-700/70 py-3 lg:flex">
          <Badge tone={connection === 'online' ? 'good' : 'warn'}>
            {connection === 'online' ? '●' : '○'}
          </Badge>
          <div className="mt-auto">
            <Button size="sm" variant="ghost" onClick={() => void signOut()} aria-label="Sign out">
              ⏏
            </Button>
          </div>
        </aside>
      </div>
    </div>
  );
}
