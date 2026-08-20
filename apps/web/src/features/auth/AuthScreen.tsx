import { useState } from 'react';
import { login, register } from '../../crypto/session.js';
import { useSession } from '../../stores/session.store.js';
import { Button, Field, inputClass } from '../../components/ui.js';

type Mode = 'sign-in' | 'sign-up';

const DEMO_USERS = [
  { name: 'Alice', email: 'alice@demo.dev' },
  { name: 'Bob', email: 'bob@demo.dev' },
  { name: 'Carol', email: 'carol@demo.dev' },
];

export function AuthScreen({ demoMode }: { demoMode: boolean }) {
  const [mode, setMode] = useState<Mode>('sign-in');
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState<string | undefined>();
  const setSession = useSession((s) => s.setSession);
  const setRecoveryCode = useSession((s) => s.setRecoveryCode);
  const error = useSession((s) => s.error);
  const setError = useSession((s) => s.setError);

  /**
   * Turn a failure into something actionable.
   *
   * The generic fallback used to swallow genuinely different problems — a
   * blocked WebAssembly compile reported itself as "account not found", which
   * sent debugging in entirely the wrong direction. Anything that is not a
   * recognised API error is surfaced with its real message.
   */
  const describe = (err: unknown): string => {
    const code = (err as { code?: string }).code;
    switch (code) {
      case 'INVALID_CREDENTIALS': return 'Incorrect email or password.';
      case 'EMAIL_TAKEN': return 'That email is already registered.';
      case 'ACCOUNT_LOCKED': return 'Too many attempts. Try again shortly.';
      case 'RATE_LIMITED': return 'Too many attempts. Try again shortly.';
      case 'VALIDATION': return 'Please check the details you entered.';
      default: break;
    }
    const message = err instanceof Error ? err.message : String(err);
    if (/WebAssembly|Content Security/i.test(message)) {
      return 'Your browser blocked the key-derivation module. Check the console for a Content Security Policy violation.';
    }
    if (/NetworkError|Failed to fetch/i.test(message)) {
      return 'Could not reach the server. Is it running?';
    }
    return message || 'Something went wrong. Please try again.';
  };

  const submit = async (event?: React.FormEvent) => {
    event?.preventDefault();
    setError(undefined);
    // Argon2id at 64 MiB takes a moment; saying so beats an unexplained pause.
    setBusy(mode === 'sign-up' ? 'Generating your encryption keys…' : 'Deriving your key…');
    try {
      if (mode === 'sign-up') {
        const { session, recoveryCode } = await register(email, displayName || email.split('@')[0]!, password);
        setRecoveryCode(recoveryCode);
        setSession(session.user, session.priv);
      } else {
        const session = await login(email, password);
        setSession(session.user, session.priv);
      }
    } catch (err) {
      setError(describe(err));
    } finally {
      setBusy(undefined);
    }
  };

  const demoLogin = async (demoEmail: string) => {
    setEmail(demoEmail);
    setPassword('demo1234');
    setError(undefined);
    setBusy('Signing in…');
    try {
      const session = await login(demoEmail, 'demo1234');
      setSession(session.user, session.priv);
    } catch (err) {
      setError(
        (err as { code?: string }).code === 'INVALID_CREDENTIALS'
          ? 'Demo accounts are not seeded yet. Run `pnpm seed`.'
          : describe(err),
      );
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <main className="grid min-h-full place-items-center p-6">
      <div className="w-full max-w-[26rem]">
        <div className="mb-7 text-center">
          <div className="mb-3 inline-flex size-12 items-center justify-center rounded-2xl bg-gradient-to-br from-accent-500 to-violet-500 text-2xl">
            🔐
          </div>
          <h1 className="text-[1.6rem] font-semibold tracking-tight text-white">Cipher</h1>
          <p className="mt-1.5 text-sm text-ink-400">
            End-to-end encrypted chat, calls and whiteboard.
          </p>
        </div>

        <form onSubmit={submit} className="panel space-y-4 p-6">
          <div className="flex gap-1 rounded-lg bg-ink-950/60 p-1" role="tablist">
            {(['sign-in', 'sign-up'] as Mode[]).map((m) => (
              <button
                key={m}
                type="button"
                role="tab"
                aria-selected={mode === m}
                onClick={() => { setMode(m); setError(undefined); }}
                className={`flex-1 rounded-md px-3 py-1.5 text-[13px] font-medium transition-colors ${
                  mode === m ? 'bg-ink-700 text-white' : 'text-ink-400 hover:text-ink-200'
                }`}
              >
                {m === 'sign-in' ? 'Sign in' : 'Create account'}
              </button>
            ))}
          </div>

          {mode === 'sign-up' && (
            <Field label="Display name">
              <input
                className={inputClass}
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Ada Lovelace"
                autoComplete="name"
                maxLength={40}
              />
            </Field>
          )}

          <Field label="Email">
            <input
              className={inputClass}
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              autoComplete="email"
            />
          </Field>

          <Field
            label="Password"
            hint={
              mode === 'sign-up'
                ? 'This password encrypts your messages. The server never receives it, and cannot reset it for you.'
                : undefined
            }
          >
            <input
              className={inputClass}
              type="password"
              required
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              autoComplete={mode === 'sign-up' ? 'new-password' : 'current-password'}
            />
          </Field>

          {error && (
            <p className="rounded-lg border border-bad/25 bg-bad/10 px-3 py-2 text-[13px] text-bad" role="alert">
              {error}
            </p>
          )}

          <Button type="submit" disabled={Boolean(busy)} className="w-full">
            {busy ?? (mode === 'sign-up' ? 'Create account' : 'Sign in')}
          </Button>

          {busy && (
            <p className="text-center text-xs text-ink-400">
              Your keys are generated and used entirely in this browser.
            </p>
          )}
        </form>

        {demoMode && (
          <div className="panel mt-4 p-5">
            <p className="mb-3 text-[13px] font-medium text-ink-300">Demo accounts</p>
            <div className="grid grid-cols-3 gap-2">
              {DEMO_USERS.map((u) => (
                <Button
                  key={u.email}
                  variant="subtle"
                  size="sm"
                  disabled={Boolean(busy)}
                  onClick={() => void demoLogin(u.email)}
                >
                  {u.name}
                </Button>
              ))}
            </div>
            <p className="mt-3 text-xs leading-relaxed text-ink-400">
              Open a second account in a new window to see real-time delivery, calls and the
              shared whiteboard between two people.
            </p>
            <Button
              variant="ghost"
              size="sm"
              className="mt-2 w-full"
              onClick={() => window.open(window.location.href, '_blank', 'noopener,width=1200,height=850')}
            >
              Open a second window ↗
            </Button>
          </div>
        )}
      </div>
    </main>
  );
}

/**
 * The recovery code, shown exactly once.
 *
 * This screen is blocking and cannot be skipped with a click-through, because
 * losing this code means losing every message permanently — the server holds
 * no key that could recover them. Making it dismissible would be quietly
 * setting users up for irreversible data loss.
 */
export function RecoveryCodeScreen({ code, onAcknowledge }: { code: string; onAcknowledge: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);

  return (
    <main className="grid min-h-full place-items-center p-6">
      <div className="panel w-full max-w-lg p-7">
        <h2 className="text-lg font-semibold text-white">Save your recovery code</h2>
        <p className="mt-2 text-sm leading-relaxed text-ink-300">
          This is the only way to recover your message history if you forget your password.
          It is shown once and is not stored anywhere we can read.
        </p>

        <pre className="mt-5 overflow-x-auto rounded-lg border border-accent-500/25 bg-ink-950/70 p-4 font-mono text-[13px] leading-relaxed tracking-wider text-accent-400">
          {code}
        </pre>

        <div className="mt-3 flex gap-2">
          <Button
            variant="subtle"
            size="sm"
            onClick={() => {
              void navigator.clipboard.writeText(code).then(() => setCopied(true));
            }}
          >
            {copied ? 'Copied' : 'Copy code'}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              const blob = new Blob([`Cipher recovery code\n\n${code}\n`], { type: 'text/plain' });
              const url = URL.createObjectURL(blob);
              const a = Object.assign(document.createElement('a'), { href: url, download: 'cipher-recovery-code.txt' });
              a.click();
              URL.revokeObjectURL(url);
            }}
          >
            Download
          </Button>
        </div>

        <label className="mt-6 flex items-start gap-2.5 text-[13px] text-ink-300">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="mt-0.5 size-4 accent-[var(--color-accent-500)]"
          />
          <span>
            I have saved this code somewhere safe. I understand that without it, a forgotten
            password means my message history is gone for good.
          </span>
        </label>

        <Button className="mt-5 w-full" disabled={!confirmed} onClick={onAcknowledge}>
          Continue
        </Button>
      </div>
    </main>
  );
}
