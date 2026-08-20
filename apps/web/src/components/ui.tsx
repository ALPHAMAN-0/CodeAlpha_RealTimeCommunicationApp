import type { ButtonHTMLAttributes, ReactNode } from 'react';

export function Avatar({
  name, color, size = 36, online, ring,
}: { name: string; color: string; size?: number; online?: boolean; ring?: boolean }) {
  const initials = name
    .split(/\s+/)
    .slice(0, 2)
    .map((p) => p[0]?.toUpperCase() ?? '')
    .join('');
  return (
    <span className="relative inline-flex shrink-0" style={{ width: size, height: size }}>
      <span
        aria-hidden
        className={`grid place-items-center rounded-full font-semibold text-ink-950 ${ring ? 'ring-2 ring-accent-400' : ''}`}
        style={{ width: size, height: size, background: color, fontSize: size * 0.38 }}
      >
        {initials || '?'}
      </span>
      {online !== undefined && (
        <span
          className={`absolute -right-0.5 -bottom-0.5 rounded-full border-2 border-ink-900 ${
            online ? 'bg-good' : 'bg-ink-600'
          }`}
          style={{ width: size * 0.3, height: size * 0.3 }}
        />
      )}
    </span>
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger' | 'subtle';
  size?: 'sm' | 'md';
};

export function Button({ variant = 'primary', size = 'md', className = '', ...rest }: ButtonProps) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45';
  const sizes = size === 'sm' ? 'px-2.5 py-1.5 text-[13px]' : 'px-4 py-2.5 text-sm';
  const variants = {
    primary: 'bg-accent-500 text-ink-950 hover:bg-accent-400',
    ghost: 'text-ink-300 hover:bg-ink-800 hover:text-ink-200',
    subtle: 'bg-ink-800 text-ink-200 hover:bg-ink-700 border border-ink-700',
    danger: 'bg-bad/15 text-bad hover:bg-bad/25 border border-bad/30',
  }[variant];
  return <button className={`${base} ${sizes} ${variants} ${className}`} {...rest} />;
}

export function Field({
  label, hint, children,
}: { label: string; hint?: ReactNode; children: ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[13px] font-medium text-ink-300">{label}</span>
      {children}
      {hint && <span className="mt-1.5 block text-xs leading-relaxed text-ink-400">{hint}</span>}
    </label>
  );
}

export const inputClass =
  'w-full rounded-lg border border-ink-700 bg-ink-950/60 px-3 py-2.5 text-sm text-ink-200 ' +
  'placeholder:text-ink-400 focus:border-accent-500 focus:outline-none';

export function Badge({ tone = 'neutral', children }: { tone?: 'neutral' | 'good' | 'warn' | 'bad' | 'accent'; children: ReactNode }) {
  const tones = {
    neutral: 'bg-ink-800 text-ink-300 border-ink-700',
    good: 'bg-good/12 text-good border-good/25',
    warn: 'bg-warn/12 text-warn border-warn/25',
    bad: 'bg-bad/12 text-bad border-bad/25',
    accent: 'bg-accent-500/12 text-accent-400 border-accent-500/25',
  }[tone];
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium ${tones}`}>
      {children}
    </span>
  );
}

export function Spinner({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-xs text-ink-400" role="status">
      <span className="size-3 animate-spin rounded-full border-2 border-ink-600 border-t-accent-400" />
      {label}
    </span>
  );
}

export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="grid h-full place-items-center p-8 text-center">
      <div className="max-w-sm">
        <p className="text-base font-semibold text-ink-200">{title}</p>
        <p className="mt-2 text-sm leading-relaxed text-ink-400">{body}</p>
        {action && <div className="mt-5">{action}</div>}
      </div>
    </div>
  );
}

/** The lock badge. Deliberately reads as a fact, never as marketing. */
export function EncryptionBadge({ verified }: { verified: boolean }) {
  return (
    <Badge tone={verified ? 'good' : 'accent'}>
      <svg viewBox="0 0 16 16" className="size-3" fill="currentColor" aria-hidden>
        <path d="M8 1a3.5 3.5 0 0 0-3.5 3.5V6H4a1.5 1.5 0 0 0-1.5 1.5v5A1.5 1.5 0 0 0 4 14h8a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 12 6h-.5V4.5A3.5 3.5 0 0 0 8 1Zm2 5H6V4.5a2 2 0 1 1 4 0V6Z" />
      </svg>
      {verified ? 'Verified' : 'Encrypted'}
    </Badge>
  );
}

export const timeOf = (ms: number): string =>
  new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

export const dayOf = (ms: number): string => {
  const date = new Date(ms);
  const today = new Date();
  const yesterday = new Date(today.getTime() - 86_400_000);
  if (date.toDateString() === today.toDateString()) return 'Today';
  if (date.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
};

export const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
};
