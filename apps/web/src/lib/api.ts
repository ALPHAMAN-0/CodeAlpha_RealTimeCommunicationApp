import type { WrappedIdentity } from '@rtc/shared';

/**
 * HTTP client.
 *
 * The access token lives in a module-scoped closure and NOTHING writes it to
 * localStorage or sessionStorage. That is the single most important decision
 * in this file: an XSS that can read storage would otherwise obtain a durable
 * credential, and in this app the same XSS is already adjacent to the E2EE
 * keys.
 *
 * The cost is real and accepted: `<img src>` and `<a href>` cannot
 * authenticate, so attachments are fetched and turned into blob: URLs instead.
 */
let accessToken: string | undefined;
let accessExpiresAt = 0;

export const setAccessToken = (token: string, expiresAt: number): void => {
  accessToken = token;
  accessExpiresAt = expiresAt;
};
export const getAccessToken = (): string | undefined => accessToken;
export const clearAccessToken = (): void => {
  accessToken = undefined;
  accessExpiresAt = 0;
};
export const tokenExpiresAt = (): number => accessExpiresAt;

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, readonly requestId?: string) {
    super(`${code} (${status})`);
    this.name = 'ApiError';
  }
}

const csrfFromCookie = (): string | undefined => {
  for (const part of document.cookie.split('; ')) {
    const i = part.indexOf('=');
    const name = part.slice(0, i);
    if (name === '__Host-csrf' || name === 'csrf') return decodeURIComponent(part.slice(i + 1));
  }
  return undefined;
};

/**
 * Single-flight refresh, coordinated across tabs.
 *
 * Two things are being prevented. Within a tab, a burst of 401s must trigger
 * ONE refresh, not one per request. Across tabs, only one tab may call
 * /refresh — rotation is destructive, so two tabs racing would have the loser
 * present a token that was just consumed, which reads as reuse and revokes the
 * whole family. The BroadcastChannel is what turns "randomly logged out" into
 * "works".
 */
let inFlightRefresh: Promise<boolean> | undefined;
const channel: BroadcastChannel | undefined =
  typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('rtc-auth') : undefined;

channel?.addEventListener('message', (event) => {
  const data = event.data as { type: string; token?: string; expiresAt?: number };
  if (data.type === 'refreshed' && data.token && data.expiresAt) {
    setAccessToken(data.token, data.expiresAt);
  }
  if (data.type === 'logout') clearAccessToken();
});

export interface SessionResponse {
  user: { id: string; displayName: string; avatarColor: string; keyVersion: number; email?: string };
  accessToken: string;
  accessExpiresAt: number;
  identity: { passwordWrap: WrappedIdentity };
}

async function doRefresh(): Promise<boolean> {
  const csrf = csrfFromCookie();
  if (!csrf) return false;
  const res = await fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'x-csrf-token': csrf },
  });
  if (!res.ok) return false;
  const body = (await res.json()) as SessionResponse;
  setAccessToken(body.accessToken, body.accessExpiresAt);
  channel?.postMessage({ type: 'refreshed', token: body.accessToken, expiresAt: body.accessExpiresAt });
  return true;
}

export function refreshSession(): Promise<boolean> {
  inFlightRefresh ??= doRefresh().finally(() => {
    inFlightRefresh = undefined;
  });
  return inFlightRefresh;
}

export interface RequestOptions {
  method?: string;
  body?: unknown;
  /** Set internally to stop a refresh loop. */
  retried?: boolean;
  signal?: AbortSignal;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (accessToken) headers.authorization = `Bearer ${accessToken}`;
  const csrf = csrfFromCookie();
  if (csrf) headers['x-csrf-token'] = csrf;

  const res = await fetch(path, {
    method: opts.method ?? 'GET',
    credentials: 'same-origin',
    headers,
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
    ...(opts.signal ? { signal: opts.signal } : {}),
  });

  if (res.status === 401 && !opts.retried) {
    const body = (await res.json().catch(() => null)) as { error?: { code?: string } } | null;
    // Refresh and retry ONCE, and only for an expired token. Retrying a
    // REFRESH_INVALID would loop against a session that is gone for good.
    if (body?.error?.code === 'TOKEN_EXPIRED' && (await refreshSession())) {
      return request<T>(path, { ...opts, retried: true });
    }
    throw new ApiError(401, body?.error?.code ?? 'UNAUTHENTICATED');
  }

  if (!res.ok) {
    const body = (await res.json().catch(() => null)) as
      | { error?: { code?: string; requestId?: string } }
      | null;
    throw new ApiError(res.status, body?.error?.code ?? 'UNKNOWN', body?.error?.requestId);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const announceLogout = (): void => channel?.postMessage({ type: 'logout' });

/**
 * Fetch an encrypted attachment.
 *
 * A plain link cannot be used: the bearer token lives only in memory, so the
 * browser would send an unauthenticated request. Fetching and decrypting into
 * a blob: URL also keeps attacker-supplied bytes off the app origin entirely.
 */
export async function fetchAttachment(attachmentId: string): Promise<Uint8Array> {
  const res = await fetch(`/api/files/${attachmentId}`, {
    credentials: 'same-origin',
    headers: accessToken ? { authorization: `Bearer ${accessToken}` } : {},
  });
  if (res.status === 401 && (await refreshSession())) return fetchAttachment(attachmentId);
  if (!res.ok) throw new ApiError(res.status, 'DOWNLOAD_FAILED');
  return new Uint8Array(await res.arrayBuffer());
}

export async function uploadAttachment(
  conversationId: string,
  cipher: Uint8Array,
  onProgress?: (fraction: number) => void,
): Promise<{ attachmentId: string; cipherSize: number }> {
  const form = new FormData();
  form.append('file', new Blob([cipher as unknown as BlobPart]), 'blob');

  // XHR rather than fetch: fetch still has no upload-progress event, and a
  // silent progress bar on a 25 MB file is a bad experience.
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api/files/${conversationId}`);
    if (accessToken) xhr.setRequestHeader('authorization', `Bearer ${accessToken}`);
    xhr.withCredentials = true;
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total);
    });
    xhr.addEventListener('load', () => {
      if (xhr.status === 201) resolve(JSON.parse(xhr.responseText));
      else reject(new ApiError(xhr.status, 'UPLOAD_FAILED'));
    });
    xhr.addEventListener('error', () => reject(new ApiError(0, 'UPLOAD_FAILED')));
    xhr.send(form);
  });
}
