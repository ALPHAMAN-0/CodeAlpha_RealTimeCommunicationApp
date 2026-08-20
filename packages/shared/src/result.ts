/**
 * Every socket ack in this app is an `Ack<T>`. Never a bare value, never
 * `(err, data)`. One shape means one error path, and `retryable` means the
 * client's retry logic never has to guess.
 */
export type ErrorCode =
  | 'UNAUTHENTICATED'
  | 'TOKEN_EXPIRED'
  | 'AUTH_REVOKED'
  | 'FORBIDDEN'
  | 'NOT_A_MEMBER'
  | 'NOT_JOINED'
  | 'BAD_TARGET'
  | 'NOT_FOUND'
  | 'VALIDATION'
  | 'RATE_LIMITED'
  | 'ROOM_FULL'
  | 'REKEY_PENDING'
  | 'CONFLICT'
  | 'PAYLOAD_TOO_LARGE'
  | 'INTERNAL';

export interface AppError {
  code: ErrorCode;
  message: string;
  /**
   * True => the client MAY retry the byte-identical payload (same clientMsgId).
   * False => retrying will fail the same way; surface it to the user instead.
   * Auto-retrying a VALIDATION or FORBIDDEN error is an infinite loop.
   */
  retryable: boolean;
  retryAfterMs?: number;
  /** Zod `flatten()` output for VALIDATION. Never echoes the offending payload. */
  details?: unknown;
}

export type Ack<T> = { ok: true; data: T } | { ok: false; error: AppError };

export const ok = <T>(data: T): Ack<T> => ({ ok: true, data });
export const fail = (error: AppError): Ack<never> => ({ ok: false, error });

/** Which codes are safe to retry automatically. Single source of truth. */
const RETRYABLE: ReadonlySet<ErrorCode> = new Set<ErrorCode>([
  'RATE_LIMITED',
  'TOKEN_EXPIRED',
  'REKEY_PENDING',
  'INTERNAL',
]);

export const isRetryable = (code: ErrorCode): boolean => RETRYABLE.has(code);

export class RtcError extends Error {
  readonly code: ErrorCode;
  readonly retryAfterMs?: number;
  readonly details?: unknown;

  constructor(code: ErrorCode, message: string, opts?: { retryAfterMs?: number; details?: unknown }) {
    super(message);
    this.name = 'RtcError';
    this.code = code;
    if (opts?.retryAfterMs !== undefined) this.retryAfterMs = opts.retryAfterMs;
    if (opts?.details !== undefined) this.details = opts.details;
  }

  toAppError(): AppError {
    return {
      code: this.code,
      message: this.message,
      retryable: isRetryable(this.code),
      ...(this.retryAfterMs !== undefined ? { retryAfterMs: this.retryAfterMs } : {}),
      ...(this.details !== undefined ? { details: this.details } : {}),
    };
  }
}

export const errUnauthenticated = (m = 'Not authenticated') => new RtcError('UNAUTHENTICATED', m);
export const errForbidden = (m = 'Forbidden') => new RtcError('FORBIDDEN', m);
export const errNotMember = (m = 'Not a member of this conversation') => new RtcError('NOT_A_MEMBER', m);
export const errNotFound = (m = 'Not found') => new RtcError('NOT_FOUND', m);
export const errValidation = (m = 'Invalid payload', details?: unknown) =>
  new RtcError('VALIDATION', m, details !== undefined ? { details } : undefined);
export const errRateLimited = (retryAfterMs: number) =>
  new RtcError('RATE_LIMITED', 'Slow down', { retryAfterMs });
export const errRoomFull = (max: number) =>
  new RtcError('ROOM_FULL', `Call is full (${max}/${max})`);
