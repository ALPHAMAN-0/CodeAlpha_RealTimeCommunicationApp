import type { ErrorRequestHandler, RequestHandler } from 'express';
import { randomUUID } from 'node:crypto';
import { RtcError } from '@rtc/shared';
import { log } from '../../config/logger.js';
import { AuthError } from '../../services/auth.service.js';
import { HashCapacityError } from '../../crypto/passwords.js';

/** Correlates a user-visible error id with a server-side log line. */
export const requestId: RequestHandler = (req, res, next) => {
  req.requestId = randomUUID();
  res.setHeader('X-Request-Id', req.requestId);
  next();
};

export const notFound: RequestHandler = (req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', requestId: req.requestId } });
};

const AUTH_STATUS: Record<AuthError['code'], number> = {
  INVALID_CREDENTIALS: 401,
  EMAIL_TAKEN: 409,
  REFRESH_INVALID: 401,
  REFRESH_REUSE: 401,
  ACCOUNT_LOCKED: 429,
};

/**
 * Terminal error handler.
 *
 * Clients receive a code and a request id. Stack traces and Mongoose
 * validation messages stay server-side: they leak schema shape, field names
 * and sometimes data.
 */
export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (res.headersSent) return;

  if (err instanceof AuthError) {
    if (err.retryAfterSeconds) res.setHeader('Retry-After', String(err.retryAfterSeconds));
    res.status(AUTH_STATUS[err.code]).json({ error: { code: err.code, requestId: req.requestId } });
    return;
  }
  if (err instanceof HashCapacityError) {
    res.setHeader('Retry-After', String(err.retryAfterSeconds));
    res.status(503).json({ error: { code: 'BUSY', requestId: req.requestId } });
    return;
  }
  if (err instanceof RtcError) {
    const status = err.code === 'FORBIDDEN' || err.code === 'NOT_A_MEMBER' ? 403
      : err.code === 'NOT_FOUND' ? 404
      : err.code === 'VALIDATION' ? 400
      : err.code === 'PAYLOAD_TOO_LARGE' ? 413
      : err.code === 'RATE_LIMITED' ? 429
      : 500;
    res.status(status).json({ error: { code: err.code, requestId: req.requestId } });
    return;
  }

  // Body-parser and multer surface size violations as typed errors.
  const anyErr = err as { type?: string; code?: string; status?: number; message?: string };
  if (anyErr.type === 'entity.too.large' || anyErr.code === 'LIMIT_FILE_SIZE') {
    res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', requestId: req.requestId } });
    return;
  }
  if (anyErr.type === 'entity.parse.failed') {
    res.status(400).json({ error: { code: 'VALIDATION', requestId: req.requestId } });
    return;
  }

  log.error({ err, requestId: req.requestId, path: req.path }, 'unhandled request error');
  res.status(500).json({ error: { code: 'INTERNAL', requestId: req.requestId } });
};
