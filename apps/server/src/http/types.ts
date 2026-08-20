/**
 * Express request augmentation.
 *
 * Validated input lands on `req.validated` rather than overwriting `req.query`
 * — in Express 5 `query` is a getter, so assigning to it either throws or
 * silently does nothing. (This is also why `express-mongo-sanitize` is
 * unusable on Express 5, and why typed parsing is the right layer anyway.)
 */
declare global {
  /*
   * Express declares its own types inside a global namespace, so augmenting
   * them requires matching that shape. There is no module-syntax equivalent,
   * which is why the lint rule is suppressed here and nowhere else.
   */
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      validated?: { body?: unknown; params?: unknown; query?: unknown };
      auth?: { userId: string; sessionId: string; expiresAt: number };
      requestId?: string;
    }
  }
}

export {};
