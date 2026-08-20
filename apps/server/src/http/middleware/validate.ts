import type { RequestHandler } from 'express';
import type { ZodType } from 'zod';

/**
 * Parse and replace request input at the trust boundary.
 *
 * Handlers then read `req.validated.*` and can only ever see values that
 * matched a schema. That is the actual NoSQL-injection defence in this
 * codebase: a `z.string().email()` field cannot carry `{$ne: null}` into a
 * query position, no matter what the client sent.
 */
export function validate(schemas: {
  body?: ZodType;
  params?: ZodType;
  query?: ZodType;
}): RequestHandler {
  return (req, res, next) => {
    const out: { body?: unknown; params?: unknown; query?: unknown } = {};
    for (const key of ['body', 'params', 'query'] as const) {
      const schema = schemas[key];
      if (!schema) continue;
      const result = schema.safeParse(req[key]);
      if (!result.success) {
        // Report WHICH fields failed, never echo the offending values back —
        // that turns an error response into a reflection primitive.
        res.status(400).json({
          error: {
            code: 'VALIDATION',
            requestId: req.requestId,
            // Field path AND issue code. A path alone is useless for
            // root-level failures (unrecognised keys, failed refinements),
            // which report an empty path. Values are still never echoed.
            issues: result.error.issues
              .slice(0, 10)
              .map((i) => ({ at: i.path.join('.') || '(root)', code: i.code })),
          },
        });
        return;
      }
      out[key] = result.data;
    }
    req.validated = out;
    next();
  };
}

/** Typed accessors, so handlers do not cast at every use site. */
export const body = <T>(req: { validated?: { body?: unknown } }): T => req.validated?.body as T;
export const params = <T>(req: { validated?: { params?: unknown } }): T => req.validated?.params as T;
export const query = <T>(req: { validated?: { query?: unknown } }): T => req.validated?.query as T;
