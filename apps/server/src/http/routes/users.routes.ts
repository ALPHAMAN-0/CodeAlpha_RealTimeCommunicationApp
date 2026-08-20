import { Router } from 'express';
import { User } from '../../db/models/index.js';
import { requireAuth } from '../middleware/requireAuth.js';

/**
 * A minimal user directory, so people can start a conversation.
 *
 * Returns ONLY public profile fields. Notably absent: email addresses. They
 * are encrypted at rest and there is no reason for one account to learn
 * another's, so the directory does not carry them — the safest field is the
 * one that is never in the response.
 *
 * A production deployment would replace this with invitations or a scoped
 * search rather than enumerating every account; that is noted in the README's
 * known-limits section rather than left as a surprise.
 */
export function usersRoutes(): Router {
  const r = Router();

  r.get('/', requireAuth, async (_req, res, next) => {
    try {
      const users = await User.find({})
        .select({ displayName: 1, avatarColor: 1, keyVersion: 1 })
        .sort({ displayName: 1 })
        .limit(200)
        .lean();
      res.json({
        users: users.map((u) => ({
          id: String(u._id),
          displayName: u.displayName,
          avatarColor: u.avatarColor,
          keyVersion: u.keyVersion,
        })),
      });
    } catch (e) {
      next(e);
    }
  });

  return r;
}
