import { Router } from 'express';
import { Types } from 'mongoose';
import { asUserId, objectIdParamSchema, publishKeysBodySchema, type PublicKeyBundle } from '@rtc/shared';
import { securityLog } from '../../config/logger.js';
import { User } from '../../db/models/index.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { body, params, validate } from '../middleware/validate.js';

/**
 * Public identity keys.
 *
 * These are public by design and must be fetchable by anyone the user might
 * talk to. The security property is not secrecy but INTEGRITY: the log is
 * append-only, each entry is self-signed, and each rotation is counter-signed
 * by the key it replaces, so a server-injected key breaks a chain the client
 * verifies for itself.
 */
export function keysRoutes(): Router {
  const r = Router();

  r.get('/:id', requireAuth, validate({ params: objectIdParamSchema }), async (req, res, next) => {
    try {
      const { id } = params<{ id: string }>(req);
      const user = await User.findById(new Types.ObjectId(id)).select({ keyLog: 1, keyVersion: 1 }).lean();
      if (!user || user.keyLog.length === 0) {
        res.status(404).json({ error: { code: 'NOT_FOUND', requestId: req.requestId } });
        return;
      }
      const log = [...user.keyLog].sort((a, b) => a.keyVersion - b.keyVersion);
      const bundle: PublicKeyBundle = {
        userId: asUserId(id),
        current: log[log.length - 1] as never,
        // The FULL log, so the client can verify the chain itself rather than
        // trusting this server's word about which key is current.
        log: log as never,
      };
      res.json(bundle);
    } catch (e) {
      next(e);
    }
  });

  /**
   * Publish a key rotation.
   *
   * The server enforces append-only and strictly-increasing versions. It never
   * deletes an entry and never lowers a version — that is precisely what makes
   * client-side tamper detection possible, because a gap or a rollback in the
   * log is evidence rather than ambiguity.
   */
  r.post('/', requireAuth, validate({ body: publishKeysBodySchema }), async (req, res, next) => {
    try {
      const { publicKeys, passwordWrap } = body<{
        publicKeys: { keyVersion: number }; passwordWrap: unknown;
      }>(req);
      const userId = new Types.ObjectId(req.auth!.userId);
      const user = await User.findById(userId).select({ keyVersion: 1 }).lean();
      if (!user) {
        res.status(404).json({ error: { code: 'NOT_FOUND', requestId: req.requestId } });
        return;
      }
      if (publicKeys.keyVersion !== user.keyVersion + 1) {
        res.status(409).json({
          error: { code: 'CONFLICT', requestId: req.requestId, expected: user.keyVersion + 1 },
        });
        return;
      }
      // $push, never $set: the log only ever grows.
      await User.updateOne(
        { _id: userId, keyVersion: user.keyVersion },
        {
          $push: { keyLog: publicKeys as never },
          $set: { keyVersion: publicKeys.keyVersion, passwordWrap: passwordWrap as never },
        },
      );
      securityLog.info({ userId: req.auth!.userId, keyVersion: publicKeys.keyVersion }, 'identity key rotated');
      res.status(201).json({ keyVersion: publicKeys.keyVersion });
    } catch (e) {
      next(e);
    }
  });

  return r;
}
