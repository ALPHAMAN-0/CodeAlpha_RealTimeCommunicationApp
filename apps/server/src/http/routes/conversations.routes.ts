import { Router } from 'express';
import { Types } from 'mongoose';
import {
  createConversationBodySchema, objectIdParamSchema, type CipherEnvelope,
} from '@rtc/shared';
import { Conversation, Participant, User } from '../../db/models/index.js';
import {
  createGroup, createOrGetDm, getJoinState, listConversations,
} from '../../services/conversation.service.js';
import { getHistory } from '../../services/message.service.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { body, params, validate } from '../middleware/validate.js';

export function conversationRoutes(): Router {
  const r = Router();
  r.use(requireAuth);

  r.get('/', async (req, res, next) => {
    try {
      res.json({ conversations: await listConversations(req.auth!.userId) });
    } catch (e) {
      next(e);
    }
  });

  r.post('/', validate({ body: createConversationBodySchema }), async (req, res, next) => {
    try {
      const input = body<{ type: 'dm' | 'group'; memberIds: string[]; titleEnvelope?: CipherEnvelope }>(req);
      const me = req.auth!.userId;
      if (input.type === 'dm') {
        const other = input.memberIds.find((id) => id !== me);
        if (!other) {
          res.status(400).json({ error: { code: 'VALIDATION', requestId: req.requestId } });
          return;
        }
        res.status(201).json({ conversation: await createOrGetDm(me, other) });
        return;
      }
      const conversation = await createGroup(
        me,
        input.memberIds,
        input.titleEnvelope,
      );
      res.status(201).json({ conversation });
    } catch (e) {
      next(e);
    }
  });

  /**
   * Public keys for every member, so a rekey leader can wrap the new epoch
   * key once per member without N separate round trips.
   *
   * Membership-gated: the member list of a room you are not in is not yours
   * to enumerate.
   */
  r.get('/:id/keys', validate({ params: objectIdParamSchema }), async (req, res, next) => {
    try {
      const { id } = params<{ id: string }>(req);
      const conv = await Conversation.findById(new Types.ObjectId(id)).select({ memberIds: 1 }).lean();
      if (!conv) {
        res.status(404).json({ error: { code: 'NOT_FOUND', requestId: req.requestId } });
        return;
      }
      if (!conv.memberIds.some((m) => String(m) === req.auth!.userId)) {
        res.status(403).json({ error: { code: 'NOT_A_MEMBER', requestId: req.requestId } });
        return;
      }
      const users = await User.find({ _id: { $in: conv.memberIds } })
        .select({ keyLog: 1, keyVersion: 1, displayName: 1, avatarColor: 1 })
        .lean();
      res.json({
        members: users.map((u) => {
          const log = [...u.keyLog].sort((a, b) => a.keyVersion - b.keyVersion);
          return {
            userId: String(u._id),
            displayName: u.displayName,
            avatarColor: u.avatarColor,
            keyVersion: u.keyVersion,
            current: log[log.length - 1],
            log,
          };
        }),
      });
    } catch (e) {
      next(e);
    }
  });

  r.get('/:id', validate({ params: objectIdParamSchema }), async (req, res, next) => {
    try {
      const { id } = params<{ id: string }>(req);
      res.json(await getJoinState(id, req.auth!.userId));
    } catch (e) {
      next(e);
    }
  });

  /** REST history, for the initial page load before the socket is up. */
  r.get('/:id/messages', validate({ params: objectIdParamSchema }), async (req, res, next) => {
    try {
      const { id } = params<{ id: string }>(req);
      const isMember = await Participant.exists({
        conversationId: new Types.ObjectId(id),
        userId: new Types.ObjectId(req.auth!.userId),
        leftAt: null,
      });
      if (!isMember) {
        res.status(403).json({ error: { code: 'NOT_A_MEMBER', requestId: req.requestId } });
        return;
      }
      const beforeSeq = Number(req.query.beforeSeq);
      const limit = Number(req.query.limit);
      res.json(
        await getHistory(id, {
          ...(Number.isFinite(beforeSeq) && beforeSeq > 0 ? { beforeSeq } : {}),
          ...(Number.isFinite(limit) && limit > 0 ? { limit } : {}),
        }),
      );
    } catch (e) {
      next(e);
    }
  });

  return r;
}
