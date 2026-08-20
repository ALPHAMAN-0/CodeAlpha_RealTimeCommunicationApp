import { Router } from 'express';
import { Types } from 'mongoose';
import { Readable } from 'node:stream';
import multer from 'multer';
import { objectIdParamSchema } from '@rtc/shared';
import { env } from '../../config/env.js';
import { log } from '../../config/logger.js';
import { Participant } from '../../db/models/index.js';
import { authorizeDownload, createAttachment } from '../../services/attachment.service.js';
import { requireAuth } from '../middleware/requireAuth.js';
import { params, validate } from '../middleware/validate.js';
import { rateLimits } from '../security.js';

/**
 * Encrypted attachments.
 *
 * Uploads are REST, never Socket.IO: maxHttpBufferSize is 1 MB by design, and
 * base64-over-WebSocket would inflate the payload by a third while
 * head-of-line-blocking every chat message behind the transfer.
 */
export function filesRoutes(): Router {
  const r = Router();

  /**
   * Limits are enforced DURING the stream, not after.
   *
   * Checking `req.file.size` afterwards means you have already written the
   * bytes to disk — the check would report the abuse rather than prevent it.
   */
  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: env.MAX_UPLOAD_BYTES, files: 1, fields: 2, parts: 4 },
  });

  r.post(
    '/:id',
    requireAuth,
    rateLimits.upload,
    validate({ params: objectIdParamSchema }),
    upload.single('file'),
    async (req, res, next) => {
      try {
        const { id: conversationId } = params<{ id: string }>(req);
        const member = await Participant.exists({
          conversationId: new Types.ObjectId(conversationId),
          userId: new Types.ObjectId(req.auth!.userId),
          leftAt: null,
        });
        if (!member) {
          res.status(403).json({ error: { code: 'NOT_A_MEMBER', requestId: req.requestId } });
          return;
        }
        if (!req.file) {
          res.status(400).json({ error: { code: 'VALIDATION', requestId: req.requestId } });
          return;
        }

        /**
         * No MIME allowlist here, and that is not an omission.
         *
         * The body is client-encrypted, so the server sees high-entropy bytes.
         * Any Content-Type check would be decoration. The real check happens
         * in the browser AFTER decryption, where magic-byte sniffing can
         * compare actual content against the claimed filename.
         *
         * The honest cost, stated in SECURITY.md: server-side antivirus
         * scanning is impossible on end-to-end encrypted attachments. You can
         * have E2EE files or server-side AV, not both.
         */
        const result = await createAttachment({
          conversationId,
          uploaderId: req.auth!.userId,
          stream: Readable.from(req.file.buffer),
        });
        res.status(201).json(result);
      } catch (e) {
        next(e);
      }
    },
  );

  r.get('/:id', requireAuth, rateLimits.download, validate({ params: objectIdParamSchema }), async (req, res, next) => {
    try {
      const { id } = params<{ id: string }>(req);
      const target = await authorizeDownload(id, req.auth!.userId);

      /**
       * Response headers, all of them load-bearing.
       *
       * Any origin that serves attacker-controlled bytes with a sniffable
       * content type is a stored-XSS primitive ON ITS OWN ORIGIN — and in this
       * app XSS means direct use of the victim's E2EE keys. octet-stream +
       * nosniff + attachment disposition + a sandboxed CSP neutralises that.
       *
       * The filename is a constant: the real one is encrypted and applied
       * client-side, which also sidesteps every Content-Disposition header
       * injection and right-to-left-override filename trick.
       */
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', 'attachment; filename="download.bin"');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
      res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
      res.setHeader('Cache-Control', 'private, no-store');
      res.setHeader('Content-Length', String(target.cipherSize));

      const { storage } = await import('../../storage/index.js');
      const stream = await storage().get(target.storageId);
      stream.on('error', (err) => {
        log.error({ err, attachmentId: id }, 'attachment stream failed');
        if (!res.headersSent) res.status(500).end();
        else res.destroy();
      });
      stream.pipe(res);
    } catch (e) {
      next(e);
    }
  });

  return r;
}
