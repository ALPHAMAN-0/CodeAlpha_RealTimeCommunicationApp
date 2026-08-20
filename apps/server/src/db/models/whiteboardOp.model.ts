import { Schema, model, type InferSchemaType, type Model } from 'mongoose';
import { envelopeSchema } from './envelope.schema.js';

/**
 * One op in a board's totally-ordered log.
 *
 * `kind`, `strokeId` and `chunk` are deliberately server-visible. The server
 * needs them to authorize an undo (the author must own the stroke), to prune
 * on clear, and to serve late joiners — none of which is possible on opaque
 * bytes. Stroke geometry, colour and width stay encrypted, so the server
 * learns "user X drew a stroke, then undid it" and never what was drawn.
 */
const whiteboardOpSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, required: true, ref: 'Conversation' },
    seq: { type: Number, required: true },
    authorId: { type: Schema.Types.ObjectId, required: true, ref: 'User' },
    kind: { type: String, required: true, enum: ['stroke', 'undo', 'redo', 'clear'] },
    strokeId: { type: String },
    chunk: { type: Number },
    done: { type: Boolean },
    /** Present for kind === 'stroke' only. */
    envelope: { type: envelopeSchema },
  },
  { timestamps: { createdAt: true, updatedAt: false }, strict: 'throw' },
);

// Ordered replay and delta sync, plus seq uniqueness.
whiteboardOpSchema.index({ conversationId: 1, seq: 1 }, { unique: true });
// Undo authorization: find the stroke's author without scanning the board.
whiteboardOpSchema.index({ conversationId: 1, strokeId: 1 }, { sparse: true });

export type WhiteboardOpDoc = InferSchemaType<typeof whiteboardOpSchema>;
export const WhiteboardOp: Model<WhiteboardOpDoc> = model<WhiteboardOpDoc>('WhiteboardOp', whiteboardOpSchema);
