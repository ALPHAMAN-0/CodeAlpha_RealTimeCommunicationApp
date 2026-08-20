/**
 * Branded id types.
 *
 * These are `string` at runtime and distinct at compile time, so passing a
 * ConversationId where a UserId is expected is a type error rather than a
 * silent authorization bug. Nothing enforces this at runtime — the Zod schemas
 * in ./schemas are the runtime half.
 */
declare const brand: unique symbol;
type Brand<T, B> = T & { readonly [brand]: B };

export type UserId = Brand<string, 'UserId'>;
export type ConversationId = Brand<string, 'ConversationId'>;
export type MessageId = Brand<string, 'MessageId'>;
export type AttachmentId = Brand<string, 'AttachmentId'>;
export type SocketId = Brand<string, 'SocketId'>;
export type StrokeId = Brand<string, 'StrokeId'>;

/**
 * UUID minted by the SENDER before the first send attempt and never
 * regenerated on retry. This is the idempotency key that makes
 * `message:send` safe to replay forever — see docs/RELIABILITY.md.
 */
export type ClientMsgId = Brand<string, 'ClientMsgId'>;

/**
 * Per-conversation sequence number, assigned by the server.
 *
 * Monotonic but NOT gap-free: a lost duplicate race or a failed insert after
 * allocation burns a number. Every query is a `seq > cursor` range scan and
 * nothing may ever expect `cursor + 1`.
 */
export type Seq = number;

export const asUserId = (v: string): UserId => v as UserId;
export const asConversationId = (v: string): ConversationId => v as ConversationId;
export const asMessageId = (v: string): MessageId => v as MessageId;
export const asAttachmentId = (v: string): AttachmentId => v as AttachmentId;
export const asSocketId = (v: string): SocketId => v as SocketId;
export const asStrokeId = (v: string): StrokeId => v as StrokeId;
export const asClientMsgId = (v: string): ClientMsgId => v as ClientMsgId;

/** Fresh idempotency key. Call once per composed message, never on retry. */
export const newClientMsgId = (): ClientMsgId => crypto.randomUUID() as ClientMsgId;
export const newStrokeId = (): StrokeId => crypto.randomUUID() as StrokeId;
