import type { Server, Socket } from 'socket.io';
import type {
  ClientToServerEvents, InterServerEvents, ServerToClientEvents, SocketData,
} from '@rtc/shared';

export type TypedServer = Server<
  ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData
>;
export type TypedSocket = Socket<
  ClientToServerEvents, ServerToClientEvents, InterServerEvents, SocketData
>;
