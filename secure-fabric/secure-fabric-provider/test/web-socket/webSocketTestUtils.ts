import http, { Server } from "http";
import { WebSocketClient } from "../../src/web-socket/client"
/**
 * Creates and starts a WebSocket server from a simple http server for testing purposes.
 * @param port Port for the server to listen on
 * @returns The created server
 */
export function startServer(port: number): Promise<Server> {
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(port, () => resolve(server));
  });
}

