import http, { Server } from "http";
import WebSocket, { WebSocketServer, Data } from "ws";
import createWebSocketServer from "./createWebSocketServer";
import { WebSocketClient, WebSocketClientOptions, waitForSocketState } from '../../src/web-socket/client';
import { Options, Util } from '../../src/internal/util';
/**
 * Creates and starts a WebSocket server from a simple http server for testing purposes.
 * @param port Port for the server to listen on
 * @returns The created server
 */
function startServer(port: number): Promise<Server> {
  const server = http.createServer();
  return new Promise((resolve) => {
    server.listen(port, () => resolve(server));
  });
}

function startWebSocketServer(server:Server,fabricWebSocket:WebSocketServer){
  const wss = new WebSocketServer({ server });
  wss.on('connection', async function connection(ws,request) {
    fabricWebSocket = ws;
    //console.log(`SEC Key: ${getSecWsKey(request)}`)
  });
}

/**
 * Creates a socket client that connects to the specified `port`. The client automatically
 * closes its socket after it receives the specified number of messages.
 * @param port The port to connect to on the localhost
 * @param closeAfter The number of messages to receive before closing the socket
 * @returns Tuple containing the created client and any messages it receives
 */

async function createSocketClient(port: number, closeAfter?: number): Promise<[WebSocket, Data[]]> {
  const client = new WebSocket(`ws://localhost:${port}`);
  await waitForSocketState(client, client.OPEN);
  const messages: WebSocket.Data[] = [];

  client.on("message", (data) => {
    messages.push(data);

    if (messages.length === closeAfter) {
      client.close();
    }
  });

  return [client, messages];
}

/**
 * Creates a socket client that connects to the specified `port`. The client automatically
 * closes its socket after it receives the specified number of messages.
 * @param port The port to connect to on the localhost
 * @param closeAfter The number of messages to receive before closing the socket
 * @returns A FabricWebSocketServer instance
 */

async function createFabricSocketClient(opts:WebSocketClientOptions): Promise<WebSocketClient> {
  const fwsClient = new WebSocketClient(opts)
  await waitForSocketState(fwsClient.ws, fwsClient.ws.OPEN);
  return fwsClient;
}



export { 
  startServer, startWebSocketServer,
  createSocketClient, 
  createFabricSocketClient };