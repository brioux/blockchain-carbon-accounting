import http, { Server } from "http";
import WebSocket, { Data } from "ws";
import createWebSocketServer from "./createWebSocketServer";
import { FabricWebSocketServer, FabricWebSocketServerOptions } from '../../src/web-socket/server';
import { FabricWebSocketClient } from '../../src/web-socket/client';
/**
 * Creates and starts a WebSocket server from a simple http server for testing purposes.
 * @param port Port for the server to listen on
 * @returns The created server
 */
function startServer(port: number): Promise<Server> {
  const server = http.createServer();
  createWebSocketServer(server);
  return new Promise((resolve) => {
    server.listen(port, () => resolve(server));
  });
}

function startFabricWebSocketServer(port: number): Promise<[Server,FabricWebSocketServer]> {
  const server = http.createServer();
  const opts:FabricWebSocketServerOptions = {
      server,
      logLevel: 'error'
  }
  const fabricWebSocketServer = new FabricWebSocketServer(opts);

  return new Promise((resolve) => {
    server.listen(port, () => resolve([server,fabricWebSocketServer]));
  });
}


/**
 * Forces a process to wait until the socket's `readyState` becomes the specified value.
 * @param socket The socket whose `readyState` is being watched
 * @param state The desired `readyState` for the socket
 */
function waitForSocketState(socket: WebSocket, state: number): Promise<void> {
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (socket.readyState === state) {
        resolve();
        //resolve(socket);
      } else {
        waitForSocketState(socket, state).then(resolve);
      }
    });
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

async function createFabricSocketClient(port:number): Promise<FabricWebSocketClient> {
  const fwsClient = new FabricWebSocketClient({ 
    host: `ws://localhost:${port}`,
    logLevel: 'error'
  })
  await waitForSocketState(fwsClient.ws, fwsClient.ws.OPEN);
  return fwsClient;
}



export { 
  startServer, startFabricWebSocketServer, 
  waitForSocketState, createSocketClient, 
  createFabricSocketClient };