import http, { Server } from "http";
import { WebSocketClient } from "../../src/web-socket/client"
import WebSocket from 'ws';
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

/**
 * Forces a process to wait until the socket's `readyState` becomes the specified value.
 * @param socket The socket whose `readyState` is being watched
 * @param state The desired `readyState` for the socket
 */
export function waitForSocketState(socket: WebSocket, state: number): Promise<void> {
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


export function waitForSocketClient(clients,pubKeyHex:string,host?:string): Promise<void> {
  if(host){
    console.log(`Waiting for web-socket connection to ${host} from client with pub key hex ${pubKeyHex.substring(0,12)}...`)}
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (clients[pubKeyHex]) {
        console.log(`Web Socket Client established for pubKeyHex ${pubKeyHex.substring(0,12)}...`)
        resolve();
      } else {
        waitForSocketClient(clients,pubKeyHex).then(resolve);
      }
    });
  });
}