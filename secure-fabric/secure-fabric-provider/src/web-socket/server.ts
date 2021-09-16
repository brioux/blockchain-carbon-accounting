import {
  LogLevelDesc,
  Logger,
  LoggerProvider,
} from "@hyperledger/cactus-common";
import WebSocket from "ws";
import { KJUR } from "jsrsasign";
import { parse, URLSearchParams } from "url";
import { randomBytes } from "crypto";
import http, { Server } from "http";
import net from "net";
import { WebSocketClient, WSClientOptions } from "./client";
import { ECCurveLong, ECCurveType } from "../internal/crypto-util";

export interface FabricSocketServerOptions {
  // existing server where all incoming web socket connections are directed.
  server: Server;
  // path for all incoming web-socket connection
  // TODO currently optional. setting this will generate error
  // if incoming connections are not directed here
  path?: string;

  logLevel: LogLevelDesc;
}

interface IWebSocketClients {
  // the pubKeyHex of the client or client abject instance
  // key is a unique/ranfrom session ID provided to the external client
  [key: string]: null | string | WebSocketClient;
}

export class FabricSocketServer {
  public readonly className = "FabricSocketServer";
  public clients: IWebSocketClients = {};
  private readonly log: Logger;
  readonly webSocketServer: WebSocket.Server;
  public readonly hostAddress: string;

  constructor(public readonly opts: FabricSocketServerOptions) {
    const fnTag = `${this.className}#constructor`;
    this.log = LoggerProvider.getOrCreate({
      level: opts.logLevel || "INFO",
      label: this.className,
    });
    this.webSocketServer = new WebSocket.Server({
      noServer: true,
      path: opts.path,
      //clientTracking: true,
    });
    this.hostAddress = `${JSON.stringify(this.opts.server.address())}; ${
      this.opts.path
    }`;
    this.log.debug(
      `${fnTag} setup web-socket-server for clients used by the WS-X.509 identity provider } `,
    );
    //Checks.nonBlankString(opts.path, `${fnTag} options.path`);

    const { log, clients, webSocketServer } = this;
    opts.server.on("upgrade", function upgrade(
      request: http.IncomingMessage,
      socket: net.Socket,
      head: Buffer,
    ) {
      log.debug(
        `${fnTag} validation of server upgrade before establishing web-socket connection`,
      );
      try {
        const { path, pathname } = parse(request.url);
        const params = path.split("?")[1];
        if (opts.path && pathname !== opts.path) {
          throw new Error(
            `incoming web-socket connections directed to ${pathname}, but required path is  ${opts.path}`,
          );
        }
        const connectionParams = new URLSearchParams(params);
        log.debug(
          `${fnTag} params received by new web-socket client: ${connectionParams}`,
        );
        const sessionId = connectionParams.get("sessionId") as string;
        const signature = connectionParams.get("signature") as string;
        const curve = connectionParams.get("crv") as ECCurveType;
        let paramErrs = [];
        if (!sessionId){paramErrs.push(`parameter 'sessionID' not provided`)}
        if (!signature){paramErrs.push(`parameter 'signature' not provided`)}
        if (!curve){paramErrs.push(`parameter 'curve' not provided`)}
        if (paramErrs.length>0) {
          throw new Error(paramErrs.join('\r\n'));
        }

        const client = clients[sessionId];
        if (!client) {
          throw new Error(
            `server is not waiting for client with sessionId ${sessionId} `,
          );
        } else if (typeof client == "object") {
          throw new Error(
            `a client has already been opened for sessionId ${sessionId}`,
          );
        }

        const pubKeyHex: string = client;
        log.debug(
          `${fnTag} build public ECDSA curve using the pub-key-hex ${pubKeyHex.substring(
            0,
            12,
          )}... to verify the sessionId signature`,
        );
        const pubKeyEcdsa = new KJUR.crypto.ECDSA({
          curve: ECCurveLong[curve],
          pub: pubKeyHex,
        });
        if (!pubKeyEcdsa.verifyHex(sessionId, signature, pubKeyHex)) {
          throw new Error("the signature does not match the public key");
        }

        webSocketServer.handleUpgrade(
          request as http.IncomingMessage,
          socket as net.Socket,
          head as Buffer,
          function validate(webSocket) {
            const wsClientOpts: WSClientOptions = {
              pubKeyHex,
              curve,
              webSocket,
              pubKeyEcdsa,
              logLevel: opts.logLevel,
            };
            clients[sessionId] = new WebSocketClient(wsClientOpts);
            webSocketServer.emit("connection", webSocket, sessionId);
          },
        );
      } catch (error) {
        socket.write(`HTTP/1.1 401 Unauthorized\r\n\r\n${error}`);
        socket.destroy();
        throw new Error(`${fnTag} incoming connection denied: ${error}`);
      }
    });
    webSocketServer.on("connection", function connection(
      webSocket: WebSocket,
      sessionId: string,
    ) {
      const client = clients[sessionId] as null | WebSocketClient;
      log.info(`session ${sessionId} in progress for ${client?.keyName}`);
      webSocket.onclose = function () {
        log.info(
          `${fnTag} client closed for sessionId ${sessionId} and pub-key-hex ${client?.keyName}`,
        );
        clients[sessionId] = null;
      };
    });
  }
  /**
   * @description create a unique sessionId for web socket connection for a given public key hex
   */
  public newSessionId(pubKeyHex: string) {
    const fnTag = `${this.className}#new-session-id`;
    const sessionId = randomBytes(8).toString("hex");
    this.clients[sessionId] = pubKeyHex;
    this.log.debug(
      `${fnTag} assign new session id ${sessionId} to public key ${pubKeyHex.substring(
        0,
        12,
      )}...`,
    );
    return sessionId;
  }
  public close() {
    Object.values(this.clients).forEach((value) => {
      if (typeof value === "object") {
        (value as WebSocketClient)?.webSocket.close();
      }
    });
    this.clients = {};
    this.webSocketServer.close();
  }
}

export function waitForSocketClient(
  clients: IWebSocketClients,
  sessionId: string,
  address?: any,
): Promise<WebSocketClient> {
  if (address) {
    const log = LoggerProvider.getOrCreate({
      label: "wait-for-socket-client",
      level: "INFO",
    });
    log.info(`waiting for web-socket connection from client for ${sessionId}`);
  }
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (typeof clients[sessionId] == "object") {
        const log = LoggerProvider.getOrCreate({
          label: "wait-for-socket-client",
          level: "INFO",
        });
        log.info(`web-socket client established for sessionId ${sessionId}`);
        resolve(clients[sessionId] as WebSocketClient);
      } else {
        waitForSocketClient(clients, sessionId).then(resolve);
      }
    });
  });
}
