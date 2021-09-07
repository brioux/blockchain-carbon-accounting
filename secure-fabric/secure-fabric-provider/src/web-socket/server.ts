import {
  LogLevelDesc,
  Logger,
  LoggerProvider,
  Checks
} from "@hyperledger/cactus-common";
import WebSocket from "ws";
import { KJUR } from "jsrsasign";
import { URLSearchParams } from "url";
import { randomBytes } from 'crypto';
import {Server} from 'http';
import { WebSocketClient, WSClientOptions } from './client';
import { ECCurveLong, ECCurveType } from "../internal/crypto-util";

export interface FabricSocketServerOptions {
  // path for all incoming web-socket connection 
  path: string;
  // existing server where all incoming web socket connectionss are directed.
  server: Server;
  logLevel: LogLevelDesc;
}

interface IWebSocketClients {
  // the pubKeyHex of the client or client abject instance
  // key is a unique/ranfrom session ID provided to the external client
  [key: string]: null | string | WebSocketClient  ;
}

export class FabricSocketServer {
  public readonly className = "FabricSocketServer";
  //public server;
  public path; 
  public clients: IWebSocketClients = {};  
  private readonly log: Logger;
  private readonly webSocketServer: WebSocket.Server;
  public readonly hostAddress:string;

  constructor(public readonly opts:FabricSocketServerOptions){
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
    this.hostAddress = `${JSON.stringify(this.opts.server.address())}; ${this.opts.path}`;
    this.log.debug(
      `${fnTag} setup web-socket-server for clients used by the WS-X.509 identity provider } `,
    ); 
    Checks.nonBlankString(
      opts.path,
      `${fnTag} options.path`,
    ); 
    this.log.debug(
      `${fnTag} validation of server upgrade before establishing web-socket connection`,
    );
    const { log, clients, webSocketServer} = this; 
    opts.server.on("upgrade", (request, socket, head) => {
      this.log.debug(
        `${fnTag} validation of server upgrade before establishing web-socket connection`,
      );      
      webSocketServer.handleUpgrade(request, socket, head, (webSocket) => {
        const [_path, params] = request?.url?.split("?");
        const connectionParams = new URLSearchParams(params);
        log.debug(`${fnTag} params received by new web-socket client: ${params}`);
        const sessionId = connectionParams.get("sessionId");
        const signature = connectionParams.get("signature");
        const curve = connectionParams.get("crv") as ECCurveType;
        if (!sessionId) {
          throw new Error("no sessionId parameter provided");
        }
        if (!signature) {
          throw new Error("no signature parameter provided");
        }
        if (!curve) {
          throw new Error("no curve parameter provided");
          //extract curve from signature/pubKeyHex?
        }
        let client = clients[sessionId]
        if (!client) {
          throw new Error(`No client exists for the provided sessionId ${sessionId}`);
        }
        let pubKeyHex
        if(typeof(client)=='string'){
          pubKeyHex = client;
        }else{
          pubKeyHex = client.pubKeyHex
          client.close();
          client = null;
        }
        log.debug(
          `${fnTag} build public ECDSA curve using the pubKeyHex ${pubKeyHex.substring(0,12)}... to verify the sessionId signature`,
        );
        const pubKeyEcdsa = new KJUR.crypto.ECDSA({
          curve: ECCurveLong[curve],
          pub: pubKeyHex,
        });
        if (!pubKeyEcdsa.verifyHex(sessionId, signature, pubKeyHex)) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          throw new Error("the signature does not match the public key");
        }
        const wsClientOpts:WSClientOptions = {
          pubKeyHex,
          curve,
          webSocket,
          pubKeyEcdsa,
          logLevel: opts.logLevel,
        }
        webSocketServer.emit("connection", webSocket,request,wsClientOpts,sessionId);
      });
    });
    webSocketServer.on("connection",
      function connection(webSocket, request, wsClientOpts, sessionId) { 
        clients[sessionId] = new WebSocketClient(wsClientOpts);
        let client = clients[sessionId] as WebSocketClient 
        log.debug(
          `session ${sessionId} in progress for ${client.keyName}`,
        );
        webSocket.onclose = function () {
          client = null;
          log.debug(
            `${fnTag} client closed for sessionId ${sessionId} and pubKeyHex ${wsClientOpts.pubKeyHex.substring(0, 12)}...`,
          );
        };
      }
    );
    }
  /**
   * @description create a unique sessionId for web socket connection for a given public key hex
   */
  public newSessionId(pubKeyHex: string) {
    const fnTag = `${this.className}#newSessionId`;
    const sessionId = randomBytes(8).toString("hex");
    this.clients[sessionId] = pubKeyHex;
    this.log.debug(
      `${fnTag} assign new sessionId ${sessionId} to public key ${pubKeyHex.substring(0,12)}...`,
    );
    return sessionId;
  }
  public close(){
    Object.values(this.clients).forEach((value, index) => {
      if(typeof(value)==='object'){
        value.close();
        value = null;
      }
    });
    this.webSocketServer.close();
  }
}

