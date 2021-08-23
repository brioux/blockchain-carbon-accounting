import { createPublicKey, JwkKeyExportOptions } from 'crypto';
import WebSocket, {WebSocketServer} from 'ws';
import { Logger } from 'winston';
import { Options, Util } from '../internal/util';
import { ec } from 'elliptic';
import http, {Server} from 'http';
import { WebSocketKey } from './key'
import { IClientPubKeyData } from './client';
export interface FabricWebSocketServerOptions extends Options {
  // port to setup the websocket server
  // eg : 8080
  server:Server;
}

interface FabricWebSocketClients{
  [key: string]: WebSocketKey
}

// FabricWebSocketServer : web socket server for interacting with fabric
// - signing message digest
// - create new EC key with key size 256 and 384
// - rotate existing private key
// - get latest EC key

export class FabricWebSocketServer {
  private readonly classLogger: Logger;
  readonly wss:Server;
  readonly ws:WebSocket;
  readonly clients:FabricWebSocketClients
  

  constructor(opts: FabricWebSocketServerOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocket Client');
    
    this.classLogger.debug('Setup a web socket server');
    this.wss = new WebSocketServer({server: opts.server});

    this.wss.on('connection', function connection(ws,request) {
      let secWSKey = request.rawHeaders.findIndex((element) => element == 'Sec-WebSocket-Key');
      const pubKeyHex = request.url.split('?')[1];
      const pubKeyData = JSON.parse(Buffer.from(pubKeyHex,'hex').toString('utf8'));
      secWSKey = request.rawHeaders[secWSKey+1];
      this.clients[secWSKey] = new WebSocketKey({ws,logLevel: opts.logLevel,pubKeyData});
    });
  }
}