import { ICryptoSuite, Utils } from "fabric-common";
import { X509, KEYUTIL } from 'jsrsasign';
import { Logger } from 'winston';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import WebSocket, { WebSocketServer } from 'ws';
import { Key } from '../internal/key'; 
import { ECCurveType } from '../internal/crypto-util'
import { WebSocketClient } from './client';
import { WebSocketCryptoSuite } from './cryptoSuite';
import { Server } from "https";
import { URLSearchParams } from "url";
const jsrsasign = require('jsrsasign');

export interface WSX509Identity extends Identity {
  type: IdentityProvidersType.WebSocket;
  credentials: {
    certificate: string;
    //pubKeyHex: string;
  };
}

export function getSecWsKey(request){
  const secKey = request.rawHeaders.findIndex((element) => element == 'Sec-WebSocket-Key');
  return request.rawHeaders[secKey+1]
}

interface WSX509IdentityData extends IdentityData {
  type: IdentityProvidersType.WebSocket;
  version: 1;
  credentials: {
    certificate: string;
  };
  mspId: string;
}
interface IClientWebSockets {
   [key:string]: WebSocket; 
}
/*interface IClientWebSocketOn {
   [key:string]:boolean; 
}*/

export interface WSX509ProviderOptions extends Options {
  server?:Server;
  port?:string;
}

export function waitForSocketClient(client:boolean,pubKeyHex?:string): Promise<void> {
  if(pubKeyHex){
    console.log(`Waiting for web-socket connection from client with pub key hex: ${pubKeyHex.substring(0,6)}`)}
  return new Promise(function (resolve) {
    setTimeout(function () {

      if (client!==null) {
        console.log(client)
        resolve();
        //resolve(socket);
      } else {
        console.log('closed')
        waitForSocketClient(client,null).then(resolve);
      }
    });
  });
}

export class WSX509Provider implements InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly classLogger: Logger;
  readonly _wss: WebSocketServer;
  clients: IClientWebSockets;
  //clientOn: boolean;

  constructor(opts: WSX509ProviderOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WSX509Provider');
    if (!opts.server && Util.isEmptyString(opts.port)) {
      throw new Error('require an http server or port number');
    }
    this._wss = opts.server ? 
      new WebSocketServer({ server: opts.server }) : 
      new WebSocketServer({ port: opts.port });

    this.clients = {};
    this.classLogger.debug(`Initiate web socket server for the identity provider at ${this._wss.url}`);
    const self=this;
    this._wss.on('connection', function connection(ws,request) {
      const urlParams = new URLSearchParams(ws.url);
      const pubKeyHex = urlParams.get('pubKeyHex')
      const curve = urlParams.get('crv') as ECCurveType;
      if(!pubKeyHex){
        throw new Error('no pubKeyHex provided by the web-socket url');
      }
      if(!curve){
        throw new Error('no curve provided by the web-socket url');
        // TO-DO we can extract the curve data from the pubKeyHex? 
        // We should not need to pass the crv 
      }
      //this.clientOn[pubKeyHex] = true;
      self.clients[pubKeyHex] = new WebSocketClient({
        pubKeyHex,
        curve,
        ws,
        secWsKey: getSecWsKey(request),
        logLevel: this.classLogger
      });
      ws.onclose = function () {
        self.clients[pubKeyHex] = null;
        //self.clientOn[pubKeyHex] = false;
      };
    });
  }

  /**
   * @description get user context for the provided identity file
   * @note before this method is called the requested identity holder must open 
   * a websocket connection with the identity provider
   */
  async getUserContext(identity: WSX509Identity, name: string): Promise<User> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getUserContext');
    methodLogger.debug(`get user context for ${name} with: = \n%o`, identity);
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    //user.setCryptoSuite(new WebSocketCryptoSuite());
    user.setCryptoSuite(Utils.newCryptoSuite());
    
    // get type of curve
    methodLogger.debug(`Get public key from provided identity crendential certificate`);
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate); 
    const pubKeyObj = cert.getPublicKey();
    console.log(cert.getPublicKey())
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(KEYUTIL.getPEM(pubKeyObj));
    console.log(pubKeyHex)
    //const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(pubKeyObj);
    //console.log(pubKeyHex)

    await waitForSocketClient(this.clients[pubKeyHex],pubKeyHex)

    const wsKey = new Key(pubKeyHex.substring(0,6),this.clients[pubKeyHex]);
    await user.setEnrollment(
      wsKey,
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }

  getCryptoSuite(): ICryptoSuite {
    throw new Error('InternalIdentityProvider::getCryptoSuite not required!!');
  }
  fromJson(data: IdentityData): WSX509Identity {
    throw new Error('InternalIdentityProvider::fromJson not required!!');
  }
  toJson(identity: Identity): WSX509IdentityData {
    throw new Error('InternalIdentityProvider::toJso : not required!!');
  }
}
