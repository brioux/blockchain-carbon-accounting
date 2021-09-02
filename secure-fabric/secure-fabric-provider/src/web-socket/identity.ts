import { ICryptoSuite } from "fabric-common";
import { X509 } from 'jsrsasign';
import { Logger } from 'winston';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import WebSocket, { WebSocketServer } from 'ws';
import { Key } from '../internal/key'; 
import { ECCurveType } from '../internal/crypto-util'
import { WebSocketClient } from './client';
import { InternalCryptoSuite } from '../internal/crypto-suite';
import { Server } from "https";
import { URLSearchParams } from "url";

export interface WSX509Identity extends Identity {
  type: IdentityProvidersType.WebSocket;
  credentials: {
    certificate: string;
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

export interface WSX509ProviderOptions extends Options {
  server?:Server;
  port?:string;
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

export class WSX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly classLogger: Logger;
  readonly _wss: WebSocketServer;
  clients: IClientWebSockets;
  //clientOn: boolean;

  constructor(opts: WSX509ProviderOptions) {
    super()
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WSX509Provider');
    if (!opts.server && Util.isEmptyString(opts.port)) {
      throw new Error('require an http server or port number');
    }
    this._wss = opts.server ? 
      new WebSocketServer({ server: opts.server }) : 
      new WebSocketServer({ port: opts.port });

    this.classLogger.debug(`Initiated web socket server for the identity provider at ${this._wss.url}`);
    this.clients = {};
    const self=this;
    this._wss.on('connection', function connection(ws,request) {
      const urlParams = new URLSearchParams(request.url.split('?')[1]);
      self.classLogger.debug(`Url params sent by new web client: ${urlParams}`)
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

      self.clients[pubKeyHex] = new WebSocketClient({
        pubKeyHex,
        curve,
        ws,
        secWsKey: getSecWsKey(request),
        logLevel: this.classLogger
      });
      ws.onclose = function () {
        self.clients[pubKeyHex] = null;
        console.log(`Client closed for pubKeyHex ${pubKeyHex.substring(0,12)}...`)
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
    user.setCryptoSuite(new InternalCryptoSuite());
    //user.setCryptoSuite(Utils.newCryptoSuite());
    
    // get type of curve
    methodLogger.debug(`Get public key from provided identity crendential certificate`);
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate); 
    const pubKeyHex = cert.getPublicKey()['pubKeyHex'];
    await waitForSocketClient(this.clients,pubKeyHex,this._wss.address()['port'])
    const wsKey = new Key(pubKeyHex.substring(0,12),this.clients[pubKeyHex]);
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
