import { X509, KEYUTIL } from 'jsrsasign';
import { Logger } from 'winston';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import WebSocket, { WebSocketServer } from 'ws';
import { WebSocketKey, WebSocketKeyOptions } from './key';
import { WebSocketCryptoSuite } from './cryptoSuite';
import { Server } from "https";

export interface WSX509Identity extends Identity {
  type: IdentityProvidersType.WebSocket;
  credentials: {
    certificate: string;
    keyName:string;
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

export interface WSX509ProviderOptions extends Options {
  server?:Server;
  port?:string;
}

export class WSX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly classLogger: Logger;
  private readonly _wss: WebSocketServer;
  ws:WebSocket;
  secWsKey:string;

  constructor(opts: WSX509ProviderOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WSX509Provider');
    if (!opts.server && Util.isEmptyString(opts.port)) {
      throw new Error('require an http server or port number');
    }
    this._wss = opts.server ? 
      new WebSocketServer({ server: opts.server }) : 
      new WebSocketServer({ port: opts.port });

    this.classLogger.debug(`Initiate web socket server for the identity provider at ${this._wss.url}`);
    
    const self=this;
    this._wss.on('connection', function connection(ws,request) {
      self.classLogger.debug(`Attach web socket with sec key ${getSecWsKey(request)}`);
      self.ws=ws;
      self.secWsKey=getSecWsKey(request);
    });
  }
  async getUserContext(identity: WSX509Identity, name: string): Promise<User> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getUserContext');
    methodLogger.debug(`get user context for ${name} with: = \n%o`, identity);
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    user.setCryptoSuite(new WebSocketCryptoSuite());
    // get type of curve
    methodLogger.debug(`Get public key from provided identity crendential certificate`);
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate); 
    const pubKeyObj = cert.getPublicKey() as any;
    const pubKey = KEYUTIL.getPEM(pubKeyObj);
    let webSocketKey
    const wsKeyOptions:WebSocketKeyOptions={
      ws:this.ws,
      secWsKey:this.secWsKey,
      pubKey, 
      keyName: identity.credentials.keyName,
      curve: `p${pubKeyObj.ecparams.keylen}` as 'p256' | 'p384',
      logLevel:methodLogger.level as 'debug' | 'info' | 'error'
    }
    webSocketKey = new WebSocketKey(wsKeyOptions) ;
    await user.setEnrollment(
      webSocketKey,
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }
}
