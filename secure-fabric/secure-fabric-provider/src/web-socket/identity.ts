import { ICryptoSuite } from "fabric-common";
import {
  LogLevelDesc,
  Logger,
  LoggerProvider,
} from "@hyperledger/cactus-common";
import { X509 } from 'jsrsasign';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import WebSocket, { WebSocketServer } from 'ws';
import { Key } from '../internal/key'; 
import { ECCurveType } from '../internal/crypto-util'
import { WebSocketClient, newEcdsaVerify } from './client';
import { InternalCryptoSuite } from '../internal/crypto-suite';
import { Server } from "https";
import { URLSearchParams } from "url";
import { randomBytes } from 'crypto';

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
interface IClientPubKeys {
  [key:string]: string;
}

export interface WSX509ProviderOptions {
  logLevel: LogLevelDesc;
  server?:Server;
  port?:string;
}

export class WSX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly log: Logger;
  public readonly className = "SecureIdentityProviders";
  readonly _wss: WebSocketServer;
  clients: IClientWebSockets;
  pubKeys: IClientPubKeys;

  constructor(private readonly opts: WSX509ProviderOptions) {
    super()
    const fnTag = `${this.className}#constructor`;
    this.log = LoggerProvider.getOrCreate({
      level: opts.logLevel || "INFO",
      label: this.className,
    });
    if (!opts.server && Util.isEmptyString(opts.port)) {
      throw new Error('require an http server or port number');
    }
    this._wss = opts.server ? 
      new WebSocketServer({ server: opts.server }) : 
      new WebSocketServer({ port: opts.port });

    this.log.debug(`Initiated web socket server for the identity provider at ${this._wss.url}`);
    this.clients = {};
    this.pubKeys = {};

    const self=this;
    this._wss.on('connection', function connection(ws,request) {
      const urlParams = new URLSearchParams(request.url.split('?')[1]);
      self.log.debug(`Url params sent by new web client: ${urlParams}`)
      const sessionId = urlParams.get('sessionId')
      const signature = urlParams.get('signature')
      const curve = urlParams.get('crv') as ECCurveType;
      if(!sessionId){
        throw new Error('no sessionId provided in the web-socket url');
      }
      if(!signature){
        throw new Error('no signature provided in the web-socket url');
      }
      if(!curve){
        throw new Error('no curve provided in the web-socket url');
        // TO-DO we can extract the curve data from the pubKeyHex? 
        // We should not need to pass the crv 
      }
      const pubKeyHex = self.pubKeys[sessionId];
      ws.onclose = function () {
        self.clients[sessionId] = null;
        self.log.debug(`Client closed for pubKeyHex ${pubKeyHex.substring(0,12)}...`)
      };
      
      self.log.debug(`build ECDSA curve required by abstract class InternalIdentityClient`);
      const pubKeyEcdsa = newEcdsaVerify(curve,pubKeyHex,sessionId,signature);

      if(pubKeyEcdsa){
        self.clients[pubKeyHex] = new WebSocketClient({
          pubKeyHex,
          curve,
          ws,
          pubKeyEcdsa,
          logLevel: self.opts.logLevel
        });
      }else{
        ws.close();
        throw new Error('the signature provided byt he incoming webSocket connection does not match the public key');
      }

    });
  }

  /**
   * @description get user context for the provided identity file
   * @note before this method is called the requested identity holder must open 
   * a websocket connection with the identity provider
   */
  async getUserContext(identity: WSX509Identity, name: string): Promise<User> {
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    user.setCryptoSuite(new InternalCryptoSuite());
    //user.setCryptoSuite(Utils.newCryptoSuite());
    
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate); 
    const pubKeyHex = cert.getPublicKey()['pubKeyHex'];

    if(!this.clients[pubKeyHex]){
      throw new Error(`no client connectected for public key ${pubKeyHex.substring(0,12).substring(0,12)}`);
    }
    const wsKey = new Key(pubKeyHex.substring(0,12),this.clients[pubKeyHex]);
    await user.setEnrollment(
      wsKey,
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }
  webSocketSessionId(pubKeyHex:string){
    const sessionId = randomBytes(8).toString('hex');
    this.pubKeys[sessionId] = pubKeyHex;
    return sessionId;
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
