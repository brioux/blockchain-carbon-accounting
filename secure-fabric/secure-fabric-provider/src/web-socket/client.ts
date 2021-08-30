import WebSocket from 'ws';
import { Logger } from 'winston';
import { createPublicKey, JwkKeyExportOptions, createHash } from 'crypto';
import { KEYUTIL, KJUR } from 'jsrsasign';
import fs from 'fs';
import { Options, Util } from '../internal/util';
import { SupportedCurves, supportedCurves} from './key'
import elliptic from 'elliptic';
const jsrsasign = require('jsrsasign');

type KeyData = SupportedCurves & {
  key:string;
  pubKey:string;
}

export type IClientNewKey = Partial<SupportedCurves> & {
  keyName: string;
}

export type WebSocketClientOptions = Options & Partial<SupportedCurves> & { 
  host:string;
  keyName?:string;
}

type IecdsaCurves = {
  [key:string]:elliptic.ec; 
};

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

export class WebSocketClient {
  private readonly classLogger: Logger;
  private readonly walletPath: string;
  private keyData: KeyData;
  ws: WebSocket;
  private readonly host: string;
  private ecdsaCurves:IecdsaCurves;

  constructor(opts: WebSocketClientOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocket Client');
    if (Util.isEmptyString(opts.host)) {
      throw new Error('require host address of web socket server');
    }
    this.walletPath = `${__dirname}/cli_wallet`;
    if(!fs.existsSync(this.walletPath)){
      this.classLogger.debug('Make directory to store keys at ${this.walletPath}');
      fs.mkdirSync(this.walletPath)
    };
    opts.keyName = opts.keyName || 'default'
    this.initKey({keyName: opts.keyName, curve: opts.curve})
    this.host = opts.host

    this.classLogger.debug('Initialize supported ECDSA curves used by keyGen and sign methods');
    const EC = elliptic.ec;

    this.ecdsaCurves={};
    Object.keys(supportedCurves).forEach(curve => {
      this.ecdsaCurves[curve] = new EC(elliptic.curves[curve]);
    });
  };

  /**
   * @description : close the WebSocket
   */
  async close():Promise<void>{
    if(this.ws){
      this.ws.close();
      await waitForSocketState(this.ws, this.ws.CLOSED); 
    }
  }

  /**
   * @description asynchronous request to get a new key. Closes the exisitng websocket connection and opens a new one
   * @param args @type IClientNewKey 
   */
  async getKey(args:IClientNewKey):Promise<string>{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getKey')
    methodLogger.debug(`Close existing websocket for key ${args.keyName}`);
    await this.close();

    methodLogger.debug(`Open new WebSocket to host server ${this.host} for ${args.keyName}`);
    this.ws = new WebSocket(`${this.host}`);
    await waitForSocketState(this.ws, this.ws.OPEN);

    /*
    this.ws.onerror = function () {
      throw new Error('require port for web socket');
    };
    this.ws.onopen = function () {
      console.log('WebSocket connection established');
    };
    */
    const self = this;
    this.ws.onclose = function incoming() {
      self.classLogger.debug(`Web socket connection closed for key ${args.keyName}`);
      self.ws = null;
    };
    this.ws.on('message', function incoming(message) {
      self.sign(message)
    });
    return this.initKey(args);
  }

  /**
   * @description will generate a new EC private key, or get existing key it already exists
   * @param args; 
   * @type IClientNewKey
   */
  private initKey(args:IClientNewKey):string{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getKey')
    this.classLogger.debug(`Look for key with name '${args.keyName}' or generate new key`);
    let info=[];
    const keyPath = this.keyPath(args.keyName);
    if(fs.existsSync(keyPath)){ 
      info.push(`Extracting existing key '${args.keyName}' from key store`)
      this.keyData = JSON.parse(fs.readFileSync(keyPath,'utf8'));
      if(args.curve && this.keyData.curve !== args.curve){
        info.push(`The requested curve type (${args.curve}) is different than the existing key: ${this.keyData.curve}`)
      }
    }else{
      this.keyGen(args)
    }
    const result = info.join('\n')
    methodLogger.debug(result);
    return result;
  };

  /**
   * @description will generate a EC private, new if key doesn't exists , or get existing key it is already exists
   * @param args; @type IClientNewKey
   */
  private keyGen(args:IClientNewKey){
    const methodLogger = Util.getMethodLogger(this.classLogger, 'keyGen'); 
    if(!args.curve){
      methodLogger.debug('No curve specified. Set to p256 as default');
      args.curve = 'p256'
    }
    const ecdsaAlg = supportedCurves[args.curve]; 
    methodLogger.debug(`Create ${args.keyName} key with elliptical curve ${ecdsaAlg}`)
    const keyPair = KEYUTIL.generateKeypair('EC',ecdsaAlg)
    const key = KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV")
    const pubKey = KEYUTIL.getPEM(keyPair.pubKeyObj)
    this.keyData = {key,pubKey,curve: args.curve};
    methodLogger.debug(`Store private key data for ${args.keyName}`)
    fs.writeFileSync(this.keyPath(args.keyName),JSON.stringify(this.keyData));
  };

  /**
   * @description generate 
   * @param prehashed digest as Buffer
   * @returns signature as string
   */
  sign(digest:Buffer):string{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    const { prvKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.key); 
    methodLogger.debug(`Use ${supportedCurves[this.keyData.curve]} to sign digest: ${digest.toString('hex').substring(0,6)}`)
    const ecdsa = this.ecdsaCurves[this.keyData.curve];
    const signKey = ecdsa.keyFromPrivate(prvKeyHex, 'hex');
    const sig = ecdsa.sign(digest, signKey);
    let signature = Buffer.from(sig.toDER());
    methodLogger.debug(`Client signature: ${signature.toString('hex').substring(0,6)}`)

    methodLogger.debug(`Send signature to web socket server ${this.ws.url}`)
    this.ws.send(signature);
    return signature.toString('hex');
  };
  private keyPath(keyName:string){
    return `${this.walletPath}/${keyName}.key`
  };
  /**
   * @description send out pubKey
   * @return pubKey pem file
   */
  getPub(){
    return this.keyData.pubKey;
  }
}

