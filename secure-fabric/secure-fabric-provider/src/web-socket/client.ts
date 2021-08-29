import WebSocket from 'ws';
import { Logger } from 'winston';
import { createPublicKey, JwkKeyExportOptions, createHash } from 'crypto';
import { KEYUTIL, KJUR } from 'jsrsasign';
import fs from 'fs';
import { Options, Util } from '../internal/util';
import { SupportedCurves, supportedCurves} from './key'

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

  constructor(opts: WebSocketClientOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocket Client');
    if (Util.isEmptyString(opts.host)) {
      throw new Error('require host address of web socket server');
    }
    this.host = opts.host
    this.setWebSocket()

    this.walletPath = `${__dirname}/cli_wallet`;
    if(!fs.existsSync(this.walletPath)){
      this.classLogger.debug('Make directory to store keys at ${this.walletPath}');
      fs.mkdirSync(this.walletPath)
    };
    opts.keyName = opts.keyName || 'default'
    this.initKey({keyName: opts.keyName, curve: opts.curve})

  };
  /**
   * @description sett the WebSocket events for the client
   * @param 
   */
  private setWebSocket(){
    this.classLogger.debug(`Create WebSocket to communicate with host server: ${this.host}`);
    this.ws = new WebSocket(`${this.host}`);
    /*
    this.ws.onerror = function () {
      throw new Error('require port for web socket');
    };
    this.ws.onopen = function () {
      console.log('WebSocket connection established');
    };
    */
    const self = this;
    this.ws.onclose = async function incoming() {
      this.classLogger.debug('Web socket connection closed');
      self.ws = null;
    };

    this.ws.on('message', function incoming(message) {
      self.sign(message)
    });
  }

  /**
   * @description : close the WebSocket key and its connetions
   */
  async close():Promise<void>{
    this.ws.close();
    await waitForSocketState(this.ws, this.ws.CLOSED); 
  }

  /**
   * @description will generate a new EC private key, or get existing key it already exists
   * @param args; 
   * @type IClientNewKey
   */
  private initKey(args:IClientNewKey):string{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getKey')
    this.classLogger.debug(`Look for key with ${args.keyName} or generate new key`);
    const keyPath = this.keyPath(args.keyName);
    let info=[];
    if(fs.existsSync(keyPath)){ 
      methodLogger.debug(`Extracting existing key ${args.keyName} from key store`)
      this.keyData = JSON.parse(fs.readFileSync(keyPath,'utf8'));
      info.push('Key retrieved from key store');
      if(!args.curve && this.keyData.curve !== args.curve){
        info.push(`The requested curve type (${args.curve}) is different than the existing key: ${this.keyData.curve}`)
      }
    }else{
      if(!args.curve){
        info.push('No curve specified. Using p256 as default');
        args.curve = 'p256'
      }
      info.push(this.keyGen(args))
    }
    const result = info.join('\n')
    methodLogger.debug(result);
    return result;
  };

  /**
   * @description asynchronous request to get a new key. Closes the exisitng websocket connection and opens a new one
   * @param args @type IClientNewKey 
   */
  async getKey(args:IClientNewKey):Promise<string>{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'changeKey')
    methodLogger.debug(`Close existing websocket and open new connection ${this.host}`);
    await this.close()
    this.setWebSocket()
    await waitForSocketState(this.ws, this.ws.OPEN);
    return this.initKey(args)
  }

  /**
   * @description will generate a EC private, new if key doesn't exists , or get existing key it is already exists
   * @param args; @type IClientNewKey
   */
  private keyGen(args:IClientNewKey){
    const methodLogger = Util.getMethodLogger(this.classLogger, 'keyGen'); 
    const ecdsaCurve = supportedCurves[args.curve]; 
    const result = `Create ${args.keyName} key with elliptical curve ${ecdsaCurve}`
    methodLogger.debug(result)
    const keyPair = KEYUTIL.generateKeypair('EC',ecdsaCurve)
    const key = KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV")
    const pubKey = KEYUTIL.getPEM(keyPair.pubKeyObj)
    this.keyData = {key,pubKey,curve: args.curve};
    methodLogger.debug(`Store private key data for ${args.keyName}`)
    fs.writeFileSync(this.keyPath(args.keyName),JSON.stringify(this.keyData))
    return result;
  };

  /**
   * @description generate 
   * @param prehashed digest as Buffer
   * @returns signature as string
   */
  sign(digest:Buffer):string{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');

   
    const jsrsasign = require('jsrsasign');
    const { prvKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.key); 
    
    const elliptic = require('elliptic');
    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves[this.keyData.curve];

    methodLogger.debug(`Use ${supportedCurves[this.keyData.curve]} to sign digest: ${digest.toString('hex')}`)
    const ecdsa = new EC(ecdsaCurve);
    const signKey = ecdsa.keyFromPrivate(prvKeyHex, 'hex');
    const sig = ecdsa.sign(digest, signKey);
    const signature = Buffer.from(sig.toDER());
    methodLogger.debug(`Client signature: ${signature.toString('hex')}`)

    /*
    const keyLength = this.keyData.curve.split('p')[1];
    const alg = `SHA${keyLength}withECDSA`;

    methodLogger.debug(`Use algorithm ${alg} to sign digest of length ${digest.length}`);//: ${digest.toString()}
    const sig = new KJUR.crypto.Signature({"alg":alg})
    sig.init(this.keyData.key);
    sig.updateString(digest.toString());
    const signature = sig.sign();
    //methodLogger.debug(`Client signature: ${signature}`)
    /*
    methodLogger.debug(`Verify signature: ${digest.toString('hex')}`);
    const sig2 = new KJUR.crypto.Signature({"alg": `SHA${keyLength}withECDSA`})
    sig.init(this.keyData.pubKey)
    sig.updateHex(digest.toString('hex'))
    if(!sig.verify(signature)){
      throw new Error('signature does not match the public key');
    }
    */
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
