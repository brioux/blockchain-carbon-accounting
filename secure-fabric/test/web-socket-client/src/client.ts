import WebSocket from 'ws';
import { Logger } from 'winston';
import fs from 'fs'; 
import elliptic from 'elliptic';
import { Options, Util } from './util';
import { keyGen, getKeyPath, getPubKeyHex, 
  IClientNewKey, KeyData, 
  ECCurveType, ECCurveLong } from './key';
const jsrsasign = require('jsrsasign');

type IecdsaCurves = {
  [key:string]:elliptic.ec; 
};

interface WSClientOtions {
  host:string;
  keyName?:string;
  curve?:ECCurveType;
  logLevel?:string; 
}


export class WebSocketClient {
  private readonly host;
  private keyData: KeyData;
  private ws: WebSocket;
  private ecdsaCurves:IecdsaCurves;
  private readonly classLogger: Logger;
  keyName:string;

  curve:ECCurveType;
  constructor(opts:WSClientOtions){
    if (Util.isEmptyString(opts.host)) {
      throw new Error('require host address of web socket server');
    }
    opts.logLevel = opts.logLevel || 'error'
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocketClient');
    
    this.host = opts.host;
    opts.keyName = opts.keyName || 'default';

    this.initKey({keyName: opts.keyName, curve: opts.curve})
    this.classLogger.debug('Initialize supported ECDSA curves used by the sign method');
    const EC = elliptic.ec;
    this.ecdsaCurves={};
    for (const value in ECCurveType) {
      this.ecdsaCurves[value] = new EC(elliptic.curves[value]);
    }
  };

  /**
   * @description will generate a new EC private key, or get existing key it already exists
   * @param args; 
   * @type IClientNewKey
   */
  initKey(args:IClientNewKey):string{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'initKey')
    methodLogger.debug(`Look for key with name '${args.keyName}' or generate new key`);
    let info=[];
  
    const keyPath = getKeyPath(args.keyName)
    if(!fs.existsSync(keyPath)){ 
      info.push(keyGen(args))
    }
    info.push(`Extracting key '${args.keyName}' from key store`)
    this.keyName = args.keyName;
    this.keyData = JSON.parse(fs.readFileSync(keyPath,'utf8'));
    if(args.curve && this.keyData.curve !== args.curve){
      info.push(`The requested curve type (${args.curve}) is different than the existing key: ${this.keyData.curve}`)
    }
    const result = info.join('\n')
    methodLogger.debug(result);
    return result;
  };

  /**
   * @description asynchronous request to get a new key and open new ws connection
   * @param args @type IClientNewKey 
   */
  async getKey(args:IClientNewKey,sessionId:string):Promise<void>{
    try{
      this.initKey(args);
      await this.open(sessionId)
    }catch(error){
      throw new Error(`Error setting client's key : ${error}`); 
    }
  }

  /**
   * @description Closes existing and open new websocket connection for client
   */
  async open(sessionId:string):Promise<void>{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'open')
    await this.close();
    try{
      //const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.pubKey);
      const signature = this.sign(Buffer.from(sessionId,'hex')).toString('hex')
      const wsHostUrl = `${this.host}/?sessionId=${sessionId}&signature=${signature}&crv=${this.keyData.curve}`;
      methodLogger.debug(`Open new WebSocket to host: ${wsHostUrl}`);
      this.ws = new WebSocket(wsHostUrl);
      await waitForSocketState(this.ws, this.ws.OPEN);
    }catch(error){
      throw new Error(`Error creating web-socket connection to host ${this.host}: ${error}`);
    }

    
    this.ws.onerror = function () {
      //throw new Error('require port for web socket');
    };
    this.ws.onopen = function () {
      console.log('WebSocket connection established');
    };
    const self = this;
    this.ws.onclose = function incoming() {
      console.log(`Web socket connection to ${self.host} closed for key ${self.keyName}`)
      self.ws = null;
    };
    this.ws.on('message', function incoming(message) {
      const signature = self.sign(message)
      methodLogger.debug(`Send signature to web socket server ${self.ws.url}`)
      self.ws.send(signature);
    });
  }
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
   * @description generate 
   * @param prehashed digest as Buffer
   * @returns signature as string
   */
  sign(digest:Buffer):Buffer{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    const { prvKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.key); 
    methodLogger.debug(`Use ${ECCurveLong[this.keyData.curve]} to sign digest: ${digest.toString('hex').substring(0,6)}`)
    const ecdsa = this.ecdsaCurves[this.keyData.curve];
    const signKey = ecdsa.keyFromPrivate(prvKeyHex, 'hex');
    const sig = ecdsa.sign(digest, signKey);
    let signature = Buffer.from(sig.toDER());
    methodLogger.debug(`Client signature: ${signature.toString('hex').substring(0,6)}`)
    return signature;
  };
  /**
   * @description send out pubKey
   * @return pubKey pem file
   */
  getPubKeyHex(){
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.pubKey);
    return pubKeyHex
  }
}

/**
 * Forces a process to wait until the socket's `readyState` becomes the specified value.
 * @param socket The socket whose `readyState` is being watched
 * @param state The desired `readyState` for the socket
 */
export function waitForSocketState(socket: WebSocket, state: number): Promise<void> {
  return new Promise(function (resolve,reject) {
    try {
      setTimeout(function () {
        if (socket.readyState === state) {
          resolve();
          //resolve(socket);
        } else {
          waitForSocketState(socket, state).then(resolve);
        }
      });
    } catch(err){
      reject(`Error wating for socket state ${state}: ${err} `)
    }
  });
}

