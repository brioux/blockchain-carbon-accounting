import WebSocket from 'ws';
import { Logger, LoggerProvider, LogLevelDesc } from "@hyperledger/cactus-common";
import { KEYUTIL, KJUR } from 'jsrsasign';
import fs from 'fs';
import { Options, Util } from '../internal/util';
import { InternalIdentityClient, ISignatureResponse } from "../internal/client";
import { ECCurveLong, ECCurveType, CryptoUtil } from "../internal/crypto-util";
import elliptic from 'elliptic';

export interface WebSocketClientOptions { 
  curve: ECCurveType;
  ws: WebSocket;
  pubKeyHex: string;
  secWsKey?:string;
  logLevel?: LogLevelDesc;
}

interface IDigestQueue{
  digest:Buffer;
  signature?:Buffer;
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

/**
 * @description : wait for digest in queue to be processed
 * @param index
 * @return signture as Buffer 
 */
function inDigestQueue(client:WebSocketClient,index:number):Promise<Buffer> {
  return new Promise(function (resolve) {
    setTimeout(function () {
      if (!client.processing) {
        resolve(client.digestQueue[index].signature); 
      } else {
        inDigestQueue(client,index).then(resolve);
      }
    });
  })
}

export class WebSocketClient implements InternalIdentityClient {
  public readonly className = "WebSocketClient";
  private readonly log: Logger;
  private readonly backend: WebSocket;
  private readonly curve: ECCurveType;
  private readonly pubKeyHex:string;
  private readonly secWsKey:string;
  private readonly pubKeyEcdsa:any;//KJUR.crypto.ECDSA;
  private readonly pubKeyObj; // pubKey from elliptic node pacakge for verifying digest signatures
  // Array of Digests to queue signing requests in series
  digestQueue:IDigestQueue[]
  processing:boolean;


  constructor(opts: WebSocketClientOptions) {
    this.log = LoggerProvider.getOrCreate({
      label: "WebSocketClient",
      level: opts.logLevel || "INFO",
    });
    this.backend = opts.ws;
    this.curve = opts.curve;
    this.pubKeyHex = opts.pubKeyHex;
    this.secWsKey = opts.secWsKey;
    this.digestQueue = [];
    this.log.debug(`New web-socket client for publicKey ${this.pubKeyHex.substring(0,6)}`);
    
    this.log.debug(`Build ECDSA curve required by abstract class InternalIdentityClient`);
    //this.pubKeyEcdsa = new KJUR.crypto.ECDSA({'curve': ECCurveLong[this.curve], 'pub': this.pubKeyHex});
    this.pubKeyEcdsa = KEYUTIL.getKey(this.pubKeyHex, null, "pkcs8pub")
    
    this.log.debug(`Initialize elliptic key used to verify incoming signatures`);
    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves[this.curve];
    const ec = new EC(ecdsaCurve);
    this.pubKeyObj = ec.keyFromPublic(this.pubKeyHex, 'hex');

    const self = this;
    this.backend.on('message', function incoming(signature) {
      self.verify(signature);
    });
    this.backend.onclose = function () {
      self.log.debug(`WebSocket connection closed for public key ${this.pubKeyHex.substring(0,6)}...`);
      //self.backend = null;
    };
  };

  /**
   * @description : sign message and return in a format in which fabric understafnd
   * @param args:IClientDigest
   * @param args.digest 
   * @param args.preHashed 
   */
  async sign(keyName: string, digest: Buffer): Promise<ISignatureResponse> {
    const fnTag = `${this.className}#sign`;
    this.log.debug(
      `Sign digest for pubKey ${this.pubKeyHex.substring(0,6)}: digestSize = ${digest.length}`,
    );
    if(this.processing){
      throw new Error('a digest is still being signed by the client');
    }
    this.digestQueue.push({digest: digest});
    const queueI = this.digestQueue.length-1; //spot in the queue
    this.backend.send(digest);

    this.log.debug(`Wait for digest ${queueI} to be signed`);
    this.processing = true;
    const raw = await inDigestQueue(this,queueI) 
    const sig = CryptoUtil.encodeASN1Sig(raw,this.curve)
    return {sig, crv: this.curve}
  };

  /**
   * @description return public key ECDSA
   * @return ECDSA curve
   */
  async getPub(keyName: string): Promise<KJUR.crypto.ECDSA> {
    return new Promise(function (resolve) {
      resolve(this.pubKeyEcdsa)
    });
  }
  /**
   * @description return public key ECDSA
   * @return ECDSA curve
   */
  async rotateKey(keyName: string): Promise<void> {
    return new Promise(function (resolve,reject) {
      //resolve('WebSocket client can not rotate private keys. External client must enroll with a new csr')
      reject('WebSocket client can not rotate private keys. External client must enroll with a new csr')
    });
  }
  /**
   * @description : signature is verified after processing by client and stored in digestQueue (serial processing)
   * @param index
   */
  private verify(signature:Buffer) {
    const fnTag = `${this.className}#verify`;
    // TO-DO if allowing parrallel signature processing
    // pull the queue index from the signature buf.
    const queueI = this.digestQueue.length-1;
    const digest = this.digestQueue[queueI].digest
    this.log.debug(`Digest to verify using ${ECCurveLong[this.curve]}: ${digest.toString('hex').substring(0,6)}`)
    this.log.debug(`Write signature to digestQueue at position ${queueI} and mark as processed `);
    this.digestQueue[queueI].signature = signature;
    this.processing = false;
    this.log.debug(`Signature to verify: ${signature.toString('hex').substring(0,6)}`)
    const verified = this.pubKeyObj.verify(digest, signature)
    if(!verified){
      throw new Error('Signature does not match the public key. Closing the web socket connection');
      this.close()
    }
  }
  /**
   * @description : close the WebSocket
   */
  async close(){
    this.backend.close();
    await waitForSocketState(this.backend, this.backend.CLOSED); 
  }
}


