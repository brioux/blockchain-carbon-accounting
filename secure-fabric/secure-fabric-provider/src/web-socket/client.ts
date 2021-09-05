import WebSocket from 'ws';
import { Logger, LoggerProvider, LogLevelDesc } from "@hyperledger/cactus-common";
import { KEYUTIL, KJUR } from 'jsrsasign';
import fs from 'fs';
import { Options, Util } from '../internal/util';
import { InternalIdentityClient, ISignatureResponse } from "../internal/client";
import { ECCurveLong, ECCurveType, CryptoUtil } from "../internal/crypto-util";
import elliptic from 'elliptic';


export interface WebSocketClientOptions { 
  pubKeyHex: string;
  curve: ECCurveType;
  ws: WebSocket;
  pubKeyEcdsa: KJUR.crypto.ECDSA;
  logLevel?: LogLevelDesc;
}

interface IDigestQueue{
  digest:Buffer;
  signature?:Buffer;
} 



export class WebSocketClient implements InternalIdentityClient {
  public readonly className = "WebSocketClient";
  private readonly log: Logger;
  private readonly backend: WebSocket;
  private readonly curve: ECCurveType;
  private readonly secWsKey:string;
  private readonly pubKeyEcdsa:KJUR.crypto.ECDSA; //KJUR.crypto.ECDSA for csr requests;
  //private readonly pubKeyObj:; // pubKey from elliptic node pacakge for verifying digest signatures
  private readonly pubKeyHex:string;
  // Array of Digests to queue signing requests in series
  private digestQueue:IDigestQueue[]
  private processing:boolean;


  constructor(opts: WebSocketClientOptions) {
    this.log = LoggerProvider.getOrCreate({
      label: "WebSocketClient",
      level: opts.logLevel || "INFO",
    });
    this.log.debug(`new web-socket client for publicKey ${opts.pubKeyHex.substring(0,6)}`);
       
    this.backend = opts.ws;
    this.curve = opts.curve;
    this.pubKeyHex = opts.pubKeyHex;
    this.pubKeyEcdsa = opts.pubKeyEcdsa;
    this.digestQueue = [];
 
    //this.log.debug(`initialize elliptic key used to verify incoming signatures`);
    //this.pubKeyObj = opts.pubKeyObj

    const self = this;
    this.backend.on('message', function incoming(signature) {
      self.verify(signature);
    });
    this.backend.onclose = function () {
      self.log.debug(`WebSocket connection closed for public key ${this.pubKeyHex.substring(0,12)}...`);
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
      `Sign digest for pubKey ${this.pubKeyHex.substring(0,12)}: digestSize = ${digest.length}`,
    );
    if(this.processing){
      throw new Error('a digest is still being signed by the client');
    }
    this.digestQueue.push({digest: digest});
    const queueI = this.digestQueue.length-1; //spot in the queue
    this.backend.send(digest);

    this.log.debug(`Wait for digest ${queueI} to be signed`);
    this.processing = true;
    const raw = await this.inDigestQueue(queueI) 
    const sig = CryptoUtil.encodeASN1Sig(raw,this.curve)
    return {sig, crv: this.curve}
  };

  /**
   * @description return public key ECDSA
   * @return ECDSA curve
   */
  async getPub(keyName: string): Promise<KJUR.crypto.ECDSA> {
    const self = this
    return new Promise(function (resolve) {
      resolve(self.pubKeyEcdsa)
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
  private verify(signature:Buffer):boolean {
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
    const verified = this.pubKeyEcdsa.verifyHex(
      digest.toString('hex'), signature.toString('hex'),this.pubKeyHex)
    if(!verified){
      this.log.debug('signature does not match the public key. closing the web socket connection');
      this.backend.close()
    }
    return verified;
  }
/**
 * @description : wait for digest in queue to be processed
 * @param index
 * @return signture as Buffer 
 */
  private inDigestQueue(index:number):Promise<Buffer> {
    const client = this;
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (!client.processing) {
          resolve(client.digestQueue[index].signature); 
        } else {
          client.inDigestQueue(index).then(resolve);
        }
      });
    })
  }
}

export function newEcdsaVerify(
  curve:string,
  pubKeyHex:string,
  digest:string,
  signature:string) {
  const ecdsa = new KJUR.crypto.ECDSA({'curve': ECCurveLong[curve], 'pub': pubKeyHex});
  //this.pubKeyEcdsa = KEYUTIL.getKey(this.pubKeyHex, null, "pkcs8pub")
  if(ecdsa.verifyHex(digest,signature,pubKeyHex)){
    return ecdsa
  };

  /*
  const ecdsaCurve = elliptic.curves[curve];
  const ec = new elliptic.ec(ecdsaCurve);
  const pubKeyObj = ec.keyFromPublic(pubKeyHex, 'hex');
  if(pubKeyObj.verify(digest, signature)){
    return pubKeyObj
  }
  */
}

