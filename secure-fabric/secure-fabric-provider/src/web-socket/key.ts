import WebSocket from 'ws';
import { Util, Options } from '../internal/util';
import { InternalKey, asn1ToDer } from '../internal/key';
import { waitForSocketState } from './client';
import { Logger } from 'winston';
import { KEYUTIL, KJUR } from 'jsrsasign';
import { createHash } from 'crypto';
import asn1 from 'asn1.js';
import elliptic from 'elliptic';
const jsrsasign = require('jsrsasign');

export type SupportedCurves ={
  curve: 'p256' | 'p384';
}
export enum supportedCurves {
  p256 = 'secp256r1',
  p384 = 'secp384r1'
}
export type IClientDigest = {
  digest:Buffer; 
  preHashed?:boolean;
}
export type IClientCsrReq = {
  commonName:string;
}
export type WebSocketKeyOptions = Options & SupportedCurves & {
  ws: WebSocket; 
  pubKey:string;
  secWsKey?:string;
  keyName?:string;
};
interface IDigestQueue{
  digest:Buffer;
  signature?:Buffer;
} 

export class WebSocketKey extends InternalKey {
  private readonly classLogger: Logger;
  private _ws: WebSocket;
  private readonly secWsKey: string;
  private readonly pubKey:string;
  private readonly keyName:string;
  private readonly curve:string;
  private readonly algorithm:string;
  private readonly pubKeyObj;
  private processing:boolean;
  // Array of Digests to queue log signing requests in series
  private digestQueue:IDigestQueue[]

  constructor(opts: WebSocketKeyOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocketKey');
    if (Util.isEmptyString(opts.pubKey)) {
      throw new Error('pubKey pem should not be empty');
    }
    /*if (Util.isEmptyString(opts.secWsKey)) {
      throw new Error('secWsKey should not be empty');
    }
    /*if (Util.isEmptyString(opts.keyName)) {
      // we dont need the keyname only the publick key file to verify the signature
      // the outgoing webSocket connection is not be able to ask the client
      // for a particular keyname
      throw new Error('keyName should not be empty');
    }
    */
    this.pubKey = opts.pubKey;
    this.secWsKey = opts.secWsKey;
    this.keyName = opts.keyName;
    this.curve = opts.curve;
    this._ws = opts.ws;
    this.classLogger.debug(`Initialized WebSocketKey with secWsKey ${this.secWsKey}`);

    const keyLength = this.curve.split('p')[1];
    this.algorithm = `SHA${keyLength}withECDSA`;

    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves[this.curve];
    const ec = new EC(ecdsaCurve);
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(this.pubKey);     
    this.pubKeyObj = ec.keyFromPublic(pubKeyHex, 'hex');

    this.digestQueue = [];
    
    const self = this;
    this._ws.on('message', function incoming(message) {
      self.verify(message);
    });
    this._ws.onclose = function () {
      self.classLogger.debug(`WebSocketKey connection closed for secWsKey ${this.secWsKey}`);
      self._ws = null;
    };
  }

  /**
   * @description : close the WebSocket
   */
  async close(){
    if(this._ws){
      this._ws.close();
      await waitForSocketState(this._ws, this._ws.CLOSED); 
    }
  }

  /**
   * @description : sign message and return in a format in which fabric understand
   * @param args:IClientDigest
   * @param args.digest 
   * @param args.preHashed 
   */
  async sign(args: IClientDigest): Promise<Buffer> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`Sign digest using sec key ${this.secWsKey}: digestSize = ${args.digest.length} preHashed = ${args.preHashed}`);
    if(this.processing){
      throw new Error('a digest is still being signed by the client');
    }
    if(!args.preHashed){
      methodLogger.debug('get SHA256 hash of digest');
      args.digest = createHash('sha256').update(args.digest).digest()
    };
    this.digestQueue.push({digest: args.digest});
    const queueI = this.digestQueue.length-1; //spot in the queue
    this._ws.send(args.digest);

    methodLogger.debug(`Wait for digest ${queueI} to be signed`);
    this.processing = true;
    const signature = await this.inDigestQueue(queueI) 
    return asn1ToDer(signature,methodLogger)
  };

  /**
   * @description : wait for digest in queue to be processed
   * @param index
   * @return signture as Buffer 
   */
  private async inDigestQueue(index:number):Promise<Buffer>{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'inDigestQueue');
    const self = this;
    return new Promise(function (resolve) {
      setTimeout(function () {
        if (!self.processing) {
          methodLogger.debug(`Digest ${index} processed`);
          resolve(self.digestQueue[index].signature); 
        } else {
          self.inDigestQueue(index).then(resolve);
        }
      });
  });
  }

  /**
   * @description : signature is verified after processing by client and stored in digestQueue (serial processing)
   * @param index
   */
  private verify(signature:Buffer) {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'verify');

    // TO-DO if allowing parrallel signature processing
    // pull the queue index from the signature buf.
    const queueI = this.digestQueue.length-1;
    const digest = this.digestQueue[queueI].digest
    methodLogger.debug(`Digest to verify using ${this.algorithm}: ${digest.toString('hex').substring(0,6)}`)
    
    methodLogger.debug(`Write signature to digestQueue at position ${queueI} and market as processed `);
    this.digestQueue[queueI].signature = signature;
    this.processing = false;

    methodLogger.debug(`Signature to verify: ${signature.toString('hex').substring(0,6)}`)
    if(!this.pubKeyObj.verify(digest, signature)){
      throw new Error('Signature does not match the public key');
      throw new Error('Closing the web socket connection');
      this.close()
    }
  }

  /**
   * @description generate CSR to be signed by the client via web socket
   * @param args @type IClientCsrReq with attribtues required ot build CSR
   * @returns pem encoded csr
   */
  async generateCSR(args:IClientCsrReq): Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${args.commonName}`) 

    var rs = require('jsrsasign');
    const pub = KEYUTIL.getKey(this.pubKey);
    
    const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    csri.setSubjectByParam({ str: '/CN=' + args.commonName });
    csri.setSubjectPublicKeyByGetKey(pub);
    const csr = new rs.KJUR.asn1.csr.CertificationRequest({ 
      csrinfo: csri}) as any;
    //sigalg: this.algorithm 
    csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: this.algorithm });
    const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest();
    
    methodLogger.debug('Sign CSR digest');
    const signature = await this.sign({digest, preHashed: true});
    csr.hexSig = signature.toString('hex');
    csr.asn1Sig = new KJUR.asn1.DERBitString({ hex: '00' + csr.hexSig });
    const seq = new KJUR.asn1.DERSequence({ array: [csr.asn1CSRInfo, csr.asn1SignatureAlg, csr.asn1Sig] }) as any;
    csr.hTLV = seq.getEncodedHex();
    csr.isModified = false;
    const pem = csr.getPEMString();

    methodLogger.debug(`generated pem encoded csr = \n${pem}`);
    return pem as string;
  }
}
