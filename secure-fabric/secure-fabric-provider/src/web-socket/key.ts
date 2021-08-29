import WebSocket from 'ws';
import { Util, Options } from '../internal/util';
import { InternalKey } from '../internal/key';
import { Logger } from 'winston';
import { KEYUTIL, KJUR } from 'jsrsasign';
import { createHash } from 'crypto';
import asn1 from 'asn1.js';


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

const elliptic = require('elliptic');
const jsrsasign = require('jsrsasign');
export class WebSocketKey extends InternalKey {
  private readonly classLogger: Logger;
  private _ws: WebSocket;
  private readonly secWsKey: string;
  private readonly pubKey:string;
  private readonly keyName:string;
  private readonly curve:string;
  private readonly algorithm:string;
  private processing:boolean;
  private readonly pubKeyObj;
  // TO-DO ? Use array of Digests to queue multiple signing requests.
  // Need to make sure signatures returend by client match the queued digest.
  // e.g. append queue ticket number to digest and pull from incoming signature buff
  // for now we stop the queue when this.processing is true
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

    this._ws = opts.ws;
    this.pubKey = opts.pubKey;
    this.secWsKey = opts.secWsKey;
    this.keyName = opts.keyName;
    this.curve = opts.curve;

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
    this._ws.onclose = async function () {
      this.classLogger.debug('Web socket connection closed');
      this._ws = null;
    };
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
    methodLogger.debug(`Wait for digest ${queueI} to be signed`);
    this.processing = true;
    this._ws.send(args.digest);
    const raw = await this.inDigestQueue(queueI) 
    return raw;
  };

  /**
   * @description : wait digest in queue to be processed
   * @param index
   * @return siganture as Buffer 
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

  private verify(signature:Buffer) {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'verify');

    // TO-DO if allowing parrallel signature processing
    // pull the queue index from the signature buf.
    const queueI = this.digestQueue.length-1;
    const digest = this.digestQueue[queueI].digest
    methodLogger.debug(`Digest to verify using ${this.algorithm}: ${digest.toString('hex')}`)
    
    methodLogger.debug(`Write signature to digestQueue at position ${queueI}`);
    this.digestQueue[queueI].signature = signature;
    this.processing = false;

    methodLogger.debug(`Signature to verify: ${signature.toString('hex')}`)
    if(!this.pubKeyObj.verify(digest, signature)){
      throw new Error('signature does not match the public key');
    }
    /*
    methodLogger.debug(`Verify signature using ${this.algorithm}`);
    const sig = new KJUR.crypto.Signature({alg: this.algorithm})
    sig.init(this.pubKey)
    //
    sig.updateString(digest.toString())
    //methodLogger.debug(`Signature to verify: ${signature.toString()}`)
    if(!sig.verify(signature.toString())){
      throw new Error('signature does not match the public key');
    }
    */

    
    /*
    the sign method from the WebSocketClient Class 
    should send the signature in a format fabric understands. 
    methodLogger.debug(`converting asn1 sig format to der for fabric to accept`);
    const rsSig = EcdsaDerSig.decode(message.signature, 'der');
    const r = rsSig.r as BN;
    let s = rsSig.s as BN;
    if (r === undefined || s === undefined) {
      throw new Error('invalid signature');
    }
    let crvN: BN = p256N;
    if (this.pubKeyData.curve === 'p384') {
      crvN = p384N;
    }
    const halfOrder = crvN.shrn(1);
    if (!halfOrder) {
      throw new Error('Can not find the half order needed to calculate "s" value for immalleable signatures');
    }
    if (s.cmp(halfOrder) === 1) {
      const bigNum = crvN as BN;
      s = bigNum.sub(s);
    }
    const der = new ecsig({ r: r, s: s }).toDER();
    methodLogger.debug(`digest successfully signed`);
    const signature= Buffer.from(der);
    */
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
