import WebSocket from 'ws';
import { WebSocketClient } from './client';
import { Util, Options } from '../internal/util';
import { Key } from '../internal/key';
import { CryptoUtil } from "../internal/crypto-util";
import { Logger } from 'winston';
import { KJUR } from 'jsrsasign';
import { createHash } from 'crypto';

export interface IClientDigest {
  digest:Buffer; 
  preHashed?:boolean;
}
export interface IClientCsrReq {
  commonName:string;
}
export interface WebSocketKeyOptions extends Options {
  client: WebSocketClient;
  keyName:string;
};
export class WebSocketKey extends Key {
  private readonly classLogger: Logger;
  private readonly client: WebSocketClient;



  constructor(opts: WebSocketKeyOptions) {
    super(keyName:opts.keyName, client: opts.client);
    /*this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocketKey');

    this.client = opts.client;
    this.classLogger.debug(`Initialized WebSocketKey`)*/
  }

  /**
   * @description : sign message and return in a format in which fabric understand
   * @param args:IClientDigest
   * @param args.digest 
   * @param args.preHashed 
   */
  /*
  async sign(digest: Buffer): Promise<Buffer> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`Sign digest using sec key ${this.secWsKey}: digestSize = ${args.digest.length} preHashed = ${args.preHashed}`);
     if(!args.preHashed){
      methodLogger.debug('get SHA256 hash of digest');
      args.digest = createHash('sha256').update(args.digest).digest()
    };   
    signature = await this._backend.sign({keyname:'',digest: args.digest})
  };
  */
  /**
   * @description generate CSR to be signed by the client via web socket
   * @param args @type IClientCsrReq with attribtues required ot build CSR
   * @returns pem encoded csr
   */
  /*
  async generateCSR(args:IClientCsrReq): Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${args.commonName}`) 

    const pub = this._backend.getPub();
    
    
    //const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    //csri.setSubjectByParam({ str: '/CN=' + args.commonName });
    //csri.setSubjectPublicKeyByGetKey(pub);
    //const csr = new KJUR.asn1.csr.CertificationRequest({ 
      csrinfo: csri}) as any;
    //const ecdsaAlg = `SHA256withECDSA`;
    //csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: ecdsaAlg });
    
    let csr = CryptoUtil.createCsr(pub,args.commonName);
    const digest = getCSRDigest(csr);
    //const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest();
    
    methodLogger.debug('Sign CSR digest');
    const signature = await this._backend.sign({keyName: this._backend.keyName, digest});
    csr.hexSig = signature.toString('hex');
    
    csr.asn1Sig = new KJUR.asn1.DERBitString({ hex: '00' + csr.hexSig });
    const seq = new KJUR.asn1.DERSequence({ array: [csr.asn1CSRInfo, csr.asn1SignatureAlg, csr.asn1Sig] }) as any;
    csr.hTLV = seq.getEncodedHex();
    csr.isModified = false;
    //const pem = csr.getPEMString();
    const pem = getPemCSR(csr,signature);
    methodLogger.debug(`generated pem encoded csr = \n${pem}`);
    return pem as string;
  }*/
}
