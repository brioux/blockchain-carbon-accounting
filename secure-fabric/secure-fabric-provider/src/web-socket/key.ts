import WebSocket from 'ws';
//import { FabricWebSocketServer } from './server';
import { Util, Options } from '../internal/util';
import { InternalKey } from '../internal/key';
import { Logger } from 'winston';
import { KJUR } from 'jsrsasign';
import { createHash } from 'crypto';
import ecsig from 'elliptic/lib/elliptic/ec/signature.js';
import asn1 from 'asn1.js';
import BN from 'bn.js';
import { curves } from 'elliptic';
import { 
  IWebSocketSign, IWebSocketGetKey, IWebSocketCSR, 
  IClientNewKey, IClientCsrReq, IClientDigest,
  IClientSignature, IClientPubKeyData, IClientCSR } from './client';

const EcdsaDerSig = asn1.define('ECPrivateKey', function () {
  return this.seq().obj(this.key('r').int(), this.key('s').int());
});

const p256N = (curves as any).p256.n as BN;
const p384N = (curves as any).p384.n as BN;

export type WebSocketKeyOptions = Options &
//IClientNewKey &
{ ws: WebSocket; 
  pubKeyData: IClientPubKeyData;};

export class WebSocketKey extends InternalKey {
  private readonly classLogger: Logger;
  private readonly _ws: WebSocket;
// What public key data shouldnwe store on the client operating server side?
// Right now we are sending the key name the, the public key and the ecdsa curve type
// We can instead keep all the necessary key data on the client using the service
// We can communicate only the keyName/or publicKey for the client to know what key the user has currenlty exposed
  private pubKeyData:IClientPubKeyData; 
  constructor(opts: WebSocketKeyOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocketKey');
    if (opts.ws === undefined) {
      throw new Error('require web socket client');
    }
    this._ws = opts.ws;
    this.pubKeyData=opts.pubKeyData
    
    /*this._ws.on('message', async function incoming(message) {
      this.opts pubKeyData await onMessage
      this.classLogger.debug('Store public key for client with SEC WebSocket key %{secWSKey}');
      console.log(pubKeyData)
    })*/
  }

  /**
   * @description will generate a EC private, new if key doesn't exists , or get existing key it is already exists
   * @param args: IClientNewKey
   *    @param args.keyName label of the key
   *    @param arg.curve 'p256'|'p384'
   * @return public key in hex form
   */
  async getKey(args:IClientNewKey): Promise<string> { 
    const methodLogger = Util.getMethodLogger(this.classLogger, 'newKey');
    methodLogger.debug(`generate new key with name = ${args.keyName} of type ${args.curve}`);
    //this.keyName = args.keyName
    const getKey: IWebSocketGetKey = {fcn: 'getKey', args}; 
    this._ws.send(getKey);
    this.pubKeyData = await this.onMessage();
    methodLogger.debug(`%{args.keyName} retreived successfully with public key %{pubKeyData.pubKey}`);
    return this.pubKeyData.pubKey;
  }

  /**
   * @description Request CSR to be genearted thorugh web socket connection
   * @param args 
   * @type IClientCsrReq with attribtues required ot build CSR
   * @returns pem encoded csr
   */
  async generateCSRws(args:IClientCsrReq): Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${args.commonName}`);
    const newCSR:IWebSocketCSR ={fcn: 'generateCSR', args: args}
    this._ws.send(newCSR);
    const message:IClientCSR = await this.onMessage();
    return message.csr;
  }

  /**
   * @param commonName of the client
   * @returns pem encoded csr
   */
  async generateCSR(args:IClientCsrReq): Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${args.commonName}`);
    const pub = new KJUR.crypto.ECDSA({ curve: this.pubKeyData.curve });
    pub.setPublicKeyHex(this.pubKeyData.pubKey);

    methodLogger.debug('creating csr information');
    const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    csri.setSubjectByParam({ str: '/CN=' + args.commonName });
    csri.setSubjectPublicKeyByGetKey(pub);
    const csr = new KJUR.asn1.csr.CertificationRequest({ csrinfo: csri }) as any;
    csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: 'SHA256withECDSA' });
    const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest('hex');
    
    methodLogger.debug('Sign CSR digest');
    const signDigest:IWebSocketSign = {fcn: 'sign', args: {digest: Buffer.from(digest),preHashed: true}}
    this._ws.send(signDigest);
    const message:IClientSignature = await this.onMessage();

    csr.hexSig = message.signature.toString('hex');
    csr.asn1Sig = new KJUR.asn1.DERBitString({ hex: '00' + csr.hexSig });
    const seq = new KJUR.asn1.DERSequence({ array: [csr.asn1CSRInfo, csr.asn1SignatureAlg, csr.asn1Sig] }) as any;
    csr.hTLV = seq.getEncodedHex();
    csr.isModified = false;

    const pem = csr.getPEMString();
    methodLogger.debug(`generated pem encoded csr = \n${pem}`);
    return pem as string;
  }

  /**
   * @description : sign message and return in a format in which fabric understand
   * @param args:IClientDigest
   * @param args.digest 
   * @param args.preHashed 
   */
  async sign(args: IClientDigest): Promise<Buffer> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`digestSize = ${args.digest.length} preHashed = ${args.preHashed}`);
    const signDigest:IWebSocketSign = {fcn: 'sign', args }
    this._ws.send(signDigest);
    const message:IClientSignature = await this.onMessage();

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
    return signature ; 
  }

  async onMessage(){
    const methodLogger = Util.getMethodLogger(this.classLogger, 'onMessage');
    return await this._ws.on('message', async function incoming(message) {
      methodLogger.debug(`Received web socket message: ${message}`);
      return JSON.parse(message);  
    });
  }
}
