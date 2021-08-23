import WebSocket from 'ws';
import { Logger } from 'winston';
import elliptic from 'elliptic';
import KeyEncoder from 'key-encoder'
import { createPublicKey, JwkKeyExportOptions, createHash } from 'crypto';
import { KEYUTIL, KJUR } from 'jsrsasign';
import asn1 from 'asn1.js';
import BN from 'bn.js';
import fs from 'fs';
import { Options, Util } from '../internal/util';

export type SupportedCurves ={
  curve: 'p256' | 'p384';
}
enum supportedCurves {
  p256 = 'secp256r1',
  p384 = 'secp384r1'
}
export type IClientDigest = {
  digest:Buffer; 
  preHashed?:boolean;
}
export type IClientSignature = {
  signature:Buffer;
}
export type IClientNewKey = Partial<SupportedCurves> & {
  keyName: string;
}
export type IClientCsrReq = {
  commonName:string;
}
export type IClientCSR = {
  csr:string;
}
export type IClientPubKey = {
  pubKey:string;
}

export type IClientPubKeyData = Partial<SupportedCurves> & Partial<IClientPubKey> &{
  keyName:string;
}

type KeyData = SupportedCurves & IClientPubKey & {
  key:string;
}

export type IWebSocketSign = {
  fcn: 'sign';
  args: IClientDigest ;
}
export type IWebSocketGetKey = {
  fcn: 'getKey';
  args: IClientNewKey;
}
export type IWebSocketCSR = {
  fcn: 'generateCSR';
  args: {commonName:string};
}

export type FabricWebSocketClientOptions = Options & Partial<SupportedCurves> & { 
  host:string;
  keyName?:string;
}

export class FabricWebSocketClient {
  private readonly classLogger: Logger;
  private readonly walletPath: string;
  keyData: KeyData;
  readonly ws: WebSocket;

  constructor(opts: FabricWebSocketClientOptions) {
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WebSocket Client');
    if (Util.isEmptyString(opts.host)) {
      throw new Error('require host of web socket server');
    }
    
    this.walletPath = `${__dirname}/wallet`;
    if(!fs.existsSync(this.walletPath)){
      this.classLogger.debug('Make directory to store keys at ${walletPath}');
      fs.mkdirSync(this.walletPath)
    };
    opts.keyName = opts.keyName || 'default'
    const pubKeyData = this.getKey({keyName: opts.keyName, curve: opts.curve},false)
    const pubKeyHex = Buffer.from(JSON.stringify(pubKeyData), 'utf8').toString('hex');

    this.classLogger.debug('Create WebSocket to communicate with host server: ${opts.host}');
    
    this.ws = new WebSocket(`${opts.host}?${pubKeyHex}`);

    /*this.ws.onerror = function () {
      throw new Error('require port for web socket');
    };
    this.ws.onopen = function () {
      console.log('WebSocket connection established');
    };
    this.ws.onclose = function () {
      console.log('WebSocket connection closed');
      this.ws = null;
    };*/
    this.ws.on('message', function incoming(message) {
      if(!message.fcn){ 
        throw new Error(`No function passed with message from web socket server: ${message}`);
      } 
      if(!message.args){ 
        throw new Error(`No arguments provided to function: ${message.fcn}`);
      }
      console.log('received: %s', message);
      this[message.fn](message.args)
    });
  };

  /**
   * @description will generate a EC private, new if key doesn't exists , or get existing key it is already exists
   * @param args; 
   * @type IClientNewKey
   * @return pubKeyData @type IClientPubKeyData
   */
  getKey(args:IClientNewKey,sendMsg:boolean=true):IClientPubKeyData{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getKey')
    this.classLogger.debug('Look for key with ${opts.keyName} or generate new key');
    const keyPath = this.keyPath(args.keyName);
    if(fs.existsSync(keyPath)){ 
      methodLogger.debug('Extracting existing key from ${keyPath}')
      this.keyData = JSON.parse(fs.readFileSync(keyPath,'utf8'));
    }else{

      if(!args.curve){
        methodLogger.debug('No curve specified. Using p256 as default.')
        args.curve = 'p256'
      }
      this.keyGen(args)
    }
    const pubKeyData: IClientPubKeyData = {
      keyName: args.keyName,
      curve: this.keyData.curve,
      pubKey: this.keyData.pubKey
    }
    

    if(sendMsg){this.sendMessage(pubKeyData)};
    return pubKeyData;
  };

  keyGen(args:IClientNewKey):void{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'keyGen'); 
    const ecdsaCurve = supportedCurves[args.curve];
    
    methodLogger.debug(`Create key ${args.keyName} with elliptical curve ${ecdsaCurve}`)
    const keyPair = KEYUTIL.generateKeypair('EC',ecdsaCurve)
    const key = KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV")
    const jsrsasign = require('jsrsasign');
    const { pubKeyHex } = jsrsasign.KEYUTIL.getKey(keyPair.pubKeyObj);
    const pubKey = pubKeyHex;
    /*
    const EC = new elliptic.ec(ecdsaCurve);
    const key = EC.genKeyPair();

    methodLogger.debug('Encode raw private key into PEM format')

    var encoderOptions = {
        curveParameters: [1, 3, 132, 0, 10],
        privatePEMOptions: {label: 'EC PRIVATE KEY'},
        publicPEMOptions: {label: 'PUBLIC KEY'},
        curve: ecdsaCurve
    }
    const keyEncoder = new KeyEncoder(encoderOptions);
    const keyPEM = keyEncoder.encodePrivate(key.getPrivate('hex'), 'raw', 'pem')//,'pkcs8')

    //const pubPoint = key.getPublic();
    //const pub = pubPoint.encode('hex',true);
    //const pubKey = EC.keyFromPublic(pub, 'hex');   
     */
    this.keyData = {key,pubKey,curve: args.curve};
    methodLogger.debug(`Store private key data for $(args.keyName)`)
    fs.writeFileSync(this.keyPath(args.keyName),JSON.stringify(this.keyData))
  };

  /**
   * @description generate 
   * @param args 
   * @type IClientDigest pass in digest to be signed (e.g.commonName)
   * @returns signature as Buffer
   */
  sign(args:IClientDigest,sendMsg:boolean=true):Buffer{
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');

    methodLogger.debug(`Generate private key hex and sign digest $(args.digest)`);
    const jsrsasign = require('jsrsasign');
    const { prvKeyHex } = jsrsasign.KEYUTIL.getKey(this.keyData.key); 
    const EC = elliptic.ec;
    const ecdsaCurve = elliptic.curves[this.keyData.curve];
    const ecdsa = new EC(ecdsaCurve);
    const signKey = ecdsa.keyFromPrivate(prvKeyHex, 'hex');

    if(!args.preHashed){
      methodLogger.debug('get SHA256 hash of digest');
      args.digest = createHash('sha256').update(args.digest).digest()
    };
    const sig = ecdsa.sign(args.digest, signKey);
    const signature = Buffer.from(sig.toDER());

    if(sendMsg){this.sendMessage({signature})}
    return signature;
  };

  /**
   * @param args 
   * @type IClientCsrReq params for CSR (e.g.commonName)
   * @returns pem encoded as string
   */
  async generateCSR(args: IClientCsrReq):Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${args.commonName}`);

    const pub = new KJUR.crypto.ECDSA({ curve: supportedCurves[this.keyData.curve] });
    pub.setPublicKeyHex(this.keyData.pubKey);

    methodLogger.debug('creating csr information');
    const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    csri.setSubjectByParam({ str: '/CN=' + args.commonName });
    csri.setSubjectPublicKeyByGetKey(pub);
    const csr = new KJUR.asn1.csr.CertificationRequest({ csrinfo: csri }) as any;
    csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: 'SHA256withECDSA' });
    const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest('hex');

    methodLogger.debug('get csr information signed');
    //const sig = await this._backend.sign({digest: Buffer.from(digest, 'hex'), preHashed: true});
    
    const sig = this.sign({digest: Buffer.from(digest),preHashed: true},false) ;  

    csr.hexSig = sig.toString('hex');
    csr.asn1Sig = new KJUR.asn1.DERBitString({ hex: '00' + csr.hexSig });
    const seq = new KJUR.asn1.DERSequence({ array: [csr.asn1CSRInfo, csr.asn1SignatureAlg, csr.asn1Sig] }) as any;
    csr.hTLV = seq.getEncodedHex();
    csr.isModified = false;
    const pem = csr.getPEMString();
    this.sendMessage({csr: pem})
    methodLogger.debug(`generated pem encoded csr = \n${pem}`);
    return pem as string;
  };

  sendMessage(message){
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sendMessage');
    methodLogger.debug(`Send message to web socket server ${this.ws.url}: $(JSON.stringify(message))`)
    this.ws.send(JSON.stringify(message));
  }
  keyPath(keyName:string){
    return `${this.walletPath}/${keyName}.key`
  };
}
