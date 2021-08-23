import { VaultTransitClient } from './client';
import { Util, Options } from '../internal/util';
import { InternalKey } from '../internal/key';
import { Logger } from 'winston';
import { KJUR } from 'jsrsasign';
import { createHash } from 'crypto';
import ecsig from 'elliptic/lib/elliptic/ec/signature.js';
import asn1 from 'asn1.js';
import BN from 'bn.js';
import { curves } from 'elliptic';

const EcdsaDerSig = asn1.define('ECPrivateKey', function () {
  return this.seq().obj(this.key('r').int(), this.key('s').int());
});

const p256N = (curves as any).p256.n as BN;
const p384N = (curves as any).p384.n as BN;

export interface VaultKeyOptions extends Options {
  keyName: string;
  vaultClient: VaultTransitClient;
  curve?: 'p256' | 'p384';
}
export class VaultKey extends InternalKey {
  private readonly classLogger: Logger;
   readonly _backend: VaultTransitClient;
  private readonly keyName: string;
  private readonly crv: string;
  constructor(opts: VaultKeyOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'VaultKey');
    if (opts.vaultClient === undefined) {
      throw new Error('require vault transit client');
    }
    if (opts.keyName === undefined || opts.keyName === '') {
      throw new Error(`require non empty vault keyName`);
    }
    this._backend = opts.vaultClient;
    this.keyName = opts.keyName;
    this.crv = opts.curve;
  }

  /**
   * @param commonName of the client
   * @returns pem encoded csr
   */
  async generateCSR(commonName: string): Promise<string> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'generateCSR');
    methodLogger.debug(`commonName = ${commonName}`);
    methodLogger.debug(`get pubKey from vault`);
    const key = await this._backend.getPub(this.keyName);
    let crv: string = 'secp256r1';
    if (key.ec.curve._bitLength === 384) {
      crv = 'secp384r1';
    }
    const pub = new KJUR.crypto.ECDSA({ curve: crv });
    pub.setPublicKeyHex(key.getPublic('hex'));

    methodLogger.debug('creating csr information');
    const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    csri.setSubjectByParam({ str: '/CN=' + commonName });
    csri.setSubjectPublicKeyByGetKey(pub);
    const csr = new KJUR.asn1.csr.CertificationRequest({ csrinfo: csri }) as any;
    csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: 'SHA256withECDSA' });
    const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest('hex');

    methodLogger.debug('get csr information signed');
    const sig = await this._backend.sign(this.keyName, Buffer.from(digest, 'hex'), true);
    csr.hexSig = sig.toString('hex');
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
   * @param digest
   * @param preHashed
   */
  async sign(digest: Buffer, preHashed: boolean): Promise<Buffer> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'sign');
    methodLogger.debug(`digestSize = ${digest.length} preHashed = ${preHashed}`);
    methodLogger.debug('getting signature from vault');
    const raw = await this._backend.sign(this.keyName, digest, preHashed);
    methodLogger.debug(`converting asn1 sig format to der for fabric to accept`);
    const rsSig = EcdsaDerSig.decode(raw, 'der');
    const r = rsSig.r as BN;
    let s = rsSig.s as BN;
    if (r === undefined || s === undefined) {
      throw new Error('invalid signature');
    }
    let crvN: BN = p256N;
    if (this.crv === 'p384') {
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
    return Buffer.from(der);
  }
}
