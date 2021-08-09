import { getClassLogger, getMethodLogger, Options } from './util';
import { VaultTransitClient } from './vault-client';
import { ICryptoKey } from '@zzocker/fabric-common';
import { Logger } from 'winston';
import { KJUR } from 'jsrsasign';
import { createHash } from 'crypto';

export interface VaultKeyOptions extends Options {
  keyName: string;
  vaultClient: VaultTransitClient;
}
export class VaultKey implements ICryptoKey {
  private readonly classLogger: Logger;
  private readonly _backend: VaultTransitClient;
  private readonly keyName: string;
  constructor(opts: VaultKeyOptions) {
    this.classLogger = getClassLogger(opts.logLevel, 'VaultKey');
    if (opts.vaultClient === undefined) {
      throw new Error('require vault transit client');
    }
    if (opts.keyName === undefined || opts.keyName === '') {
      throw new Error(`require non empty vault keyName`);
    }
    this._backend = opts.vaultClient;
    this.keyName = opts.keyName;
  }

  /**
   * @param commonName of the client
   * @returns pem encoded csr
   */
  async generateCSR(commonName: string): Promise<string> {
    const methodLogger = getMethodLogger(this.classLogger, 'generateCSR');
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

  // NOT REQUIRED
  getSKI(): string {
    const methodLogger = getMethodLogger(this.classLogger, 'getSKI');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
  getHandle(): string {
    const methodLogger = getMethodLogger(this.classLogger, 'getHandle');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
  isSymmetric(): boolean {
    const methodLogger = getMethodLogger(this.classLogger, 'isSymmetric');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
  isPrivate(): boolean {
    const methodLogger = getMethodLogger(this.classLogger, 'isPrivate');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
  getPublicKey(): ICryptoKey {
    const methodLogger = getMethodLogger(this.classLogger, 'getPublicKey');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
  toBytes(): string {
    const methodLogger = getMethodLogger(this.classLogger, 'toBytes');
    methodLogger.debug('not required');
    throw new Error('not required');
  }
}
