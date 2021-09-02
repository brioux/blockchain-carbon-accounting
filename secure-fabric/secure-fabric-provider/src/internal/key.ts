import { ICryptoKey } from "fabric-common";
import { InternalIdentityClient } from "./client";
import { CryptoUtil } from "./crypto-util";
import { KJUR } from "jsrsasign";
import { createHash } from "crypto";

// internal class used by cryptoSuite, this is just to support interface provided by
// fabric-sdk-node
export class Key implements ICryptoKey {
  constructor(
    private readonly keyName: string,
    private readonly client: InternalIdentityClient,
  ) {}
  
  async sign(digest: Buffer): Promise<Buffer> {
    const { sig, crv } = await this.client.sign(this.keyName, digest);
    return CryptoUtil.encodeASN1Sig(sig, crv);
  }

  /**
   * @description generate a csr
   * @param commonName
   * @returns pem encoded csr string
   */
  async generateCSR(commonName: string): Promise<string> {
    const pub = await this.client.getPub(this.keyName);
    //const csr = CryptoUtil.createCSR(pub, commonName);
    //const digest = CryptoUtil.getCSRDigest(csr.asn1CSRInfo);
    
    const csri = new KJUR.asn1.csr.CertificationRequestInfo();
    csri.setSubjectByParam({ str: '/CN=' + commonName });
    csri.setSubjectPublicKeyByGetKey(pub);
    const csr = new KJUR.asn1.csr.CertificationRequest({ 
      csrinfo: csri}) as any;
    csr.asn1SignatureAlg = new KJUR.asn1.x509.AlgorithmIdentifier({ name: "SHA256withECDSA" });
    const digest = createHash('sha256').update(Buffer.from(csr.asn1CSRInfo.getEncodedHex(), 'hex')).digest();

    const { sig } = await this.client.sign(this.keyName, digest);    
    //return CryptoUtil.getPemCSR(csr, sig);

    csr.hexSig = sig.toString('hex');
    csr.asn1Sig = new KJUR.asn1.DERBitString({ hex: '00' + csr.hexSig });
    const seq = new KJUR.asn1.DERSequence({ array: [csr.asn1CSRInfo, csr.asn1SignatureAlg, csr.asn1Sig] }) as any;
    csr.hTLV = seq.getEncodedHex();
    csr.isModified = false;
    const pem = csr.getPEMString();

    return pem as string;
  }

  /**
   * @description will rotate the key
   */
  async rotate(): Promise<void> {
    await this.client.rotateKey(this.keyName);
  }
  getSKI(): string {
    throw new Error("Key::getSKI not-required");
  }
  getHandle(): string {
    throw new Error("Key::getHandle not-required");
  }
  isSymmetric(): boolean {
    throw new Error("Key::isSymmetric not-required");
  }
  isPrivate(): boolean {
    throw new Error("Key::isPrivate not-required");
  }
  getPublicKey(): ICryptoKey {
    throw new Error("Key::getPublicKey not-required");
  }
  toBytes(): string {
    throw new Error("Key::toBytes not-required");
  }
}

// internal class used by cryptoSuite, this is just to support interface provided by
// fabric-sdk-node
export class InternalKey implements ICryptoKey {
  getSKI(): string {
    throw new Error('not-required');
  }
  getHandle(): string {
    throw new Error('not-required');
  }
  isSymmetric(): boolean {
    throw new Error('not-required');
  }
  isPrivate(): boolean {
    throw new Error('not-required');
  }
  getPublicKey(): ICryptoKey {
    throw new Error('not-required');
  }
  toBytes(): string {
    throw new Error('not-required');
  }
}
