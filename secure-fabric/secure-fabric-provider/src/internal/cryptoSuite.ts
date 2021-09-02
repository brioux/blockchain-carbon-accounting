import { ICryptoSuite, ICryptoKey, KeyOpts, ICryptoKeyStore } from 'fabric-common';
import { createHash } from 'crypto';
import { Key } from './key';

export abstract class InternalCryptoSuite implements ICryptoSuite {
  createKeyFromRaw(pem: string): ICryptoKey {
    return new Key();
  }
  decrypt(key: ICryptoKey, cipherText: Buffer, opts: any): Buffer {
    throw new Error('InternalCryptoSuite::decrypt : not required!!');
  }
  deriveKey(key: ICryptoKey, opts?: KeyOpts): ICryptoKey {
    throw new Error('InternalCryptoSuite::deriveKey : not required!!');
  }
  encrypt(key: ICryptoKey, plainText: Buffer, opts: any): Buffer {
    throw new Error('InternalCryptoSuite::encrypt : not required!!');
  }
  getKey(ski: string): Promise<ICryptoKey> {
    throw new Error('InternalCryptoSuite::getKey : not required!!');
  }
  getKeySize(): number {
    throw new Error('InternalCryptoSuite::getKeySize : not required!!');
  }
  generateKey(opts?: KeyOpts): Promise<ICryptoKey> {
    throw new Error('InternalCryptoSuite::generateKey : not required!!');
  }
  hash(msg: string, opts: any): string {
    return createHash('sha256').update(msg).digest('hex');
  }
  importKey(pem: string, opts?: KeyOpts): ICryptoKey | Promise<ICryptoKey> {
    throw new Error('InternalCryptoSuite::importKey : not required!!');
  }
  setCryptoKeyStore(cryptoKeyStore: ICryptoKeyStore): void {
    throw new Error('InternalCryptoSuite::setCryptoKeyStore : not required!!');
  }
  // TODO : override this
  async sign(key: ICryptoKey, digest: Buffer): Promise<Buffer> {
    throw new Error('InternalCryptoSuite::sign : implement me!!');
  }
  verify(key: ICryptoKey, signature: Buffer, digest: Buffer): boolean {
    throw new Error('InternalCryptoSuite::verify : not required!!');
  }
}
