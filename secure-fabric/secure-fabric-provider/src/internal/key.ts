import { ICryptoKey } from 'fabric-common';

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
