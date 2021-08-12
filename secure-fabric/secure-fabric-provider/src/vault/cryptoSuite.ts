import { InternalCryptoSuite } from '../internal/cryptoSuite';
import { VaultKey } from './key';

export class VaultCryptoSuite extends InternalCryptoSuite {
  async sign(key: VaultKey, digest: Buffer): Promise<Buffer> {
    return key.sign(digest, true);
  }
}
