import { InternalCryptoSuite } from '../internal/cryptoSuite';
import { WebSocketKey, IClientDigest } from './key';

export class WebSocketCryptoSuite extends InternalCryptoSuite {
  async sign(key: WebSocketKey, digest:Buffer): Promise<Buffer> {
    const args:IClientDigest = {digest,preHashed:true};
    return key.sign(args);
  }
}
