import { InternalCryptoSuite } from '../internal/cryptoSuite';
import { WebSocketKey } from './key';
import { IClientDigest } from './client';
export class WebSocketCryptoSuite extends InternalCryptoSuite {
  async sign(key: WebSocketKey, args: IClientDigest): Promise<Buffer> {
    return key.sign(args);
  }
}
