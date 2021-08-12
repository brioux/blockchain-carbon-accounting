import { ICryptoSuite, User } from '@zzocker/fabric-common';
import { IdentityProvider, Identity, IdentityData } from '@zzocker/fabric-network';

export { Identity, IdentityData } from '@zzocker/fabric-network';
export { User } from '@zzocker/fabric-common';
// InternalIdentityProvider : a abstract class which will be implemented by identity provider
// in this repo
// some of the function are just to support the interface provided by the fabric-sdk-node
export abstract class InternalIdentityProvider implements IdentityProvider {
  // TODO override this
  readonly type: string;
  getCryptoSuite(): ICryptoSuite {
    throw new Error('InternalIdentityProvider::getCryptoSuite not required!!');
  }
  fromJson(data: IdentityData): Identity {
    throw new Error('InternalIdentityProvider::fromJson not required!!');
  }
  toJson(identity: Identity): IdentityData {
    throw new Error('InternalIdentityProvider::toJso : not required!!');
  }
  // TODO : override this
  getUserContext(identity: Identity, name: string): Promise<User> {
    throw new Error('InternalIdentityProvider::InternalIdentityProvider : implement me!!');
  }
}

export enum IdentityProvidersType {
  // vault identity provider wherein private key are store with vault transit engine
  // and certificate are store in certData store
  Vault = 'Vault-X.509',

  // WebSocket identity provider wherein private key are store with client inside the extension
  // signing of digest are done by sending of data as websocket message through webSocket connection between
  // server and client extension
  // certificate are store in certData store
  WebSocket = 'WS-X.509',
}
