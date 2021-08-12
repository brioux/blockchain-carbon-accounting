import { X509 } from 'jsrsasign';
import { Logger } from 'winston';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import { VaultKey } from './key';
import { VaultTransitClient } from './client';
import { VaultCryptoSuite } from './cryptoSuite';

export interface VaultX509Identity extends Identity {
  type: IdentityProvidersType.Vault;
  credentials: {
    certificate: string;
    keyName: string;
  };
}

interface VaultX509IdentityData extends IdentityData {
  type: IdentityProvidersType.Vault;
  version: 1;
  credentials: {
    certificate: string;
  };
  mspId: string;
}

export interface VaultX509ProviderOptions extends Options {
  endpoint: string;
  transitSecretMountPath: string;
  token: string;
}

export class VaultX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.Vault;
  private readonly classLogger: Logger;
  private readonly vaultClient: VaultTransitClient;
  constructor(opts: VaultX509ProviderOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'VaultX509Provider');
    this.vaultClient = new VaultTransitClient({
      logLevel: opts.logLevel,
      endpoint: opts.endpoint,
      mountPath: opts.transitSecretMountPath,
      token: opts.token,
    });
  }
  async getUserContext(identity: VaultX509Identity, name: string): Promise<User> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getUserContext');
    methodLogger.debug(`get user context for ${name} with identity = \n%o`, identity);
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    user.setCryptoSuite(new VaultCryptoSuite());
    // get type of curve
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate);
    const pubKey = cert.getPublicKey() as any;
    methodLogger.debug(`certificate created using key with size ${pubKey.ecparams.keylen}`);
    await user.setEnrollment(
      new VaultKey({
        keyName: identity.credentials.keyName,
        vaultClient: this.vaultClient,
        logLevel: this.classLogger.level as 'debug' | 'info' | 'error',
        curve: ('p' + pubKey.ecparams.keylen) as 'p256' | 'p384',
      }),
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }
}
