import { X509 } from 'jsrsasign';
import { Logger } from 'winston';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import { WebSocketKey } from './key';
import { FabricWebSocketServer } from './server';
import { WebSocketCryptoSuite } from './cryptoSuite';

export interface WSX509Identity extends Identity {
  type: IdentityProvidersType.WebSocket;
  credentials: {
    certificate: string;
    keyName:string;
  };
}

interface WSX509IdentityData extends IdentityData {
  type: IdentityProvidersType.WebSocket;
  version: 1;
  credentials: {
    certificate: string;
  };
  mspId: string;
}

export interface WSX509ProviderOptions extends Options {
  port:string
}

export class WSX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly classLogger: Logger;
  private readonly FabricWebSocketServer: FabricWebSocketServer;
  constructor(opts: WSX509ProviderOptions) {
    super();
    this.classLogger = Util.getClassLogger(opts.logLevel, 'WSX509Provider');
    this.FabricWebSocketServer = new FabricWebSocketServer({
      logLevel: opts.logLevel,
    });
  }
  async getUserContext(identity: WSX509Identity, name: string): Promise<User> {
    const methodLogger = Util.getMethodLogger(this.classLogger, 'getUserContext');
    methodLogger.debug(`get user context for ${name} with identity = \n%o`, identity);
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    user.setCryptoSuite(new WebSocketCryptoSuite());
    // get type of curve
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate);
    const pubKey = cert.getPublicKey() as any;
    methodLogger.debug(`certificate created using key with size ${pubKey.ecparams.keylen}`);
    await user.setEnrollment(
      new WebSocketKey({
        keyName: identity.credentials.keyName,
        FabricWebSocketServer: this.FabricWebSocketServer,
        logLevel: this.classLogger.level as 'debug' | 'info' | 'error',
        curve: ('p' + pubKey.ecparams.keylen) as 'p256' | 'p384',
      }),
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }
}
