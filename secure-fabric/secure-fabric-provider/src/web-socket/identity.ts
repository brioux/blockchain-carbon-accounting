import { ICryptoSuite } from "fabric-common";
import {
  LogLevelDesc,
  Logger,
  LoggerProvider,
  Checks
} from "@hyperledger/cactus-common";
import { X509 } from 'jsrsasign';
import { Identity, IdentityProvidersType, IdentityData, InternalIdentityProvider, User } from '../internal/identity-provider';
import { Options, Util } from '../internal/util';
import WebSocket, { WebSocketServer } from 'ws';
import { Key } from '../internal/key'; 
import { WebSocketClient } from './client';
import { InternalIdentityClient } from "../internal/client";
import { InternalCryptoSuite } from '../internal/crypto-suite';

export interface WSX509Identity extends Identity {
  type: IdentityProvidersType.WebSocket;
  credentials: {
    certificate: string;
  };
  sessionId?: string;
}

export function getSecWsKey(request){
  const secKey = request.rawHeaders.findIndex((element) => element == 'Sec-WebSocket-Key');
  return request.rawHeaders[secKey+1]
}

interface WSX509IdentityData extends IdentityData {
  type: IdentityProvidersType.WebSocket;
  version: 1;
  credentials: {
    certificate: string;
  };
  mspId: string;
}

export interface WSX509ProviderOptions {
  webSocketClient: WebSocketClient;
  logLevel: LogLevelDesc;
}

export class WSX509Provider extends InternalIdentityProvider {
  readonly type: string = IdentityProvidersType.WebSocket;
  private readonly log: Logger;
  public readonly className = "SecureIdentityProviders";

  constructor(private readonly opts: WSX509ProviderOptions) {
    super()
    const fnTag = `${this.className}#constructor`;
    this.log = LoggerProvider.getOrCreate({
      level: opts.logLevel || "INFO",
      label: this.className,
    });
    this.log.debug(
      `${fnTag} setup WS-X.509 identity identity provider for client ${opts.webSocketClient.keyName}`,
    );
  }

  /**
   * @description get user context for the provided identity file
   * @note before this method is called the requested identity holder must open 
   * a websocket connection with the identity provider
   */
  async getUserContext(identity: WSX509Identity, name: string): Promise<User> {
    if (identity === undefined) {
      throw new Error('require identity');
    } else if (Util.isEmptyString(name)) {
      throw new Error('require name');
    }

    const user = new User(name);
    user.setCryptoSuite(new InternalCryptoSuite());
    //user.setCryptoSuite(Utils.newCryptoSuite());
    
    const cert = new X509();
    cert.readCertPEM(identity.credentials.certificate); 
    const pubKeyHex = cert.getPublicKey()['pubKeyHex'];

    const client = this.opts.webSocketClient;
    if (client.pubKeyHex !== pubKeyHex) {
      throw new Error("the public key of the web-socket client does not match the provided certificate");
    }
    const wsKey = new Key(client.keyName,client);
    await user.setEnrollment(
      wsKey,
      identity.credentials.certificate,
      identity.mspId
    );
    return user;
  }

  getCryptoSuite(): ICryptoSuite {
    throw new Error('InternalIdentityProvider::getCryptoSuite not required!!');
  }
  fromJson(data: IdentityData): WSX509Identity {
    throw new Error('InternalIdentityProvider::fromJson not required!!');
  }
  toJson(identity: Identity): WSX509IdentityData {
    throw new Error('InternalIdentityProvider::toJso : not required!!');
  }
}
