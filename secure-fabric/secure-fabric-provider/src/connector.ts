import { IdentityProvidersType } from './internal/identity-provider';
import { DiscoveryOptions, DefaultQueryHandlerOptions, DefaultEventHandlerOptions } from 'fabric-network';
import CA, { TLSOptions } from 'fabric-ca-client';
import { Options, Util } from './internal/util';
import { Logger } from 'winston';
import { IIdentity, IIdentityData, IVaultIdentity } from './identity';
import { ICertDatastore } from './certStore/certStore';
import { VaultKey } from './vault/key';
import { VaultTransitClient } from './vault/client';
import { IKeyValueAttribute } from 'fabric-ca-client';
import { User, Utils } from 'fabric-common';
import { VaultX509Provider } from './vault/identity';

export interface ISecureFabricConnector extends Options {
  // array of identity types that application is going to support
  // eg [IdentityProvidersType.Vault , IdentityProvidersType.Default IdentityProvidersType.WebSocket]
  // this will accept client request with vault , default or websocket for signing fabric messages
  supportedIdentitiesType: IdentityProvidersType[];

  // vault server config if Vault identity is support
  vaultOptions?: {
    endpoint: string;
    transitEngineMountPath: string;
  };

  // for registering client : NOTE /register endpoint should not be exposed to client
  // rather this endpoint is for org's admin
  registrar?: {
    certificate: string;
    mspId: string;
    // if privateKey is provided , this private will be used for signing
    privateKey?: string;

    // if provided , application will use private key of registerer stored with vault
    // to register and revoke client
    vaultKey?: { token: string; keyName: string };
  };

  // cert data store configuration
  certStore: ICertDatastore;
  // provide ca server info , to support enroll and register
  caInfo?: {
    // ca config
    url: string;
    tlsOptions?: TLSOptions;
    caName?: string;
  };

  // usual field required in fabric-sdk-node's GatewayOptions
  connectionProfile: object;
  tlsInfo?: {
    certificate: string;
    key: string;
  };
  discovery?: DiscoveryOptions;
  eventHandlerOptions?: DefaultEventHandlerOptions;
  queryHandlerOptions?: DefaultQueryHandlerOptions;
  'connection-options'?: any;
}

export interface IRegisterRequest {
  enrollmentID: string;
  enrollmentSecret?: string;
  role?: string;
  affiliation: string;
  maxEnrollments?: number;
  attrs?: IKeyValueAttribute[];
}

export class SecureFabricConnector {
  private readonly classLogger: Logger;
  private registrar: User;
  constructor(private readonly opts: ISecureFabricConnector) {
    if (opts.supportedIdentitiesType === undefined || opts.supportedIdentitiesType.length === 0) {
      throw new Error('require at least one supported identities type');
    }
    this.classLogger = Util.getClassLogger(opts.logLevel, 'SecureFabricConnector');
  }

  // should be called only once before other method can be used
  async initialize() {
    if (this.opts.registrar !== undefined && this.opts.registrar !== null) {
      if (this.opts.registrar.privateKey !== undefined && this.opts.registrar.privateKey !== null) {
        // TODO registrar with default identity provider
        this.registrar = new User('registrar');
        const suite = Utils.newCryptoSuite();
        this.registrar.setCryptoSuite(suite);
        const importedKey = suite.createKeyFromRaw(this.opts.registrar.privateKey);
        await this.registrar.setEnrollment(importedKey, this.opts.registrar.certificate, this.opts.registrar.mspId);
      } else if (this.opts.registrar.vaultKey !== undefined && this.opts.registrar.vaultKey !== null) {
        const provider = this._getVaultProvider(this.opts.registrar.vaultKey.token);
        this.registrar = await provider.getUserContext(
          {
            type: IdentityProvidersType.Vault,
            credentials: {
              certificate: this.opts.registrar.certificate,
              keyName: this.opts.registrar.vaultKey.keyName,
            },
            mspId: this.opts.registrar.mspId,
          },
          'registrar',
        );
      } else {
        throw new Error('registrar config require either default or vault identity provider');
      }
    }
  }
  async register(request: IRegisterRequest): Promise<string> {
    const ca = this._getCA();
    return await ca.register(request, this.registrar);
  }

  async enroll(identity: IIdentity, request: { enrollmentID: string; enrollmentSecret: string }): Promise<void> {
    if (identity === undefined || identity === null) {
      throw new Error(`require non-empty identity`);
    }
    if (request === undefined || request === null) {
      throw new Error(`require non-empty enrollment request`);
    }
    if (Util.isEmptyString(identity.mspId)) {
      throw new Error('require non-empty mspId of identity');
    }
    if (!this.opts.supportedIdentitiesType.includes(identity.type)) {
      throw new Error(`cannot accept of identity of type ${identity.type}`);
    }
    const methodLogger = Util.getMethodLogger(this.classLogger, 'enroll');
    methodLogger.debug(`enrolling client of type ${identity.type}`);
    const ca = this._getCA();
    let csr: string;
    switch (identity.type) {
      case IdentityProvidersType.Vault:
        methodLogger.debug(`generating csr for vault identity provider`);
        const id = identity as IVaultIdentity;
        const vaultKey = this._getVaultKey(id.keyName, id.token);
        csr = await vaultKey.generateCSR(request.enrollmentID);
        break;
    }
    const resp = await ca.enroll({
      enrollmentID: request.enrollmentID,
      enrollmentSecret: request.enrollmentSecret,
      csr: csr,
    });
    const identityData: IIdentityData = {
      key: request.enrollmentID,
      type: identity.type,
      mspId: identity.mspId,
      credentials: {
        certificate: resp.certificate,
      },
    };
    if (resp.key !== undefined) {
      identityData.credentials.privateKey = resp.key.toBytes();
    }
    methodLogger.debug(`putting identity data into certStore`);
    await this.opts.certStore.put(identityData);
  }
  private _getCA(): CA {
    if (this.opts === undefined) {
      throw new Error('require non-empty caInfo');
    }
    return new CA({
      url: this.opts.caInfo.url,
      caName: this.opts.caInfo.caName,
      tlsOptions: this.opts.caInfo.tlsOptions,
    });
  }
  private _getVaultKey(keyName: string, token: string): VaultKey {
    const client = new VaultTransitClient({
      endpoint: this.opts.vaultOptions.endpoint,
      mountPath: this.opts.vaultOptions.transitEngineMountPath,
      token: token,
      logLevel: this.opts.logLevel,
    });
    return new VaultKey({
      keyName: keyName,
      vaultClient: client,
      logLevel: this.opts.logLevel,
    });
  }
  private _getVaultProvider(token: string): VaultX509Provider {
    if (this.opts.vaultOptions === undefined || this.opts.vaultOptions === null) {
      throw new Error('require non-empty vault server config');
    }
    // TODO check for field of options
    return new VaultX509Provider({
      endpoint: this.opts.vaultOptions.endpoint,
      transitSecretMountPath: this.opts.vaultOptions.transitEngineMountPath,
      token: token,
      logLevel: this.opts.logLevel,
    });
  }
}
