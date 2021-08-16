import { IdentityProvidersType } from './internal/identity-provider';
// every identity  type and certificate data will extends this interface
export interface IIdentity {
  // key used for storing identity data with cert datastore
  key?: string;
  type: IdentityProvidersType;
  // require at the time of enrolling
  mspId?: string;
}

// IVaultIdentity represents a client using vault transit engine
export interface IVaultIdentity extends IIdentity {
  keyName: string;
  token: string;
}

// TODO Add IWebsocketIdentity here
// TODO Add IGRPCIdentity here

// IIdentityData : data that will be stored with cert datastore
// with key as client's commonName (from X509 certificate) and value as following field
export interface IIdentityData extends IIdentity {
  credentials: {
    certificate: string;
    // if identity type is IdentityProvidersType.Default
    privateKey?: string;
  };
  mspId: string;
}
