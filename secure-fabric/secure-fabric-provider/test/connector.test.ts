import { ISecureFabricConnector, SecureFabricConnector } from '../src/connector';
import { IdentityProvidersType } from '../src/internal/identity-provider';
import { FileCertStore } from '../src/certStore/fileSystem';
import { join } from 'path';
import { IVaultIdentity } from '../src/identity';
import { randomBytes } from 'crypto';
import chai from 'chai';
import asPromise from 'chai-as-promised';
const should = chai.should();
chai.use(asPromise);

const testP384 = 'test-p384';

describe('connector', () => {
  const cerStoreFS = new FileCertStore({
    folderPath: join(__dirname, '.certStore'),
  });
  const connectorOptions: ISecureFabricConnector = {
    logLevel: 'info',
    supportedIdentitiesType: [IdentityProvidersType.Default, IdentityProvidersType.Vault],
    vaultOptions: {
      endpoint: 'http://localhost:8200',
      transitEngineMountPath: '/transit',
    },
    registrar: {
      certificate: undefined,
      mspId: 'DevMSP',
      privateKey: undefined,
      vaultKey: { token: 'tokenId', keyName: 'admin' },
    },
    certStore: cerStoreFS,
    caInfo: {
      url: 'http://localhost:7054',
    },
    connectionProfile: undefined,
  };
  describe('constructor', () => {
    // TODO
  });

  describe('enroll-registrar-vault', () => {
    let connector: SecureFabricConnector;
    before(() => {
      const opts: ISecureFabricConnector = Object.assign({}, connectorOptions);
      connector = new SecureFabricConnector(opts);
    });
    it('should be able to enroll identity with vault identity provider', async () => {
      const identity: IVaultIdentity = {
        mspId: connectorOptions.registrar.mspId,
        type: IdentityProvidersType.Vault,
        // vault input by client
        keyName: 'admin',
        token: 'tokenId',
      };
      await connector.enroll(identity, { enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
    });
    it('throw if identity is undefined', () => {
      return connector.enroll(undefined, { enrollmentID: 'admin', enrollmentSecret: 'adminpw' }).should.be.rejectedWith('require non-empty identity');
    });
    it('throw if request is undefined', () => {
      return connector
        .enroll(
          {
            key: 'admin-default',
            mspId: connectorOptions.registrar.mspId,
            type: IdentityProvidersType.Default,
          },
          null,
        )
        .should.be.rejectedWith('require non-empty enrollment request');
    });
    it('throw if application do not accept a identity type', () => {
      return connector
        .enroll(
          {
            key: 'admin-default',
            mspId: connectorOptions.registrar.mspId,
            type: 'notSupported' as IdentityProvidersType,
          },
          { enrollmentID: 'admin', enrollmentSecret: 'adminpw' },
        )
        .should.be.rejectedWith('cannot accept of identity of type notSupported');
    });
  });
  // commonName of client registered using vault private key of registrar
  const vaultUser = randomBytes(16).toString('hex');
  describe('register', () => {
    let connector: SecureFabricConnector;
    before(async () => {
      const opts: ISecureFabricConnector = Object.assign({}, connectorOptions);
      const cert = await cerStoreFS.get('admin');
      opts.registrar.certificate = cert.credentials.certificate;
      connector = new SecureFabricConnector(opts);
      await connector.initialize();
    });

    it('should register client using vault identity provider', async () => {
      const secret = await connector.register({
        enrollmentID: vaultUser,
        enrollmentSecret: 'pw',
        affiliation: 'org1.department1',
      });
      secret.should.be.eql('pw');
    });
  });

  describe('enroll-registrar-default', () => {
    let connector: SecureFabricConnector;
    before(() => {
      const opts: ISecureFabricConnector = Object.assign({}, connectorOptions);
      connector = new SecureFabricConnector(opts);
    });
    it('should be able to enroll identity with default identity provider', async () => {
      const identity = {
        mspId: connectorOptions.registrar.mspId,
        type: IdentityProvidersType.Default,
      };
      await connector.enroll(identity, { enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
    });
  });
  // commonName of client registered using default private key of registrar
  const defaultUser = randomBytes(16).toString('hex');
  describe('register', () => {
    let connector: SecureFabricConnector;
    before(async () => {
      const opts: ISecureFabricConnector = Object.assign({}, connectorOptions);
      const cert = await cerStoreFS.get('admin');
      opts.registrar.certificate = cert.credentials.certificate;
      opts.registrar.privateKey = cert.credentials.privateKey;
      opts.registrar.vaultKey = undefined;
      connector = new SecureFabricConnector(opts);
      await connector.initialize();
    });

    it('should register client using default identity provider', async () => {
      const secret = await connector.register({
        enrollmentID: defaultUser,
        enrollmentSecret: 'pw',
        affiliation: 'org1.department1',
      });
      secret.should.be.eql('pw');
    });
  });

  describe('enroll-client', () => {
    let connector: SecureFabricConnector;
    before(() => {
      const opts: ISecureFabricConnector = Object.assign({}, connectorOptions);
      connector = new SecureFabricConnector(opts);
    });
    it('should be able to enroll client using default identity provider', async () => {
      const identity = {
        mspId: connectorOptions.registrar.mspId,
        type: IdentityProvidersType.Default,
      };
      await connector.enroll(identity, { enrollmentID: defaultUser, enrollmentSecret: 'pw' });
    });
    it('should be able to enroll client using vault identity provider', async () => {
      const identity: IVaultIdentity = {
        mspId: connectorOptions.registrar.mspId,
        type: IdentityProvidersType.Vault,

        keyName: testP384,
        token: 'tokenId',
      };
      await connector.enroll(identity, { enrollmentID: vaultUser, enrollmentSecret: 'pw' });
    });
  });
});
