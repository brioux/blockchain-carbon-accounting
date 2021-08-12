import CA from '@zzocker/fabric-ca-client';
import { Gateway, GatewayOptions } from '@zzocker/fabric-network';
import chai, { expect } from 'chai';
import { User, IdentityProvidersType } from '../../src/internal/identity-provider';
import { VaultTransitClient } from '../../src/vault/client';
import { VaultX509Provider, VaultX509ProviderOptions, VaultX509Identity } from '../../src/vault/identity';
import { VaultKey } from '../../src/vault/key';
import { load } from 'js-yaml';
import { join } from 'path';
import { readFileSync } from 'fs';
import asPromised from 'chai-as-promised';
chai.use(asPromised);

const ccPath = join(__dirname, '..', '..', '..', 'test', 'fabric-network', 'connection-profile.yaml');
const ccp = load(readFileSync(ccPath, 'utf-8')) as object;

describe('vault/identity', () => {
  describe('using only identity provider', () => {
    let vaultClient: VaultTransitClient;
    let identityProvider: VaultX509Provider;
    let adminKey: VaultKey;
    let clientKeyP256: VaultKey;
    let clientKeyP384: VaultKey;
    let ca: CA;
    before(() => {
      const providerOpts: VaultX509ProviderOptions = {
        endpoint: 'http://localhost:8200',
        transitSecretMountPath: '/transit',
        token: 'tokenId',
        logLevel: 'info',
      };
      identityProvider = new VaultX509Provider(providerOpts);
      vaultClient = new VaultTransitClient({
        endpoint: providerOpts.endpoint,
        mountPath: providerOpts.transitSecretMountPath,
        token: providerOpts.token,
        logLevel: providerOpts.logLevel,
      });
      adminKey = new VaultKey({
        vaultClient: vaultClient,
        keyName: 'admin',
        curve: 'p256',
        logLevel: providerOpts.logLevel,
      });
      clientKeyP256 = new VaultKey({
        vaultClient: vaultClient,
        keyName: 'test-p256',
        curve: 'p256',
        logLevel: providerOpts.logLevel,
      });
      clientKeyP384 = new VaultKey({
        vaultClient: vaultClient,
        keyName: 'test-p384',
        curve: 'p384',
        logLevel: providerOpts.logLevel,
      });
      ca = new CA('http://localhost:7054');
    });
    let adminUser: User;
    it('should enroll admin', async () => {
      // generate csr for admin
      const csr = await adminKey.generateCSR('admin');

      // enroll admin to get certificate
      // will return only certificate
      const resp = await ca.enroll({
        enrollmentID: 'admin',
        enrollmentSecret: 'adminpw',
        csr: csr,
      });

      adminUser = await identityProvider.getUserContext(
        {
          type: IdentityProvidersType.Vault,
          credentials: {
            certificate: resp.certificate,
            keyName: 'admin',
          },
          mspId: 'DevMSP',
        },
        'Registrar'
      );
    });

    let usernameP256 = 'usernameP256';
    it('should register client', async () => {
      const secret = await ca.register(
        {
          enrollmentID: usernameP256,
          affiliation: 'org1.department1',
          enrollmentSecret: 'pw',
        },
        adminUser
      );

      expect(secret).to.be.eql('pw');
    });

    let clientP256Identity: VaultX509Identity;
    it('should enroll client-p256', async () => {
      // generate csr for enrolling client using 256 bit key size
      const csr = await clientKeyP256.generateCSR(usernameP256);
      const resp = await ca.enroll({
        enrollmentID: usernameP256,
        enrollmentSecret: 'pw',
        csr: csr,
      });

      clientP256Identity = {
        type: IdentityProvidersType.Vault,
        credentials: {
          certificate: resp.certificate,
          keyName: 'test-p256',
        },
        mspId: 'DevMSP',
      };
    });
    let gateway: Gateway;
    it('should successfully query-p256', async () => {
      gateway = new Gateway();
      const opts: GatewayOptions = {
        identity: clientP256Identity,
        identityProvider: identityProvider,
      };
      await gateway.connect(ccp, opts);
      const channel = await gateway.getNetwork('devchannel');

      const contract = channel.getContract('basic-transfer');
      const res = await contract.evaluateTransaction('ReadAsset', 'asset1');
    });

    it('should successfully invoke-p256', async () => {
      const channel = await gateway.getNetwork('devchannel');
      const contract = channel.getContract('basic-transfer');
      await contract.submitTransaction('TransferAsset', 'asset1', 'newOwner3');
      gateway.disconnect();
    });
  });
});
