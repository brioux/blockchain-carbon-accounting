import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import { KJUR } from 'jsrsasign';
import { VaultTransitClient } from '../src/vault-client';
import { VaultKey } from '../src/vault-key';
chai.use(asPromised);
const should = chai.should();
describe('vault-key', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';
  const token = 'tokenId';
  describe('constructor', () => {
    const vaultClient = new VaultTransitClient({
      endpoint: 'http://localhost:8200',
      mountPath: '/transit',
      token: token,
      logLevel: 'debug',
    });
    it('should create a VaultKey', () => {
      const key = new VaultKey({
        logLevel: 'debug',
        keyName: 'test-constructor',
        vaultClient: vaultClient,
      });
      expect(key).not.to.be.undefined;
    });
    it('throw if vaultClient is undefined', () => {
      let err: Error;
      try {
        new VaultKey({
          keyName: 'test-constructor',
          logLevel: 'debug',
          vaultClient: undefined,
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require vault transit client');
    });
    it('throw if keyName is empty', () => {
      let err: Error;
      try {
        new VaultKey({
          keyName: '',
          logLevel: 'debug',
          vaultClient: vaultClient,
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require non empty vault keyName');
    });
  });

  describe('not-require-methods', () => {
    let key: VaultKey;
    before(() => {
      key = new VaultKey({
        logLevel: 'debug',
        keyName: 'test-constructor',
        vaultClient: new VaultTransitClient({
          endpoint: 'http://localhost:8200',
          mountPath: '/transit',
          token: token,
          logLevel: 'debug',
        }),
      });
    });
    it('getSKI', () => {
      should.throw(() => {
        key.getSKI();
      });
    });
    it('getHandle', () => {
      should.throw(() => {
        key.getHandle();
      });
    });
    it('isSymmetric', () => {
      should.throw(() => {
        key.isSymmetric();
      });
    });
    it('isPrivate', () => {
      should.throw(() => {
        key.isPrivate();
      });
    });
    it('getPublicKey', () => {
      should.throw(() => {
        key.getPublicKey();
      });
    });
    it('toBytes', () => {
      should.throw(() => {
        key.toBytes();
      });
    });
  });

  describe('generateCSR', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      });
    });
    it('for-p256', async () => {
      const key = new VaultKey({
        logLevel: 'debug',
        vaultClient: client,
        keyName: testP256,
      });
      const csrPem = await key.generateCSR('user1');
      const csr = KJUR.asn1.csr.CSRUtil.getInfo(csrPem);
      expect(csr.subject.name).to.be.eql('/CN=user1');
      expect((csr.pubkey.obj as any).curveName).to.be.eql('secp256r1');
    });
    it('for-p384', async () => {
      const key = new VaultKey({
        logLevel: 'debug',
        vaultClient: client,
        keyName: testP384,
      });
      const csrPem = await key.generateCSR('user2');
      const csr = KJUR.asn1.csr.CSRUtil.getInfo(csrPem);
      expect(csr.subject.name).to.be.eql('/CN=user2');
      expect((csr.pubkey.obj as any).curveName).to.be.eql('secp384r1');
    });
  });
});
