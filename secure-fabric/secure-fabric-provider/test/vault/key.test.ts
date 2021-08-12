import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import { createHash } from 'crypto';
import { KJUR } from 'jsrsasign';
import { VaultTransitClient } from '../../src/vault/client';
import { VaultKey } from '../../src/vault/key';
chai.use(asPromised);
describe('vault/key', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';
  const keyNotSupported = 'keyNotSupported';
  const token = 'tokenId';
  describe('constructor', () => {
    const vaultClient = new VaultTransitClient({
      endpoint: 'http://localhost:8200',
      mountPath: '/transit',
      token: token,
      logLevel: 'info',
    });
    it('should create a VaultKey', () => {
      const key = new VaultKey({
        logLevel: 'info',
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
          logLevel: 'info',
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
          logLevel: 'info',
          vaultClient: vaultClient,
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require non empty vault keyName');
    });
  });

  describe('generateCSR', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'info',
      });
    });
    it('for-p256', async () => {
      const key = new VaultKey({
        logLevel: 'info',
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
        logLevel: 'info',
        vaultClient: client,
        keyName: testP384,
      });
      const csrPem = await key.generateCSR('user2');
      const csr = KJUR.asn1.csr.CSRUtil.getInfo(csrPem);
      expect(csr.subject.name).to.be.eql('/CN=user2');
      expect((csr.pubkey.obj as any).curveName).to.be.eql('secp384r1');
    });
    it('key-not-supported', async () => {
      const key = new VaultKey({
        logLevel: 'info',
        vaultClient: client,
        keyName: keyNotSupported,
      });
      let err: Error;
      try {
        await key.generateCSR('user2');
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('only P-256 and P-384 curve are supported');
    });
  });
  describe('sign', () => {
    let client: VaultTransitClient;
    const digest = Buffer.from('hello');
    const hashedDigest = createHash('sha256').update(digest).digest();
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'info',
      });
    });
    it('with-p256', async () => {
      const key = new VaultKey({
        logLevel: 'info',
        vaultClient: client,
        keyName: testP256,
        curve: 'p256',
      });
      const sig = await key.sign(digest, false);
      expect(sig).to.be.instanceOf(Buffer);
      expect(sig).not.be.undefined;
    });
    it('with-p384', async () => {
      const key = new VaultKey({
        logLevel: 'info',
        vaultClient: client,
        keyName: testP384,
        curve: 'p384',
      });
      const sig = await key.sign(digest, true);
      expect(sig).to.be.instanceOf(Buffer);
      expect(sig).not.be.undefined;
    });
    it('with-key-not-supported', async () => {
      const key = new VaultKey({
        logLevel: 'info',
        vaultClient: client,
        keyName: keyNotSupported,
      });
      let err: Error;
      try {
        await key.sign(digest, false);
      } catch (error) {
        err = error;
      }
      expect(err.message).not.to.be.undefined;
    });
  });
});
