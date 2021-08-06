import { VaultTransitClientOptions, VaultTransitClient } from '../src/vault-client';
import { describe, beforeEach, it } from 'mocha';
import chai from 'chai';
import asPromised from 'chai-as-promised';

const expect = chai.expect;
chai.use(asPromised);

describe('Vault-Client', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';
  const keyNotSupported = 'keyNotSupported';
  const token = 'tokenId';
  let vaultClient: VaultTransitClient;
  beforeEach(() => {
    const vaultClientOpts: VaultTransitClientOptions = {
      endpoint: 'http://localhost:8200',
      mountPath: '/transit',
      logLevel: 'debug',
    };
    vaultClient = new VaultTransitClient(vaultClientOpts);
  });
  describe('#sign', () => {
    it('return signature', async () => {
      const signatureP256 = await vaultClient.sign(token, testP256, Buffer.from('Hello Vault'), false);
      expect(signatureP256).not.to.be.empty;
      expect(signatureP256).to.be.instanceOf(Buffer);

      const signatureP384 = await vaultClient.sign(token, testP384, Buffer.from('Hello Vault'), false);
      expect(signatureP384).not.to.be.empty;
      expect(signatureP384).to.be.instanceOf(Buffer);
    });

    it('throw if token is incorrect', async () => {
      await expect(vaultClient.sign('incorrect', testP256, Buffer.from('Hello Vault'), false)).to.be.rejected;
    });
    it('throw if keyName not found', async () => {
      await expect(vaultClient.sign(token, 'not-found-key', Buffer.from('Hello Vault'), false)).to.be.rejected;
    });
  });
  describe('#getPub', () => {
    it('return-public-key-p256', async () => {
      const pub = await vaultClient.getPub(token, testP256);
      expect(pub).not.be.empty;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.x)).to.be.true;
      expect(re.test(pub.y)).to.be.true;
      expect(pub.crv).to.be.eql('p256');
    });

    it('return-public-key-p384', async () => {
      const pub = await vaultClient.getPub(token, testP384);
      expect(pub).not.be.empty;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.x)).to.be.true;
      expect(re.test(pub.y)).to.be.true;
      expect(pub.crv).to.be.eql('p384');
    });
    it('throw if curve not supported', async () => {
      try {
        await vaultClient.getPub(token, keyNotSupported);
      } catch (error) {
        expect(error).to.be.instanceOf(Error);
        expect((error as Error).message).to.be.eql('only P-256 and P-384 curve are supported, but provided aes256-gcm96');
      }
    });

    it('throw if token is incorrect', async () => {
      await expect(vaultClient.getPub('incorrect-token', testP256)).to.be.rejected;
    });
    it('throw if keyName not found', async () => {
      await expect(vaultClient.getPub(token, 'not-found')).to.be.rejected;
    });
  });
});
