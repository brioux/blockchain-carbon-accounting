import { VaultTransitClient } from '../src/vault-client';
import { expect } from 'chai';
import { createHash } from 'crypto';

describe('vault-client', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';
  const keyNotSupported = 'keyNotSupported';
  const token = 'tokenId';

  describe('constructor', () => {
    it('should create a VaultTransitClient', () => {
      const client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      });
      expect(client).not.be.undefined;
    });

    it('throw if endpoint is empty', () => {
      let err: Error;
      try {
        new VaultTransitClient({
          endpoint: '',
          mountPath: '/transit',
          token: token,
          logLevel: 'debug',
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require vault endpoint');
    });

    it('throw if mountPath is empty', () => {
      let err: Error;
      try {
        new VaultTransitClient({
          endpoint: 'http://localhost:8200',
          mountPath: '',
          token: token,
          logLevel: 'debug',
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require mount path of vault transit secret engine');
    });

    it('throw if token is empty', () => {
      let err: Error;
      try {
        new VaultTransitClient({
          endpoint: 'http://localhost:8200',
          mountPath: '/transit',
          token: '',
          logLevel: 'debug',
        });
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('require vault token');
    });
  });

  describe('getPub', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      });
    });
    it('get-p256-pub-key', async () => {
      const pub = await client.getPub(testP256);
      expect(pub).not.to.be.undefined;
      expect(pub.getPublic().validate()).to.be.true;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.getPublic('hex'))).to.be.true;
      expect(pub.ec.curve._bitLength).to.be.eql(256);
    });
    it('get-p384-pub-key', async () => {
      const pub = await client.getPub(testP384);
      expect(pub).not.to.be.undefined;
      expect(pub.getPublic().validate()).to.be.true;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.getPublic('hex'))).to.be.true;
      expect(pub.ec.curve._bitLength).to.be.eql(384);
    });
    it('throw if key type not supported', async () => {
      let err: Error;
      try {
        await client.getPub(keyNotSupported);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('only P-256 and P-384 curve are supported');
    });
    it('throw if key not found', async () => {
      let err: Error;
      try {
        await client.getPub('not-found');
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('Status 404');
    });
  });

  describe('sign', async () => {
    let client: VaultTransitClient;
    const digest = Buffer.from('hello-secure-fabric');
    const hashedDigest = createHash('sha256').update(digest).digest();
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      });
    });
    it('sign-with', async () => {
      const signature = await client.sign(testP256, digest, false);
      expect(signature).not.to.be.undefined;
    });
    it('sign-with-hashed-message', async () => {
      const signature = await client.sign(testP384, hashedDigest, true);
      expect(signature).not.to.be.undefined;
    });
    it('throw if key not found', async () => {
      let err: Error;
      try {
        await client.sign('not-found', digest, false);
      } catch (error) {
        err = error;
      }
      expect(err.message).to.be.eql('encryption key not found');
    });
  });
});
