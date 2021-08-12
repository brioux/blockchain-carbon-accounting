import { VaultTransitClient, VaultTransitClientOptions } from '../../src/vault/client';
import { expect } from 'chai';
import { createHash } from 'crypto';
import {ec} from 'elliptic'

describe('vault/client', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';
  const keyNotSupported = 'keyNotSupported';
  const token = 'tokenId';

  describe('constructor', () => {
    it('should create a VaultTransitClient', () => {
      const opts: VaultTransitClientOptions = {
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      };
      new VaultTransitClient(opts);
    });
    it('throw if endpoint is empty', () => {
      const opts: VaultTransitClientOptions = {
        endpoint: '',
        mountPath: '/transit',
        token: token,
        logLevel: 'debug',
      };
      expect(function () {
        new VaultTransitClient(opts);
      }).to.throw('require vault endpoint');
    });
    it('throw if mount path is empty', () => {
      const opts: VaultTransitClientOptions = {
        endpoint: 'http://localhost:8200',
        mountPath: '',
        token: token,
        logLevel: 'debug',
      };
      expect(function () {
        new VaultTransitClient(opts);
      }).to.throw('require transit engine mount path');
    });

    it('throw if token is empty', () => {
      const opts: VaultTransitClientOptions = {
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: undefined,
        logLevel: 'debug',
      };
      expect(function () {
        new VaultTransitClient(opts);
      }).to.throw('require vault token');
    });
  });

  describe('newKey', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'error',
      });
    });
    it('new key of size 256 bits', async () => {
      await client.newKey(testP256, 'ecdsa-p256');
    });
    it('new key of size 384 bits', async () => {
      await client.newKey(testP384, 'ecdsa-p384');
    });
  });

  let keyP256:ec.KeyPair
  let keyP384:ec.KeyPair
  describe('getPub', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'info',
      });
    });
    it('get-p256-pub-key', async () => {
      const pub = await client.getPub(testP256);
      expect(pub).not.to.be.undefined;
      expect(pub.getPublic().validate()).to.be.true;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.getPublic('hex'))).to.be.true;
      expect(pub.ec.curve._bitLength).to.be.eql(256);
      keyP256 = pub;
    });
    it('get-p384-pub-key', async () => {
      const pub = await client.getPub(testP384);
      expect(pub).not.to.be.undefined;
      expect(pub.getPublic().validate()).to.be.true;
      const re = /[0-9A-Fa-f]{6}/g;
      expect(re.test(pub.getPublic('hex'))).to.be.true;
      expect(pub.ec.curve._bitLength).to.be.eql(384);
      keyP384 = pub;
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
        logLevel: 'error',
      });
    });
    it('sign-with-p256', async () => {
      const signature = await client.sign(testP256, digest, false);
      expect(signature).not.to.be.undefined;
    });
    it('sign-with-hashed-message-p384', async () => {
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

  describe('rotateKey', () => {
    let client: VaultTransitClient;
    before(() => {
      client = new VaultTransitClient({
        endpoint: 'http://localhost:8200',
        mountPath: '/transit',
        token: token,
        logLevel: 'error',
      });
    });

    it('rotate a 256 bit key',async ()=>{
        await client.rotateKey(testP256)
        const pub =await  client.getPub(testP256)
        expect(pub.getPublic('hex')).not.eql(keyP256.getPublic('hex'))
    })
    it('rotate a 384 bit key',async ()=>{
        await client.rotateKey(testP384)
        const pub =await  client.getPub(testP384)
        expect(pub.getPublic('hex')).not.eql(keyP384.getPublic('hex'))
    })
  });
});
