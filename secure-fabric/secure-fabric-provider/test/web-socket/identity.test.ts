import CA from 'fabric-ca-client';
import { Gateway, GatewayOptions } from 'fabric-network';
import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import { Key } from '../../src/internal/key';
import { WSX509Provider,WSX509Identity,waitForSocketClient} from '../../src/web-socket/identity';
import { startServer } from "./webSocketTestUtils";
import { User, IdentityProvidersType } from '../../src/internal/identity-provider';
import { join } from 'path';
import { load } from 'js-yaml';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { Server } from "http";
chai.use(asPromised);

const port = 8500;
const testP256 = 'test-p256';
const testP384 = 'test-p384';
let server;
const adminPubKeyHex='042c9232b11b5806f588f3c51d7d0ad4c699e168fb441ac27997b42ffff8ec431016b080556e98a40a5073917989bf01d64eaeb4c6bfc66d0aab966d7e2b82ae6a';
const userPubKeyHex='045f00bea5d3b16acbcbbf608b9f04fbc30d82d4c4a61092a9381d5d0579ddf798b75b9d11504084995f85c0567542bccd52c47b21cd3b6cefa247d451e58092d1'

let identityProvider:WSX509Provider;

const ccPath = join(__dirname, '..', '..', '..', 'test', 'fabric-network', 'connection-profile.yaml');
const ccp = load(readFileSync(ccPath, 'utf-8')) as object;

describe('web-socket/identity', () => {
  let ca: CA;
  before (async () => {
    server = await startServer(port);
    ca = new CA('http://localhost:7054');
  })
  after(async () => {
    server.close();
  })    
  describe('constructor', async () => {

    it('should create a WSX509Provider instance', async() => { 
      identityProvider = new WSX509Provider({
        server: server,
        logLevel: 'error' 
      });
      // create new admin and test user web socket client instances
    });
    it('throw if port and server are empty', () => {
      expect(function () {
        new WSX509Provider({port: '', logLevel: 'error'});
      }).to.throw('require an http server or port number');
    });
  });
      
  describe('methods', () => {
    describe('getUserContext', () => {
      let adminIdentity:WSX509Identity;
      it('should enroll admin', async () => {
        // Wait for client to establish web socket connetion ith idenity provider
        await waitForSocketClient(identityProvider.clients[adminPubKeyHex],adminPubKeyHex)
        const adminKey = new Key(
          adminPubKeyHex.substring(0,6),
          identityProvider.clients[adminPubKeyHex]);
        const csr = await adminKey.generateCSR('admin');
        const resp = await ca.enroll({
          enrollmentID: 'admin',
          enrollmentSecret: 'adminpw',
          csr: csr,
        });
        adminIdentity = {
          type: IdentityProvidersType.WebSocket,
          credentials: {
            certificate: resp.certificate
            //,.pubKeyHex: adminPubKeyHex
          },
          mspId: 'DevMSP',
        }      
      });
      // in-order to run the test multiple times
      let usernameP256 = randomBytes(8).toString('hex')
      let adminUser;
      it('should register client', async () => { 
        adminUser = await identityProvider.getUserContext(
          adminIdentity,'Registrar'
        ); 
        const secret = await ca.register(
          {
            enrollmentID: usernameP256,
            affiliation: 'org1.department1',
            enrollmentSecret: 'pw',
          },
          adminUser
        );
        expect(secret).to.be.eql('pw');
      })
      let clientP256Identity: WSX509Identity;
      it('should enroll client-p256', async () => {
        // Wait for client to establish web socket connetion ith idenity provider
        await waitForSocketClient(identityProvider.clients[userPubKeyHex],userPubKeyHex)
        const clientKeyP256 = new Key(
          userPubKeyHex.substring(0,6),
          identityProvider.clients[userPubKeyHex]
        );
        const csr = await clientKeyP256.generateCSR(usernameP256);
        const resp = await ca.enroll({
          enrollmentID: usernameP256,
          enrollmentSecret: 'pw',
          csr: csr,
        });
        clientP256Identity = {
          type: IdentityProvidersType.WebSocket,
          credentials: {
            certificate: resp.certificate
            //,pubKeyHex:userPubKeyHex
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
        console.log(res.toString())
      });
      it('should successfully invoke-p256', async () => {
        const channel = await gateway.getNetwork('devchannel');
        const contract = channel.getContract('basic-transfer');
        await contract.submitTransaction('TransferAsset', 'asset1', 'newOwner5');
        gateway.disconnect();
      });
    });
  });
});
