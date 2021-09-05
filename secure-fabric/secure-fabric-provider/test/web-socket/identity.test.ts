import CA from 'fabric-ca-client';
import { Gateway, GatewayOptions } from 'fabric-network';
import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import { Key } from '../../src/internal/key';
import { WSX509Provider,WSX509Identity} from '../../src/web-socket/identity';
import { WebSocketClient } from '../../../test/web-socket-client/src/client';
import { startServer, waitForSocketClient } from "./webSocketTestUtils";
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

let wsClientAdmin:WebSocketClient;
let wsClient:WebSocketClient;

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
    /*console.log(`Close the admin web-socket connection`);
    wsClientAdmin.close();
    console.log(`Close the user web-socket connection`);
    wsClient.close();*/
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
      let adminPubKeyHex;
      it('should enroll admin', async () => {
        /*wsClientAdmin = new WebSocketClient({
          host: `ws://localhost:${port}`,
          keyName: 'admin',logLevel:'error'});
        adminPubKeyHex=wsClientAdmin.getPubKeyHex();
        await wsClientAdmin.open();*/
        // Wait for client to establish web socket connetion ith idenity provider
        const adminPubKeyHex = '04488af79edb4048a65e5d8e82feabf9683f2af09cd1a92fc99147bbe1031ec80b1f9ba3b03ffcfaffb4b0cafc54b41c6bc58053ac0e004bc87bbe4e32d9a86b03'
        const sessionId = identityProvider.webSocketSessionId(adminPubKeyHex);
        console.log(`sessionId: ${sessionId}`);
        await waitForSocketClient(
          identityProvider.clients,adminPubKeyHex,
          identityProvider._wss.address()['port'])
        
        const adminKey = new Key(
          adminPubKeyHex.substring(0,12),
          identityProvider.clients[adminPubKeyHex]);

        console.log(`Generate and request signature from pubKey: ${adminPubKeyHex.substring(0,12)}...`);
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
          },
          mspId: 'DevMSP',
        }      
      });
      let adminUser;
      // in-order to run the test multiple times
      let usernameP256 = randomBytes(8).toString('hex')
      it('should register client', async () => { 
        console.log('register user')
        adminUser = await identityProvider.getUserContext(
          adminIdentity,'Registrar'
        ); 
        console.log(`Register a user account with commonName ${usernameP256}`);
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
      let userIdentity: WSX509Identity;
      const userPubKeyHex = '04beac60b7a61716a87167893943667e470a7e21a215568422552d075ff39c1610b1174ea8ca9a4ae16d5d8f1736be71a292cdaa3c83c7b45ce9443f38a61e96cd';
      it('should enroll client-p256', async () => {
        // Wait for client to establish web socket connetion with idenity provider
        const sessionId = identityProvider.webSocketSessionId(userPubKeyHex);
        console.log(`sessionId: ${sessionId}`);

        await waitForSocketClient(
          identityProvider.clients,userPubKeyHex,
          identityProvider._wss.address()['port'])
        const userKey = new Key(
          userPubKeyHex.substring(0,12),
          identityProvider.clients[userPubKeyHex]
        );
        console.log(`Generate csr for ${usernameP256} and request signature from pubKey: ${userPubKeyHex.substring(0,12)}...`);
        const csr = await userKey.generateCSR(usernameP256);
        console.log(`Enroll ${usernameP256} pubKey: ${userPubKeyHex.substring(0,12)}...`)
        const resp = await ca.enroll({
          enrollmentID: usernameP256,
          enrollmentSecret: 'pw',
          csr: csr,
        });
        userIdentity = {
          type: IdentityProvidersType.WebSocket,
          credentials: {
            certificate: resp.certificate
          },
          mspId: 'DevMSP',
        };
      });
      let gateway: Gateway;
      it('should successfully query-p256', async () => {
        gateway = new Gateway();
        const opts: GatewayOptions = {
          identity: userIdentity,
          identityProvider: identityProvider,
        };
        console.log(`Create gateway for ${usernameP256} with pubKey: ${userPubKeyHex.substring(0,12)}...`)
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
