import CA from 'fabric-ca-client';
import { Gateway, GatewayOptions } from 'fabric-network';
import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import { Key } from '../../src/internal/key';
import { WSX509Provider,WSX509Identity} from '../../src/web-socket/identity';
import { FabricSocketServer,FabricSocketServerOptions} from '../../src/web-socket/server';
import { WebSocketClient } from '../../../test/web-socket-client/src/client';
import { startServer, waitForSocketClient,waitForSocketState } from "./webSocketTestUtils";
import { User, IdentityProvidersType } from '../../src/internal/identity-provider';
import { join } from 'path';
import { load } from 'js-yaml';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';
import { Server } from "http";
import { socketServer } from 'ws';
chai.use(asPromised);

const port = '8500';
const testP256 = 'test-p256';
const testP384 = 'test-p384';
let server,socketServer;

let wsClientAdmin:WebSocketClient;
let wsClient:WebSocketClient;

let identityProvider:WSX509Provider;
let adminSessionId, adminPubKeyHex,
  userPubKeyHex, userSessionId;
let adminClient,userClient;

const ccPath = join(__dirname, '..', '..', '..', 'test', 'fabric-network', 'connection-profile.yaml');
const ccp = load(readFileSync(ccPath, 'utf-8')) as object;

let ca: CA;
before (async () => {
  server = await startServer(port);
  const socketServerOptions: FabricSocketServerOptions = {
    path: '/sockets',
    server,
    logLevel: 'debug'
  }
  socketServer = new FabricSocketServer(socketServerOptions)
  ca = new CA('http://localhost:7054');

  adminPubKeyHex = '04cc1753fd57368ce8b5805a96e03a10ef6d50c50ed1c121c58bb620ab8afa4c422f310f18fad90522af94f0dbd695e9f32568c9271719b447d71c77cf843d8ed1'
  adminSessionId = socketServer.newSessionId(adminPubKeyHex);
  userPubKeyHex = '04a7bda4fe85999b564c07f1cbfabfbb8407a3262f6bca2213cecae89a0e10d9e0bc47c61a895f6f6b9af949cc792d2590104e0433d200e10883bfa7ce59e25194';
  userSessionId = socketServer.newSessionId(userPubKeyHex);
  await waitForSocketClient(
    socketServer.clients,adminSessionId,
    socketServer.hostAddress)
})
after(async () => {
  socketServer.close();
  server.close();
})

describe('web-socket/identity', () => {
    
  describe('constructor', async () => {
    it('should create a WSX509Provider instance', async() => { 
      adminClient = socketServer.clients[adminSessionId]
      identityProvider = new WSX509Provider({
        webSocketClient: adminClient,
        logLevel: 'error' 
      });
    });
  });
      
  describe('methods', () => {
    describe('getUserContext', () => {
      let adminIdentity:WSX509Identity;
      it('should enroll admin', async () => {
        const adminKey = new Key(adminClient.keyName,adminClient);
        console.log(`Generate and request signature from pubKey: ${adminClient.keyName}`);
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
      it('should enroll client-p256', async () => {
        // Wait for client to establish web socket connetion with idenity provider
        await waitForSocketClient(
          socketServer.clients,userSessionId,
          socketServer.hostAddress)
        userClient = socketServer.clients[userSessionId]
        const userKey = new Key(userClient.keyName, userClient);
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
        identityProvider = new WSX509Provider({
          webSocketClient: userClient,
          logLevel: 'error' 
        });
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
