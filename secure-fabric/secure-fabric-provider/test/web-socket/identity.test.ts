import CA from 'fabric-ca-client';
import { Gateway, GatewayOptions } from 'fabric-network';
import chai, { expect } from 'chai';
import asPromised from 'chai-as-promised';
import WebSocket, {WebSocketServer} from 'ws';
import { WebSocketKey } from '../../src/web-socket/key';
import { WebSocketClient, WebSocketClientOptions } from '../../src/web-socket/client';
import { WSX509Provider,WSX509Identity } from '../../src/web-socket/identity';
import { startServer, createFabricSocketClient } from "./webSocketTestUtils";
import { User, IdentityProvidersType } from '../../src/internal/identity-provider';
import { join } from 'path';
import { load } from 'js-yaml';
import { readFileSync } from 'fs';
import { randomBytes } from 'crypto';

chai.use(asPromised);

const port = 8500;
const testP256 = 'test-p256';
const testP384 = 'test-p384';
let server,wss;
let fwsClientAdmin:WebSocketClient;
let fwsClient:WebSocketClient;
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
    await fwsClientAdmin.close();
    await fwsClient.close();
    server.close();
  })    
  describe('constructor', async () => {
    
    const fwsClientAdminOpts:WebSocketClientOptions = {
      host:`ws://localhost:${port}`,
      keyName: 'admin',
      logLevel: 'error'
    }
    const fwsClientOpts:WebSocketClientOptions = {
      host:`ws://localhost:${port}`,
      keyName: testP256,
      logLevel: 'error'
    }
    it('should create a WSX509Provider instance', async() => { 
      identityProvider = new WSX509Provider({
        server: server,
        logLevel: 'error' 
      });
      fwsClientAdmin = await createFabricSocketClient(fwsClientAdminOpts);
      fwsClient = await createFabricSocketClient(fwsClientOpts);
    });
    it('throw if port and server are empty', () => {
      expect(function () {
        new WSX509Provider({port: '', logLevel: 'error'});
      }).to.throw('require an http server or port number');
    });
  });
      
  describe('methods', () => {
    describe('getUserContext', () => {
      let adminUser;
      it('should enroll admin', async () => {
        // open web socket connection between admin client and the Identityprovider server
        await fwsClientAdmin.getKey({keyName: 'admin'});
        const adminKey = new WebSocketKey({
          ws: identityProvider.ws,
          secWsKey: identityProvider.secWsKey, 
          pubKey: fwsClientAdmin.getPub(),
          curve: 'p256',
          logLevel: 'error',
          keyName: 'admin'
        });
        const csr = await adminKey.generateCSR({commonName:'admin'});
        const resp = await ca.enroll({
          enrollmentID: 'admin',
          enrollmentSecret: 'adminpw',
          csr: csr,
        });
        // When done with adminKey close it and the webSocket connection.
        // TODO: this should be managed within the client
        // i.e., when the signature request is complete the client should close the connection
        // for single use (e.g. sign a CSR) can close the web socket after sendingback first 
        // however most fabric transactions require multiple signatures... 
        //await fwsClientAdmin.close();
        const identity:WSX509Identity = {
          type: IdentityProvidersType.WebSocket,
          credentials: {
            certificate: resp.certificate,
            keyName: 'admin',
          },
          mspId: 'DevMSP',
        }
        await fwsClientAdmin.getKey({keyName: 'admin'});
        adminUser = await identityProvider.getUserContext(
          identity,'Registrar'
        );        
      });
      // in-order to run the test multiple times
      let usernameP256 = randomBytes(8).toString('hex')
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
      })
      let clientP256Identity: WSX509Identity;
      it('should enroll client-p256', async () => {
        // open web socket connection between test client and the identityProvider server
        await fwsClient.getKey({keyName: testP256});    
        const clientKeyP256 = new WebSocketKey({
          ws: identityProvider.ws,
          secWsKey: identityProvider.secWsKey,  
          pubKey: fwsClient.getPub(),
          curve: 'p256',
          logLevel: 'error',
          keyName: testP256
        });
        const csr = await clientKeyP256.generateCSR({commonName:usernameP256});
        const resp = await ca.enroll({
          enrollmentID: usernameP256,
          enrollmentSecret: 'pw',
          csr: csr,
        });
        clientP256Identity = {
          type: IdentityProvidersType.WebSocket,
          credentials: {
            certificate: resp.certificate,
            keyName: testP256,
          },
          mspId: 'DevMSP',
        };
      });
    let gateway: Gateway;
    it('should successfully query-p256', async () => {
      await fwsClient.getKey({keyName: testP256});
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
  
});
