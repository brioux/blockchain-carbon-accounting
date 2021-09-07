import { WebSocketClient, WSClientOptions, IClientDigest, IClientCsrReq, } from '../../src/web-socket/client';
import { getSecWsKey } from '../../src/web-socket/identity';
import { expect } from 'chai';
import { createHash } from 'crypto';
import WebSocket, {WebSocketServer} from 'ws';
import { startServer } from "./webSocketTestUtils";

const port = 8500;
const testP256 = 'test-p256';
const testP384 = 'test-p384';
let server;
let fwsClient:WebSocketClient;
let fwsKey:WebSocketClient;
let fws:WebSocket;
let secWsKey;

describe('web-socket/client', () => {
  before (async () => {
    server = await startServer(port);
    const wss = new WebSocketServer({ server });
    wss.on('connection', async function connection(ws,request) {
      fws = ws;
      secWsKey = getSecWsKey(request);
    });
    const fwsClientOpts:WSClientOptions = {
      host:`ws://localhost:${port}`,
      keyName: testP256, 
      curve:'p256',
      logLevel: 'error'
    }
    fwsClient = new WebSocketClient(fwsClientOpts);
  })
  after(async () => {
    await fwsClient.close();
    server.close();
  })    
  describe('constructor', async () => {
    it('should create a WebSocketClient instance', async() => { 
      // get a new p256 key and crate websocket connection
      await fwsClient.getKey({keyName: testP256, curve: 'p256'});
      fwsKey = new WebSocketClient({
        ws:fws, 
        secWsKey:secWsKey,
        pubKey: fwsClient.getPub(),
        curve: 'p256',
        logLevel: 'error' 
      });
    });
    it('throw if pubKey is empty', () => {
      const wskOpts:WSClientOptions = {
        ws:fws,
        secWsKey:secWsKey,
        pubKey:'', 
        curve: 'p384',
        keyName:testP256, 
        logLevel:'error',
      }
      expect(function () {
        new WebSocketClient(wskOpts);
      }).to.throw('pubKey pem should not be empty');
    });
    /*it('throw if secWsKey is empty', () => {
      const wskOpts:WSClientOptions = {
        ws:fws,
        secWsKey:'',
        pubKey:fwsClient.getPub(), 
        curve: 'p384',
        keyName:testP256, 
        logLevel:'error',
      }
      expect(function () {
        new WebSocketClient(wskOpts);
      }).to.throw('secWsKey should not be empty');
    });*/
  });
      
  describe('methods', () => {
    describe('sign', () => {
      const digest = Buffer.from('hello-secure-fabric');
      const hashedDigest = createHash('sha256').update(digest).digest();
      it('sign-with-p256', async () => {
        const args:IClientDigest = {digest,preHashed:false}
        const signature = await fwsKey.sign(args);
        expect(signature).not.to.be.undefined;
      });
      
      it('sign-with-hashed-message-p384', async () => {
        const args:IClientDigest = {digest,preHashed:false}
        // get a new p384 key and crate websocket connection
        await fwsClient.getKey({keyName: testP384, curve: 'p384'});
        fwsKey = new WebSocketClient({
          ws:fws, 
          secWsKey,
          pubKey: fwsClient.getPub(),
          curve: 'p384',
          logLevel: 'error' 
        });
        const signature = await fwsKey.sign(args);
        expect(signature).not.to.be.undefined;
      });
    });
    describe('generateCSR', () => {
      it('for-p256', async () => {
        const args:IClientCsrReq = {commonName: 'user'}
        await fwsClient.getKey({keyName: testP256})
        fwsKey = new WebSocketClient({
          ws:fws,
          secWsKey,
          pubKey: fwsClient.getPub(),
          curve: 'p256',
          logLevel: 'error' 
        });
        const csr = await fwsKey.generateCSR(args);
        expect(csr).not.to.be.undefined;
      });
    });
  });
  
});
