import http, { Server } from "http";
import { FabricWebSocketServer, FabricWebSocketServerOptions } from '../../src/web-socket/server';
import { FabricWebSocketClient, IClientNewKey, 
  IClientDigest, IClientCsrReq } from '../../src/web-socket/client';
import { expect } from 'chai';
import { createHash } from 'crypto';
import { ec } from 'elliptic'
import fs from 'fs';
import { 
  startServer, startFabricWebSocketServer,
  waitForSocketState, createFabricSocketClient } from "./webSocketTestUtils";


const port = 8000;
describe('web-socket/client', () => {
  const testP256 = 'test-p256';
  const testP384 = 'test-p384';

  fs.rmdirSync(`${__dirname}/../../src/web-socket/wallet`, { recursive: true });

  describe('constructor', async () => {
    it('should create a FabricWebSocketServer', async() => {
      const opts: FabricWebSocketServerOptions = {
        server: http.createServer(),
        logLevel: 'debug'
      };
      new FabricWebSocketServer(opts);
    });
  });

  let server;
  let fwsServer:FabricWebSocketServer;
  let fwsClient:FabricWebSocketClient;

  describe('methods', () => {
    beforeEach(async () => {
      //[server,fwsServer]= startFabricWebSocketServer(port);
      server = http.createServer();
      const opts:FabricWebSocketServerOptions = {
          server,
          logLevel: 'error'
      }
      fwsServer = new FabricWebSocketServer(opts);
      await server.listen(port);
      fwsClient = await createFabricSocketClient(port);
    });
    afterEach(async () => {
      fwsClient.ws.close();
      await waitForSocketState(fwsClient.ws, fwsClient.ws.CLOSED); 
      server.close()
    });
    describe('getKey', () => {    
      it('new key of size 256 bits', async () => {
        const args:IClientNewKey = {keyName: testP256, curve: 'p256'};
        await fwsClient.getKey(args);
        
      });
      it('new key of size 384 bits', async () => {
        const args:IClientNewKey = {keyName: testP384, curve: 'p384'};
        await fwsClient.getKey(args);
      });
    });
     
    let keyP256:ec.KeyPair
    let keyP384:ec.KeyPair
  
    describe('sign', () => {
      const digest = Buffer.from('hello-secure-fabric');
      const hashedDigest = createHash('sha256').update(digest).digest();
      it('sign-with-p256', async () => {
        const args:IClientDigest = {digest,preHashed:false}
        fwsClient.getKey({keyName: testP256, curve: 'p256'})
        const signature = await fwsClient.sign(args);
        expect(signature).not.to.be.undefined;
      });
      it('sign-with-hashed-message-p384', async () => {
        const args:IClientDigest = {digest:hashedDigest,preHashed:true}
        fwsClient.getKey({keyName: testP384, curve: 'p384'})
        const signature = await fwsClient.sign(args);
        expect(signature).not.to.be.undefined;
      });
    });
    describe('generateCSR', () => {
      it('output with commonName user', async () => {
        const args:IClientCsrReq = {commonName: 'user'}
        fwsClient.getKey({keyName: testP256, curve: 'p256'})
        const csr = await fwsClient.generateCSR(args);
        console.log(csr);
        expect(csr).not.to.be.undefined;
      });
    });
  });
});
