import { WebSocketClient, IClientNewKey } from '../../src/web-socket/client';
import { IClientCsrReq } from '../../src/web-socket/key';
import { expect } from 'chai';
import { createHash } from 'crypto';
import {WebSocketServer} from 'ws';
import fs from 'fs';
import { startServer, startWebSocketServer, createFabricSocketClient } from "./webSocketTestUtils";

const port = 8500;
const testP256 = 'test-p256';
const testP384 = 'test-p384';
let server,fws;
let fwsClient:WebSocketClient;
// Clear the local wallet key store used for testing purposes only
fs.rmdirSync(`${__dirname}/../../src/web-socket/cli_wallet`, { recursive: true });

describe('web-socket/client', () => {
  before (async () => {
    server = await startServer(port);
    const wss = new WebSocketServer({ server });
    wss.on('connection', async function connection(ws,request) {
      fws = ws;
      //console.log(`SEC Key: ${getSecWsKey(request)}`)
    });
  })
  after(async () => {
    await fwsClient.close();
    server.close();
  })

  describe('constructor', async () => {
    it('should create a WebSocketServer', async() => { 
      fwsClient = await createFabricSocketClient({
        host: `ws://localhost:${port}`, logLevel: 'error'
      });
    });
    it('throw if host is empty', () => {
      expect(function () {
        new WebSocketClient({host: '', logLevel: 'error'});
      }).to.throw('require host address of web socket server');
    });
  });

  describe('methods', () => {
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
  
    describe('sign', () => {
      const digest = Buffer.from('hello-secure-fabric');
      const hashedDigest = createHash('sha256').update(digest).digest();
      afterEach(async () => {
        fws.send(hashedDigest)
        let signature
        await fws.on('message', async function incoming(message) {
           signature = message
        });
      })
      it('sign-with-p256', async () => {
        await fwsClient.getKey({keyName: testP256, curve: 'p256'})
      });
      it('sign-wit-p384', async () => {
        await fwsClient.getKey({keyName: testP384, curve: 'p384'})
      });
    });
    /*
    describe('generateCSR', () => {
      it('for-p256', async () => {
        const args:IClientCsrReq = {commonName: 'user'}
        fwsClient.getKey({keyName: testP256, curve: 'p256'})
        const csr = await fwsClient.generateCSR(args);
        //console.log(csr);
        expect(csr).not.to.be.undefined;
      });
    });
    describe('generateCSR', () => {
      it('for-p384', async () => {
        const args:IClientCsrReq = {commonName: 'user'}
        fwsClient.getKey({keyName: testP256, curve: 'p384'})
        const csr = await fwsClient.generateCSR(args);
        //console.log(csr);
        expect(csr).not.to.be.undefined;
      });
    });
    */
  });
});
